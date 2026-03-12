#!/usr/bin/env python3
"""
Weather Alert System — Hamamatsu, Japan

Monitors 4–7 day forecasts and sends a LINE Works notification
when the forecast changes significantly from the baseline.
"""

import argparse
import json
import logging
import time
from datetime import date, datetime, timedelta
from pathlib import Path

import jwt       # PyJWT
import requests

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
FORECASTS_PATH = SCRIPT_DIR / "forecasts.json"
TOKEN_CACHE_PATH = SCRIPT_DIR / ".token_cache.json"
LOG_PATH = SCRIPT_DIR / "weather_alert.log"

# ── WMO weather code mappings ────────────────────────────────────────────────
WMO_DESCRIPTION = {
    0: "晴れ",
    1: "ほぼ晴れ", 2: "一部曇り", 3: "曇り",
    45: "霧", 48: "霧",
    51: "霧雨", 53: "霧雨", 55: "霧雨",
    56: "着氷性霧雨", 57: "着氷性霧雨",
    61: "雨", 63: "雨", 65: "大雨",
    66: "着氷性の雨", 67: "着氷性の雨",
    71: "雪", 73: "雪", 75: "大雪", 77: "霰",
    80: "にわか雨", 81: "にわか雨", 82: "激しいにわか雨",
    85: "にわか雪", 86: "にわか雪",
    95: "雷雨",
    96: "雹を伴う雷雨", 99: "雹を伴う雷雨",
}

# Broad groups used for "did the weather type change?" detection
# 0=clear, 1=cloudy, 2=fog, 3=rain, 4=snow, 5=thunderstorm
WMO_GROUP = {
    0: 0, 1: 0,
    2: 1, 3: 1,
    45: 2, 48: 2,
    51: 3, 53: 3, 55: 3, 56: 3, 57: 3,
    61: 3, 63: 3, 65: 3, 66: 3, 67: 3,
    80: 3, 81: 3, 82: 3,
    71: 4, 73: 4, 75: 4, 77: 4, 85: 4, 86: 4,
    95: 5, 96: 5, 99: 5,
}

GROUP_LABEL = {
    0: "☀️ 晴れ系",
    1: "☁️ 曇り系",
    2: "🌫️ 霧",
    3: "🌧️ 雨系",
    4: "❄️ 雪系",
    5: "⛈️ 雷雨",
}


# ── Config / state helpers ───────────────────────────────────────────────────

def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_forecasts() -> dict:
    if FORECASTS_PATH.exists():
        with open(FORECASTS_PATH) as f:
            return json.load(f)
    return {}


def save_forecasts(data: dict):
    with open(FORECASTS_PATH, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ── LINE Works auth ──────────────────────────────────────────────────────────

def get_access_token(config: dict) -> str:
    """Return a valid LINE Works access token, refreshing via Service Account JWT if needed."""
    lw = config["lineworks"]

    # Use cached token if still valid (with 5-min buffer)
    if TOKEN_CACHE_PATH.exists():
        with open(TOKEN_CACHE_PATH) as f:
            cache = json.load(f)
        if cache.get("expires_at", 0) > time.time() + 300:
            return cache["access_token"]

    with open(lw["private_key_path"]) as f:
        private_key = f.read()

    now = int(time.time())
    assertion = jwt.encode(
        {"iss": lw["client_id"], "sub": lw["service_account"], "iat": now, "exp": now + 3600},
        private_key,
        algorithm="RS256",
    )

    resp = requests.post(
        "https://auth.worksmobile.com/oauth2/v2.0/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            "client_id": lw["client_id"],
            "client_secret": lw["client_secret"],
            "scope": "bot",
        },
    )
    resp.raise_for_status()
    token_data = resp.json()

    with open(TOKEN_CACHE_PATH, "w") as f:
        json.dump({"access_token": token_data["access_token"],
                   "expires_at": time.time() + int(token_data.get("expires_in", 86400))}, f)

    return token_data["access_token"]


def send_message(config: dict, text: str):
    lw = config["lineworks"]
    token = get_access_token(config)
    resp = requests.post(
        f"https://www.worksapis.com/v1.0/bots/{lw['bot_id']}/users/{lw['user_id']}/messages",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"content": {"type": "text", "text": text}},
    )
    resp.raise_for_status()


# ── Weather fetching ─────────────────────────────────────────────────────────

def fetch_weather(config: dict) -> dict:
    """Fetch 8-day daily forecast from Open-Meteo. Returns dict keyed by date string."""
    loc = config["location"]
    resp = requests.get(
        "https://api.open-meteo.com/v1/forecast",
        params={
            "latitude": loc["latitude"],
            "longitude": loc["longitude"],
            "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum",
            "timezone": "Asia/Tokyo",
            "forecast_days": 8,
        },
    )
    resp.raise_for_status()
    daily = resp.json()["daily"]

    return {
        date_str: {
            "weather_code": daily["weather_code"][i],
            "temp_max": daily["temperature_2m_max"][i],
            "temp_min": daily["temperature_2m_min"][i],
            "precipitation": daily["precipitation_sum"][i] or 0.0,
        }
        for i, date_str in enumerate(daily["time"])
    }


# ── Change detection ─────────────────────────────────────────────────────────

def detect_changes(baseline: dict, current: dict, thresholds: dict) -> list[str]:
    """Return a list of human-readable change descriptions (empty = no significant change)."""
    changes = []

    # Weather group change
    if thresholds.get("weather_category_change", True):
        old_g = WMO_GROUP.get(baseline["weather_code"], -1)
        new_g = WMO_GROUP.get(current["weather_code"], -1)
        if old_g != new_g:
            changes.append(
                f"天気: {GROUP_LABEL.get(old_g, '?')} → {GROUP_LABEL.get(new_g, '?')}"
            )

    # Max temperature
    t = thresholds.get("temp_change_c", 3)
    for key, label in [("temp_max", "最高気温"), ("temp_min", "最低気温")]:
        diff = current[key] - baseline[key]
        if abs(diff) >= t:
            sign = "+" if diff > 0 else ""
            changes.append(f"{label}: {baseline[key]:.1f}°C → {current[key]:.1f}°C ({sign}{diff:.1f}°C)")

    # Precipitation
    p = thresholds.get("precipitation_change_mm", 5)
    diff = current["precipitation"] - baseline["precipitation"]
    if abs(diff) >= p:
        sign = "+" if diff > 0 else ""
        changes.append(
            f"降水量: {baseline['precipitation']:.1f}mm → {current['precipitation']:.1f}mm ({sign}{diff:.1f}mm)"
        )

    return changes


def format_alert(target_date: str, changes: list[str], current: dict, baseline: dict) -> str:
    desc_now = WMO_DESCRIPTION.get(current["weather_code"], "不明")
    desc_base = WMO_DESCRIPTION.get(baseline["weather_code"], "不明")
    lines = [
        "⚠️ 天気予報 変更アラート",
        f"📅 対象日: {target_date}",
        f"📌 7日前の予報: {desc_base} / 最高{baseline['temp_max']:.1f}°C / 最低{baseline['temp_min']:.1f}°C / 降水{baseline['precipitation']:.1f}mm",
        f"🌡️ 最新予報:    {desc_now} / 最高{current['temp_max']:.1f}°C / 最低{current['temp_min']:.1f}°C / 降水{current['precipitation']:.1f}mm",
        "",
        "7日前からの変更:",
    ] + [f"  • {c}" for c in changes]
    return "\n".join(lines)


# ── Main logic ───────────────────────────────────────────────────────────────

def run_check(config: dict, dry_run: bool = False):
    today = date.today()
    min_days = config["window"]["days_out_min"]
    max_days = config["window"]["days_out_max"]

    target_dates = [
        (today + timedelta(days=d)).isoformat()
        for d in range(min_days, max_days + 1)
    ]

    logging.info("Fetching weather forecast from Open-Meteo...")
    current_forecasts = fetch_weather(config)
    stored = load_forecasts()
    now_str = datetime.now().isoformat()

    for date_str in target_dates:
        if date_str not in current_forecasts:
            logging.warning(f"No forecast data for {date_str}, skipping.")
            continue

        current = current_forecasts[date_str]

        if date_str not in stored:
            # First sighting — save as baseline
            stored[date_str] = {
                "baseline": {**current, "recorded_at": now_str},
                "last_alerted": None,
                "last_checked": {**current, "recorded_at": now_str},
            }
            desc = WMO_DESCRIPTION.get(current["weather_code"], "?")
            logging.info(
                f"Baseline saved for {date_str}: {desc} / {current['temp_max']}°C / {current['temp_min']}°C / {current['precipitation']}mm"
            )
        else:
            baseline = stored[date_str]["baseline"]
            last_alerted = stored[date_str]["last_alerted"]

            # Always measure change vs the frozen 7-day baseline (for display)
            baseline_changes = detect_changes(baseline, current, config["thresholds"])

            # Only notify if something changed since the last alert (avoids 6-hourly spam)
            compare_for_notify = last_alerted or baseline
            notify_changes = detect_changes(compare_for_notify, current, config["thresholds"])

            if notify_changes:
                msg = format_alert(date_str, baseline_changes or notify_changes, current, baseline)
                if dry_run:
                    print(f"[DRY RUN] Would send:\n{msg}\n{'─'*40}")
                else:
                    send_message(config, msg)
                    logging.info(f"Alert sent for {date_str}")
                stored[date_str]["last_alerted"] = {**current, "recorded_at": now_str}
            else:
                logging.info(f"No significant change for {date_str}.")

            stored[date_str]["last_checked"] = {**current, "recorded_at": now_str}

    # Clean up past dates
    for d in [d for d in stored if d < today.isoformat()]:
        del stored[d]
        logging.info(f"Removed past date: {d}")

    save_forecasts(stored)



# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Hamamatsu weather change alert")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and compare without sending notifications")
    parser.add_argument("--test-notify", action="store_true",
                        help="Send a test notification to confirm setup")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )

    config = load_config()

    if args.test_notify:
        send_message(config, "🌤️ 天気通知テスト: 正常に動作しています。")
        print("Test notification sent.")
    else:
        run_check(config, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
