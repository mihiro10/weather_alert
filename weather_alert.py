#!/usr/bin/env python3
"""
Weather Alert System — Hamamatsu, Japan

Detects days with anomalous weather (outliers vs surrounding days in the
8-day forecast) and sends LINE Works notifications with business action
recommendations.
"""

import argparse
import json
import logging
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import jwt       # PyJWT
import requests

JST = ZoneInfo("Asia/Tokyo")

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

# Broad groups: 0=clear, 1=cloudy, 2=fog, 3=rain, 4=snow, 5=thunderstorm
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

# ── Business impact rules ─────────────────────────────────────────────────────
# ctx = {"avg_temp_max": float, "majority_group": int}
BUSINESS_RULES = [
    {
        "condition": lambda cur, ctx: cur["temp_max"] >= 30,
        "actions": ["🍜 冷やし麺・冷製メニューを+30%増産", "🔥 温かいメニューを-20%削減"],
    },
    {
        "condition": lambda cur, ctx: 25 <= cur["temp_max"] < 30,
        "actions": ["🍜 冷やし麺・冷製メニューを+15%増産"],
    },
    {
        # Warmer than surrounding days but not absolutely hot
        "condition": lambda cur, ctx: cur["temp_max"] - ctx["avg_temp_max"] >= 4 and cur["temp_max"] < 25,
        "actions": ["🍜 周辺日より高温 — 麺を+10%増産"],
    },
    {
        "condition": lambda cur, ctx: cur["temp_max"] <= 10,
        "actions": ["🍲 温かいメニューを+20%増産", "🍜 冷やし麺の仕入れを最小限に"],
    },
    {
        "condition": lambda cur, ctx: WMO_GROUP.get(cur["weather_code"], 0) >= 3 or cur["precipitation"] >= 10,
        "actions": ["🏭 雨天 — 工場製品の発注を削減"],
    },
    {
        # Target day is clear while surrounding days are mostly rain
        "condition": lambda cur, ctx: (
            WMO_GROUP.get(cur["weather_code"], 0) <= 1 and ctx["majority_group"] >= 3
        ),
        "actions": ["☀️ 雨続きの中でこの日は晴れ — 来店客増加を想定し店頭向け弁当を+15%増量"],
    },
]


def get_business_impact(current: dict, ctx: dict) -> list[str]:
    actions = []
    for rule in BUSINESS_RULES:
        if rule["condition"](current, ctx):
            actions.extend(rule["actions"])
    return actions


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


# ── Anomaly detection ─────────────────────────────────────────────────────────

def detect_anomaly(target_date: str, all_forecasts: dict, thresholds: dict) -> tuple[list[str], dict]:
    """
    Compare target_date against the ±3 surrounding days in the 8-day forecast.
    Returns (anomaly descriptions, context summary dict).
    Context summary: {"avg_temp_max": float, "avg_precip": float, "majority_group": int}
    """
    target_dt = date.fromisoformat(target_date)
    temp_threshold = thresholds.get("temp_change_c", 4)

    context = []
    for delta in [-3, -2, -1, 1, 2, 3]:
        d = (target_dt + timedelta(days=delta)).isoformat()
        if d in all_forecasts:
            context.append(all_forecasts[d])

    if not context:
        return [], {}

    avg_temp_max = sum(c["temp_max"] for c in context) / len(context)
    avg_precip = sum(c["precipitation"] for c in context) / len(context)
    groups = [WMO_GROUP.get(c["weather_code"], 0) for c in context]
    majority_group = max(set(groups), key=groups.count)

    target = all_forecasts[target_date]
    target_group = WMO_GROUP.get(target["weather_code"], 0)

    anomalies = []

    # Rain/snow/storm on this day
    if target_group >= 3:
        desc = WMO_DESCRIPTION.get(target["weather_code"], "悪天候")
        anomalies.append(f"{GROUP_LABEL.get(target_group, '?')} ({desc} / {target['precipitation']:.1f}mm)")

    # Temperature outlier vs surrounding days
    temp_diff = target["temp_max"] - avg_temp_max
    if abs(temp_diff) >= temp_threshold:
        sign = "+" if temp_diff > 0 else ""
        anomalies.append(
            f"気温が周辺日より{sign}{temp_diff:.1f}°C "
            f"(周辺平均 {avg_temp_max:.1f}°C → この日 {target['temp_max']:.1f}°C)"
        )

    ctx = {"avg_temp_max": avg_temp_max, "avg_precip": avg_precip, "majority_group": majority_group}
    return anomalies, ctx


# ── Alert formatting ──────────────────────────────────────────────────────────

def format_alert(target_date: str, anomalies: list[str], current: dict, ctx: dict) -> str:
    desc_now = WMO_DESCRIPTION.get(current["weather_code"], "不明")
    DOW = ["月", "火", "水", "木", "金", "土", "日"]
    target_dt = date.fromisoformat(target_date)
    days_out = (target_dt - datetime.now(JST).date()).days
    dow = DOW[target_dt.weekday()]

    lines = [
        "⚠️ 天気 異常日アラート",
        f"📅 {target_date} ({dow}) — {days_out}日後",
        f"🌡️ この日の予報: {desc_now} / 最高{current['temp_max']:.1f}°C / 最低{current['temp_min']:.1f}°C / 降水{current['precipitation']:.1f}mm",
        f"📊 周辺日の平均: {GROUP_LABEL.get(ctx['majority_group'], '?')} / 最高{ctx['avg_temp_max']:.1f}°C",
        "",
        "異常点:",
    ] + [f"  • {a}" for a in anomalies]

    impact = get_business_impact(current, ctx)
    if impact:
        lines += ["", "💼 推奨アクション:"] + [f"  {a}" for a in impact]

    return "\n".join(lines)


# ── Main logic ───────────────────────────────────────────────────────────────

def run_check(config: dict, dry_run: bool = False):
    today = datetime.now(JST).date()
    min_days = config["window"]["days_out_min"]
    max_days = config["window"]["days_out_max"]

    target_dates = [
        (today + timedelta(days=d)).isoformat()
        for d in range(min_days, max_days + 1)
    ]

    logging.info("Fetching weather forecast from Open-Meteo...")
    all_forecasts = fetch_weather(config)
    stored = load_forecasts()
    now_str = datetime.now(JST).isoformat()

    for date_str in target_dates:
        if date_str not in all_forecasts:
            logging.warning(f"No forecast data for {date_str}, skipping.")
            continue

        current = all_forecasts[date_str]
        anomalies, ctx = detect_anomaly(date_str, all_forecasts, config["thresholds"])

        if not anomalies:
            logging.info(f"No anomaly for {date_str}.")
            stored.setdefault(date_str, {})["last_checked"] = now_str
            continue

        last_alerted = stored.get(date_str, {}).get("last_alerted")

        # Dedup: skip if same anomaly was already sent (weather group and temp unchanged)
        if last_alerted:
            temp_thresh = config["thresholds"].get("temp_change_c", 6) / 2
            temp_unchanged = abs(current["temp_max"] - last_alerted["temp_max"]) < temp_thresh
            group_unchanged = (
                WMO_GROUP.get(current["weather_code"], 0) ==
                WMO_GROUP.get(last_alerted["weather_code"], 0)
            )
            if temp_unchanged and group_unchanged:
                logging.info(f"Same anomaly already alerted for {date_str}, skipping.")
                stored.setdefault(date_str, {})["last_checked"] = now_str
                continue

        msg = format_alert(date_str, anomalies, current, ctx)
        if dry_run:
            print(f"[DRY RUN] Would send:\n{msg}\n{'─'*40}")
        else:
            send_message(config, msg)
            logging.info(f"Alert sent for {date_str}")

        stored.setdefault(date_str, {})["last_alerted"] = {**current, "recorded_at": now_str}
        stored[date_str]["last_checked"] = now_str

    # Clean up past dates
    for d in [d for d in stored if d < today.isoformat()]:
        del stored[d]
        logging.info(f"Removed past date: {d}")

    save_forecasts(stored)


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Hamamatsu weather anomaly alert")
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
