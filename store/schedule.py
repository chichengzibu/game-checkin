"""签到时间设置与调度状态（本地 JSON，非敏感数据）。

配置文件：config/settings.json（可用 CHECKIN_SETTINGS_PATH 覆盖）
状态文件：logs/scheduler_state.txt（与 local/scheduler.py 共用，避免两边重复跑）

设置只包含时间/开关/频率，不包含任何账号凭据。
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime


def _app_dir() -> str:
    """与 vault.json 一致：打包后用 exe 同目录，源码运行用项目根。

    schedule.py 的 __file__ 在 PyInstaller 里指向 _MEIPASS，
    不能直接拿它拼 config/logs，否则设置和调度状态重启即丢。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    "schedule_enabled": True,
    "schedule_time": "09:00",
    "schedule_jitter_seconds": 180,
    "max_runs_per_day": 6,
    "min_interval_minutes": 30,
}


def settings_path() -> str:
    return os.environ.get("CHECKIN_SETTINGS_PATH") or os.path.join(
        _app_dir(), "config", "settings.json")


def state_path() -> str:
    return os.environ.get("CHECKIN_SCHEDULE_STATE") or os.path.join(
        _app_dir(), "logs", "scheduler_state.txt")


def _clamp_int(value, low: int, high: int, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, n))


def parse_hhmm(value: str) -> tuple[int, int]:
    """'9:05' / '09:05' -> (9, 5)；非法值回落到 09:00。"""
    try:
        h, m = str(value or "").strip().split(":", 1)
        h, m = int(h), int(m)
    except (ValueError, AttributeError):
        return 9, 0
    if not (0 <= h <= 23 and 0 <= m <= 59):
        return 9, 0
    return h, m


def normalize(raw: dict | None) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    h, m = parse_hhmm(raw.get("schedule_time", DEFAULTS["schedule_time"]))
    return {
        "schedule_enabled": bool(raw.get("schedule_enabled",
                                          DEFAULTS["schedule_enabled"])),
        "schedule_time": f"{h:02d}:{m:02d}",
        "schedule_jitter_seconds": _clamp_int(
            raw.get("schedule_jitter_seconds"),
            0, 1800, DEFAULTS["schedule_jitter_seconds"]),
        "max_runs_per_day": _clamp_int(
            raw.get("max_runs_per_day"), 1, 24,
            DEFAULTS["max_runs_per_day"]),
        "min_interval_minutes": _clamp_int(
            raw.get("min_interval_minutes"), 5, 720,
            DEFAULTS["min_interval_minutes"]),
    }


def load_settings() -> dict:
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            return normalize(json.load(f))
    except (OSError, ValueError, TypeError):
        return normalize({})


def save_settings(patch: dict) -> dict:
    """合并保存；只接受已知字段，写临时文件再原子替换。"""
    cur = load_settings()
    for k in DEFAULTS:
        if k in (patch or {}):
            cur[k] = patch[k]
    cur = normalize(cur)
    path = settings_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return cur


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def read_state() -> tuple[str, int, float]:
    """返回 (日期, 当天已跑轮数, 上次运行 epoch 秒)。"""
    try:
        with open(state_path(), "r", encoding="utf-8") as f:
            date, count, ts = f.read().strip().split("|", 2)
        return date, int(count), float(ts)
    except (OSError, ValueError):
        return "", 0, 0.0


def write_state(date: str, count: int, ts: float) -> None:
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{date}|{count}|{ts}")


def is_due(now: datetime | None = None, settings: dict | None = None) -> bool:
    """到点、未超当日轮数、与上轮间隔足够 → True（不看是否有待跑账号）。"""
    now = now or datetime.now()
    s = settings or load_settings()
    if not s.get("schedule_enabled"):
        return False
    h, m = parse_hhmm(s.get("schedule_time"))
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if now < target:
        return False
    date, count, last_ts = read_state()
    if date != today_str():
        count = 0
    if count >= int(s.get("max_runs_per_day") or 6):
        return False
    if time.time() - last_ts < int(s.get("min_interval_minutes") or 30) * 60:
        return False
    return True
