#!/usr/bin/env python3
"""本地定时调度器（新版：基于加密账号库 vault.json）。

行为：
- 每天到点（默认 09:00，可用 config/schedule.json 或参数覆盖）跑一次全部账号签到。
- 用 logs/last_sign_date.txt 记录当天是否已签，避免重复。
- 签到对象来自 store 里的账号库（local/client.py add 添加的那些）。

运行：
    python local/scheduler.py                 # 默认 09:00
    python local/scheduler.py --hour 8 --minute 30
    python local/scheduler.py --once          # 立即跑一次就退出（配合系统 cron）

后台常驻：
    nohup python local/scheduler.py > logs/scheduler.out 2>&1 &
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import service                       # noqa: E402
from store import get_store          # noqa: E402

LOCAL_USER = "local"
STATE_PATH = os.path.join(ROOT, "logs", "last_sign_date.txt")
POLL_SECONDS = 300


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def already_signed_today() -> bool:
    if not os.path.exists(STATE_PATH):
        return False
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        return f.read().strip() == today_str()


def mark_signed_today() -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        f.write(today_str())


def run_once() -> None:
    store = get_store("local")
    results = service.run_user(LOCAL_USER, store)
    if not results:
        print("[调度] 没有可签到的账号。请先用 local/client.py add 添加。")
        return
    ok = sum(1 for r in results if r["success"])
    print(f"[调度] {service._now()} 完成：成功 {ok}/{len(results)}")
    for r in results:
        print(f"  {'✅' if r['success'] else '❌'} {r['label']}: {r['message'][:60]}")
    mark_signed_today()


def main() -> None:
    p = argparse.ArgumentParser(description="本地定时签到")
    p.add_argument("--hour", type=int, default=9)
    p.add_argument("--minute", type=int, default=0)
    p.add_argument("--once", action="store_true", help="立即跑一次后退出")
    args = p.parse_args()

    if args.once:
        run_once()
        return

    h, m = args.hour, args.minute
    print(f"[调度] 目标 {h:02d}:{m:02d}，每 {POLL_SECONDS}s 检查。Ctrl+C 退出。")
    try:
        while True:
            now = datetime.now()
            target = now.replace(hour=h, minute=m, second=0, microsecond=0)
            if now >= target and not already_signed_today():
                print(f"[调度] {now:%H:%M:%S} 触发")
                run_once()
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[调度] 已停止。")


if __name__ == "__main__":
    main()
