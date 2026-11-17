#!/usr/bin/env python3
"""本地定时调度器（新版：基于加密账号库 vault.json + 按账号幂等）。

行为：
- 每天到点（默认 09:00，可用 --hour/--minute 覆盖）跑一次全部账号签到。
- 「开机补跑」：到点后机器没开机，之后开机也会立即补跑。
- 「定向补跑」：只跑当天未完整成功的账号（service.is_pending），
  一个账号失败不再拖累整天，也不会把已成功的账号重复打一遍。
- 补跑有间隔与次数上限：至少间隔 30 分钟、每天最多 6 轮，避免失败账号被
  每 5 分钟疯狂重试而触发风控。
- 触发时间加 0~180 秒随机抖动，避免所有机器整点同时打官方接口。

运行：
    python local/scheduler.py                 # 默认 09:00 常驻
    python local/scheduler.py --hour 8 --minute 30
    python local/scheduler.py --once           # 立即跑一次就退出（配合系统 cron）
    python local/scheduler.py --once --force  # 忽略幂等，强制全跑
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import service                       # noqa: E402
from store import get_store          # noqa: E402

LOCAL_USER = "local"
# 状态格式：YYYY-MM-DD|当天已跑轮数|上次运行的 epoch 秒
STATE_PATH = os.path.join(ROOT, "logs", "scheduler_state.txt")
POLL_SECONDS = 300
MIN_INTERVAL_SECONDS = 1800        # 两轮之间至少 30 分钟
MAX_RUNS_PER_DAY = 6
JITTER_SECONDS = 180               # 触发抖动 0~180 秒


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def read_state() -> tuple[str, int, float]:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            date, count, ts = f.read().strip().split("|", 2)
        return date, int(count), float(ts)
    except (OSError, ValueError):
        return "", 0, 0.0


def write_state(date: str, count: int, ts: float) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        f.write(f"{date}|{count}|{ts}")


def pending_accounts() -> list:
    return [a for a in get_store("local").list_accounts(LOCAL_USER)
            if service.is_pending(a)]


def run_once(only_pending: bool = True) -> None:
    store = get_store("local")
    results = service.run_user(LOCAL_USER, store, only_pending=only_pending)
    if not results:
        print(f"[调度] {service._now()} 没有需要补跑的账号（当天已全部完成，或没有启用账号）。")
        return
    ok = sum(1 for r in results if r["success"])
    print(f"[调度] {service._now()} 完成：成功 {ok}/{len(results)}")
    for r in results:
        print(f"  {'OK' if r['success'] else 'FAIL'} {r['label']}: {r['message'][:80]}")


def main() -> None:
    p = argparse.ArgumentParser(description="本地定时签到")
    p.add_argument("--hour", type=int, default=9)
    p.add_argument("--minute", type=int, default=0)
    p.add_argument("--once", action="store_true", help="立即跑一次后退出")
    p.add_argument("--force", action="store_true",
                    help="忽略按账号幂等，强制对全部启用账号签到")
    args = p.parse_args()

    if args.once:
        run_once(only_pending=not args.force)
        return

    h, m = args.hour, args.minute
    print(f"[调度] 目标 {h:02d}:{m:02d}，每 {POLL_SECONDS}s 检查；"
          f"补跑间隔 ≥{MIN_INTERVAL_SECONDS // 60} 分钟，每天最多 {MAX_RUNS_PER_DAY} 轮。")
    try:
        while True:
            now = datetime.now()
            target = now.replace(hour=h, minute=m, second=0, microsecond=0)
            date, count, last_ts = read_state()
            if date != today_str():
                count = 0
            if (now >= target
                    and count < MAX_RUNS_PER_DAY
                    and time.time() - last_ts >= MIN_INTERVAL_SECONDS
                    and pending_accounts()):
                # 先写状态，避免本轮执行较慢时被下一次轮询重复触发
                write_state(today_str(), count + 1, time.time())
                jitter = random.uniform(0, JITTER_SECONDS)
                if jitter:
                    print(f"[调度] 抖动等待 {jitter:.0f}s")
                    time.sleep(jitter)
                print(f"[调度] {now:%H:%M:%S} 触发第 {count + 1} 轮，待补跑 "
                      f"{len(pending_accounts())} 个账号")
                run_once(only_pending=True)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[调度] 已停止。")


if __name__ == "__main__":
    main()
