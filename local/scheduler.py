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
from store import schedule           # noqa: E402

LOCAL_USER = "local"
# 状态与设置与 Web 内置调度器共用：同一份 config/settings.json / logs 状态，
# 因此「界面里改时间」和「命令行常驻」不会各跑一套。
STATE_PATH = schedule.state_path()
POLL_SECONDS = 300


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def read_state() -> tuple[str, int, float]:
    return schedule.read_state()


def write_state(date: str, count: int, ts: float) -> None:
    schedule.write_state(date, count, ts)


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
    p.add_argument("--hour", type=int, default=None,
                   help="覆盖设置里的小时（默认读 config/settings.json）")
    p.add_argument("--minute", type=int, default=None,
                   help="覆盖设置里的分钟（默认读 config/settings.json）")
    p.add_argument("--once", action="store_true", help="立即跑一次后退出")
    p.add_argument("--force", action="store_true",
                    help="忽略按账号幂等，强制对全部启用账号签到")
    args = p.parse_args()

    if args.once:
        run_once(only_pending=not args.force)
        return

    cfg = schedule.load_settings()
    if args.hour is not None or args.minute is not None:
        h = args.hour if args.hour is not None else schedule.parse_hhmm(
            cfg["schedule_time"])[0]
        m = args.minute if args.minute is not None else schedule.parse_hhmm(
            cfg["schedule_time"])[1]
        cfg = schedule.save_settings({"schedule_time": f"{h:02d}:{m:02d}"})
    if not cfg["schedule_enabled"]:
        print("[调度] 设置里已关闭自动签到；如需临时运行请加 --once。")
        return

    h, m = schedule.parse_hhmm(cfg["schedule_time"])
    min_interval = int(cfg["min_interval_minutes"])
    max_runs = int(cfg["max_runs_per_day"])
    jitter_max = int(cfg["schedule_jitter_seconds"])
    print(f"[调度] 目标 {h:02d}:{m:02d}（来自设置），每 {POLL_SECONDS}s 检查；"
          f"补跑间隔 ≥{min_interval} 分钟，每天最多 {max_runs} 轮。")
    try:
        while True:
            cfg = schedule.load_settings()
            if not cfg["schedule_enabled"]:
                time.sleep(POLL_SECONDS)
                continue
            if schedule.is_due(settings=cfg) and pending_accounts():
                date, count, last_ts = read_state()
                if date != today_str():
                    count = 0
                # 先写状态，避免本轮执行较慢时被下一次轮询重复触发
                write_state(today_str(), count + 1, time.time())
                jitter = random.uniform(0, int(cfg["schedule_jitter_seconds"]))
                if jitter:
                    print(f"[调度] 抖动等待 {jitter:.0f}s")
                    time.sleep(jitter)
                print(f"[调度] {datetime.now():%H:%M:%S} 触发第 {count + 1} 轮，"
                      f"待补跑 {len(pending_accounts())} 个账号")
                run_once(only_pending=True)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[调度] 已停止。")


if __name__ == "__main__":
    main()
