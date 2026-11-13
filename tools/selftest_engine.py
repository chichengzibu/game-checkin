#!/usr/bin/env python3
"""引擎常量自检：直接 import engine.mihoyo 的常量，打真实 luna/home 验证。

不需要 Cookie（home 是公共接口）。用于"盐值/act_id/app_version 是否过期"的快速回归。

    python tools/selftest_engine.py        # 退出码 0 = 全部通过
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine import mihoyo as M  # noqa: E402
from engine.base import get_session  # noqa: E402


def check_normalize_cookie() -> list[str]:
    """回归：V2 cookie 必须被补出 V1 别名（否则 luna 报 -100）。"""
    print("-" * 72)
    print("normalize_cookie 回归（V2 -> V1 别名补齐）")
    raw = ("cookie_token_v2=v2_A; account_id_v2=12345678; ltoken_v2=v2_B; "
           "ltmid_v2=M; ltuid_v2=12345678")
    out = M.normalize_cookie(raw)
    d = dict(p.strip().split("=", 1) for p in out.split(";") if "=" in p)
    fails = []
    for key in ("cookie_token", "account_id", "ltoken", "ltuid", "ltmid"):
        if not d.get(key):
            print(f"❌ 缺少 V1 别名 {key}")
            fails.append(key)
    if d.get("cookie_token") != "v2_A" or d.get("account_id") != "12345678":
        print("❌ V1 别名取值不对:", d.get("cookie_token"), d.get("account_id"))
        fails.append("value")
    if d.get("cookie_token_v2") != "v2_A":
        print("❌ 原有 V2 被破坏")
        fails.append("v2-lost")
    if not fails:
        print("✅ V1 别名补齐正确，且保留原有 V2")
    return fails


def main() -> int:
    s = get_session()
    print("=" * 72)
    print("engine.mihoyo 常量自检（真实请求 luna/home，无需 Cookie）")
    print(f"APP_VERSION={M.APP_VERSION}  SALT_WEB={M.SALT_WEB[:8]}...")
    print("=" * 72)

    failures = []
    failures.extend(check_normalize_cookie())
    print("-" * 72)
    print("luna/home 常量核对")
    for biz, cfg in M.GAMES.items():
        headers = {
            "DS": M.gen_ds(),
            "x-rpc-app_version": M.APP_VERSION,
            "x-rpc-client_type": "5",
            "x-rpc-device_id": "selftest-device",
            "x-rpc-signgame": cfg["signgame"],
            "Origin": "https://act.mihoyo.com",
            "Referer": "https://act.mihoyo.com/",
        }
        try:
            r = s.get(
                cfg["api"] + cfg["path"] + "/home",
                params={"lang": "zh-cn", "act_id": cfg["act_id"]},
                headers=headers,
                timeout=20,
            )
            d = r.json()
        except Exception as e:
            print(f"❌ {cfg['name']:8s} 请求异常: {e}")
            failures.append(cfg["name"])
            continue

        rc = d.get("retcode")
        awards = (d.get("data") or {}).get("awards") or []
        if rc == 0 and awards:
            print(f"✅ {cfg['name']:8s} act={cfg['act_id']} 奖励条目={len(awards)}")
        else:
            print(f"❌ {cfg['name']:8s} rc={rc} msg={d.get('message')} "
                  f"-> 常量可能过期，请跑 tools/ 探测脚本更新")
            failures.append(cfg["name"])

    print("=" * 72)
    if failures:
        print(f"失败: {failures}")
        return 1
    print("全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
