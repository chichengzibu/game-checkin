#!/usr/bin/env python3
"""本地签到客户端（CLI）—— 多账号 + 加密存储版。

用法：
    # 账号管理（凭据加密存 config/vault.json）
    python local/client.py add --platform mihoyo --label 原神大号 --cookie "ltuid=..."
    python local/client.py add --platform kuro  --label 鸣潮   --token "xxxx"
    python local/client.py add --platform yanyun --label 燕云  --token "xxxx"
    python local/client.py list
    python local/client.py remove --id <账号id>
    python local/client.py enable --id <账号id> --off

    # 签到
    python local/client.py checkin              # 所有账号
    python local/client.py checkin --id <账号id>  # 只签一个

凭据用 AES-GCM（或零依赖 HMAC 回退）加密落盘，不存明文。
主密钥来自环境变量 CHECKIN_MASTER_KEY，未设置则用开发默认值（部署务必改）。
"""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import service                              # noqa: E402
from store import get_store                 # noqa: E402
from store.base import Account              # noqa: E402

LOCAL_USER = "local"


def _store():
    return get_store("local")


def cmd_add(args) -> None:
    cred = {}
    if args.cookie:
        cred["cookie"] = args.cookie
    if args.token:
        cred["token"] = args.token
    if args.device_id:
        cred["device_id"] = args.device_id
    if not cred:
        print("❌ 至少要提供 --cookie 或 --token")
        return
    acc = Account(platform=args.platform, label=args.label, credential=cred)
    _store().add_account(LOCAL_USER, acc)
    print(f"✅ 已添加 [{args.label or args.platform}] id={acc.id}")
    print("   （凭据已加密存储，明文不会落盘）")


def cmd_list(args) -> None:
    accs = _store().list_accounts(LOCAL_USER)
    if not accs:
        print("（还没有账号。用 add 添加，如：")
        print('  python local/client.py add --platform mihoyo --label 大号 --cookie "ltuid=..."）')
        return
    print(f"共 {len(accs)} 个账号：")
    for a in accs:
        flag = "启用" if a.enabled else "停用"
        print(f"  - {a.label or a.platform}  [{a.platform}] {flag}  id={a.id}")
        if a.last_run:
            print(f"      上次：{a.last_run}  {a.last_result}")


def cmd_remove(args) -> None:
    ok = _store().delete_account(LOCAL_USER, args.id)
    print("✅ 已删除" if ok else "❌ 没找到该账号")


def cmd_enable(args) -> None:
    accs = _store().list_accounts(LOCAL_USER)
    for a in accs:
        if a.id == args.id:
            a.enabled = not args.off
            _store().update_account(LOCAL_USER, a)
            print(f"✅ {a.label} 已{'启用' if a.enabled else '停用'}")
            return
    print("❌ 没找到该账号")


def cmd_checkin(args) -> None:
    if args.id:
        accs = [a for a in _store().list_accounts(LOCAL_USER) if a.id == args.id]
        if not accs:
            print("❌ 没找到该账号")
            return
        results = []
        for a in accs:
            ok, msg = service._check_one(a)
            _store().save_result(LOCAL_USER, a.id, service._now(), msg)
            results.append({"label": a.label or a.platform, "success": ok, "message": msg})
    else:
        results = service.run_user(LOCAL_USER, _store())

    if not results:
        print("（没有启用的账号）")
        return
    print(f"=== 签到结果 {service._now()} ===")
    for r in results:
        print(f"{'✅' if r['success'] else '❌'} [{r['label']}] {r['message']}")
    ok = sum(1 for r in results if r["success"])
    print(f"=== 完成：成功 {ok}/{len(results)} ===")


def main() -> None:
    p = argparse.ArgumentParser(description="游戏签到 CLI（多账号 + 加密存储）")
    sub = p.add_subparsers(dest="cmd")

    pa = sub.add_parser("add", help="添加账号")
    pa.add_argument("--platform", required=True,
                    choices=["mihoyo", "kuro", "yanyun", "stub"])
    pa.add_argument("--label", default="")
    pa.add_argument("--cookie", default="")
    pa.add_argument("--token", default="")
    pa.add_argument("--device-id", default="")
    pa.set_defaults(func=cmd_add)

    pl = sub.add_parser("list", help="列出账号")
    pl.set_defaults(func=cmd_list)

    pr = sub.add_parser("remove", help="删除账号")
    pr.add_argument("--id", required=True)
    pr.set_defaults(func=cmd_remove)

    pe = sub.add_parser("enable", help="启用/停用账号")
    pe.add_argument("--id", required=True)
    pe.add_argument("--off", action="store_true", help="停用")
    pe.set_defaults(func=cmd_enable)

    pc = sub.add_parser("checkin", help="签到")
    pc.add_argument("--id", default="", help="只签指定账号")
    pc.set_defaults(func=cmd_checkin)

    args = p.parse_args()
    if not getattr(args, "func", None):
        p.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
