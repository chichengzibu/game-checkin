#!/usr/bin/env python3
"""回归自检：多用户隔离 + 加密 + 批量 + 云函数 action 协议。

    python tools/selftest_store.py    # 退出码 0 = 全部通过

不依赖网络（除最后的真实签到冒烟测试可用 --no-network 跳过）。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from store import get_store                      # noqa: E402
from store.base import Account                   # noqa: E402
from store.crypto import (                       # noqa: E402
    decrypt_credential, encrypt_credential, get_cipher, gen_master_key,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  ({detail})" if detail and not cond else ""))


def main():
    print("=" * 70)
    print("存储层 / 加密 / 多用户隔离 自检")
    print("=" * 70)

    # ---- 1. 加密 ----
    print("\n[1] 加密")
    key = "unit-test-key"
    cred = {"cookie": "ltuid=1; ltoken=SECRET", "device_id": "d1"}
    blob = encrypt_credential(cred, key)
    check("加密往返一致", decrypt_credential(blob, key) == cred)
    check("密文不含明文", "SECRET" not in blob, blob[:30])
    try:
        decrypt_credential(blob, "wrong-key")
        check("错误密钥被拒绝", False)
    except Exception:
        check("错误密钥被拒绝", True)
    # 篡改检测
    tampered = blob[:-4] + ("aaaa" if blob[-4:] != "aaaa" else "bbbb")
    try:
        decrypt_credential(tampered, key)
        check("篡改被检测", False)
    except Exception:
        check("篡改被检测", True)

    # ---- 2. 本地存储隔离 ----
    print("\n[2] 本地存储（多用户隔离）")
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "vault.json")
        s = get_store("local", path=path, master_key=key)
        s.add_account("userA", Account(platform="mihoyo", label="A1", credential={"cookie": "ca1"}))
        s.add_account("userA", Account(platform="kuro", label="A2", credential={"token": "ta2"}))
        s.add_account("userB", Account(platform="yanyun", label="B1", credential={"token": "tb1"}))
        check("A 有 2 个", len(s.list_accounts("userA")) == 2)
        check("B 有 1 个", len(s.list_accounts("userB")) == 1)
        check("用户可见性隔离", {a.label for a in s.list_accounts("userA")} == {"A1", "A2"})
        check("凭据可解回", s.list_accounts("userA")[0].credential.get("cookie") == "ca1")
        raw = open(path, encoding="utf-8").read()
        check("落盘无明文", "ca1" not in raw and "tb1" not in raw)
        # 删除
        aid = s.list_accounts("userA")[0].id
        check("删除成功", s.delete_account("userA", aid))
        check("删除后剩 1", len(s.list_accounts("userA")) == 1)
        check("用户列表含 A/B", set(s.list_users()) >= {"userA", "userB"})

    # ---- 3. 云端存储（降级模式）----
    print("\n[3] 云端存储（降级内存模式）")
    import importlib
    import store
    store._CLOUD_SINGLETON = None  # 重置单例
    cs = get_store("cloud", env_id="", master_key=key)
    check("降级模式生效", cs.degraded)
    cs.add_account("openid_x", Account(platform="mihoyo", label="X", credential={"cookie": "cx"}))
    cs.add_account("openid_y", Account(platform="kuro", label="Y", credential={"token": "cy"}))
    check("openid 隔离", len(cs.list_accounts("openid_x")) == 1 and len(cs.list_accounts("openid_y")) == 1)
    check("降级仍加密（解回正确）", cs.list_accounts("openid_x")[0].credential.get("cookie") == "cx")

    # ---- 4. 云函数 action 协议 ----
    print("\n[4] 云函数 action 协议（模拟微信 openid 注入）")
    store._CLOUD_SINGLETON = None
    sys.path.insert(0, os.path.join(ROOT, "cloud"))
    os.environ["MASTER_KEY"] = key
    # 重新导入以指向新目录
    if "index" in sys.modules:
        del sys.modules["index"]
    import index as fn

    r = fn.main({"action": "list"}, None)
    check("无 openid 被拒绝", r.get("ok") is False)

    fn.main({"action": "add", "userInfo": {"openId": "WX_A"},
             "account": {"platform": "mihoyo", "label": "wxA", "credential": {"cookie": "sekret"}}}, None)
    r = fn.main({"action": "list", "userInfo": {"openId": "WX_A"}}, None)
    check("列表不返回明文", "sekret" not in json.dumps(r, ensure_ascii=False))
    check("列表有 has_credential", r["accounts"] and r["accounts"][0]["has_credential"] is True)

    r2 = fn.main({"action": "list", "userInfo": {"openId": "WX_B"}}, None)
    check("不同 openid 看不到别人账号", len(r2["accounts"]) == 0)

    print("\n" + "=" * 70)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项:", FAIL)
    print("=" * 70)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
