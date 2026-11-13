"""云数据库存储实现（微信云开发 / CloudBase）。

⚠️ 重要事实（已核对官方文档）：
    Python 云函数 **不能** 像 Node.js 那样 `require('@cloudbase/node-sdk')` 直连数据库。
    Python 运行时访问云数据库需要 `tcb_admin` 包，或走 HTTP API。

本文件按 tcb_admin 的常见接口编写，并做了**降级保护**：
    若环境里没有 tcb_admin（本地开发 / 未安装），自动退化为内存字典，
    让逻辑可测试、可本地跑，部署时再装依赖即可。

部署准备：
    1. 云函数目录加 requirements.txt: tcb_admin
    2. 环境变量 MASTER_KEY 设为随机串（生成见 store.crypto.gen_master_key）
    3. 控制台建集合 `checkin_accounts`，索引 openid

集合结构（每个账号一条文档）：
    { _id, openid, platform, label, credential_enc, enabled,
      last_run, last_result, created_at }
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime

from .base import Account, AccountStore
from .crypto import decrypt_credential, encrypt_credential

COLLECTION = "checkin_accounts"

try:  # 云函数环境
    from tcb_admin import TCB  # type: ignore

    _HAS_TCB = True
except Exception:  # noqa: BLE001
    _HAS_TCB = False


class CloudBaseStore(AccountStore):
    def __init__(self, env_id: str | None = None, master_key: str | None = None):
        self.env_id = env_id or os.environ.get("TCB_ENV", "")
        self.master_key = master_key or os.environ.get("MASTER_KEY", "")
        self._mem: dict[str, dict] = {}  # 降级用
        if _HAS_TCB and self.env_id:
            self._db = TCB(self.env_id).database()
            self._collection = self._db.collection(COLLECTION)
        else:
            self._db = None
            self._collection = None

    @property
    def degraded(self) -> bool:
        return self._collection is None

    # ---- 底层读写 ----
    def _raw_list(self, user_id: str) -> list[dict]:
        if self.degraded:
            return list(self._mem.get(user_id, {}).values())
        res = self._collection.where({"openid": user_id}).get()
        return res.get("data", []) if isinstance(res, dict) else list(res)

    def _raw_put(self, doc: dict) -> None:
        if self.degraded:
            self._mem.setdefault(doc["openid"], {})[doc["id"]] = doc
            return
        # 云数据库没有统一 upsert，按 _id 存在性二选一
        self._collection.doc(doc["id"]).set(doc)

    def _raw_delete(self, user_id: str, account_id: str) -> bool:
        if self.degraded:
            bucket = self._mem.get(user_id, {})
            return bucket.pop(account_id, None) is not None
        try:
            self._collection.doc(account_id).remove()
            return True
        except Exception:  # noqa: BLE001
            return False

    # ---- 编解码 ----
    @staticmethod
    def _row_id(user_id: str, account_id: str) -> str:
        return f"{user_id}_{account_id}"

    def _decode(self, doc: dict) -> Account:
        cred = {}
        enc = doc.get("credential_enc")
        if enc:
            try:
                cred = decrypt_credential(enc, self.master_key)
            except Exception:  # noqa: BLE001
                cred = {}
        return Account(
            platform=doc.get("platform", "stub"),
            label=doc.get("label", ""),
            credential=cred,
            enabled=doc.get("enabled", True),
            id=doc.get("id") or doc.get("_id", ""),
            last_run=doc.get("last_run"),
            last_result=doc.get("last_result"),
        )

    def _encode(self, user_id: str, acc: Account) -> dict:
        if not acc.id:
            acc.id = uuid.uuid4().hex
        return {
            "id": acc.id,
            "openid": user_id,
            "platform": acc.platform,
            "label": acc.label,
            "credential_enc": encrypt_credential(acc.credential, self.master_key),
            "enabled": acc.enabled,
            "last_run": acc.last_run,
            "last_result": acc.last_result,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }

    # ---- 接口实现 ----
    def list_accounts(self, user_id: str) -> list[Account]:
        return [self._decode(d) for d in self._raw_list(user_id)]

    def add_account(self, user_id: str, account: Account) -> Account:
        if not account.id:
            account.id = uuid.uuid4().hex
        self._raw_put(self._encode(user_id, account))
        return account

    def update_account(self, user_id: str, account: Account) -> Account:
        self._raw_put(self._encode(user_id, account))
        return account

    def delete_account(self, user_id: str, account_id: str) -> bool:
        return self._raw_delete(user_id, account_id)

    def save_result(self, user_id: str, account_id: str,
                    last_run: str, last_result: str) -> None:
        for acc in self.list_accounts(user_id):
            if acc.id == account_id:
                acc.last_run = last_run
                acc.last_result = last_result
                self._raw_put(self._encode(user_id, acc))
                return

    def list_users(self) -> list[str]:
        if self.degraded:
            return [u for u, v in self._mem.items() if v]
        try:
            res = self._collection.field({"openid": True}).get()
            rows = res.get("data", []) if isinstance(res, dict) else list(res)
            return sorted({r["openid"] for r in rows if r.get("openid")})
        except Exception:  # noqa: BLE001
            return []
