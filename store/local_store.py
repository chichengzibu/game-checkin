"""本地 JSON 存储实现（桌面端）。

文件结构：
{
  "_users": ["local"],
  "local": {
     "accounts": [
        {"id":..., "platform":..., "label":..., "credential_enc": "...", ...}
     ]
  }
}

凭据加密存储，字段名 credential_enc；读取时解密回 credential。

主密钥（master key）与 vault 路径的稳定性直接决定「要不要反复重新登录」：
    - PyInstaller 打包后 __file__ 指向临时解包目录 _MEIPASS，绝不能把
      vault 放那里（重启即丢）。因此打包后一律用 exe 所在目录。
    - 全新安装会生成随机主密钥并持久化到 config/master.key，重启后仍可
      解密，无需用户重新授权；已有旧库则沿用历史默认密钥，不贸然换 key
      把旧库锁死（也可用 CHECKIN_MASTER_KEY 显式指定）。
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
from datetime import datetime

from .base import Account, AccountStore
from .crypto import decrypt_credential, encrypt_credential

DEFAULT_USER = "local"
LEGACY_DEFAULT_KEY = "dev-only-insecure-key-change-me"


def _app_dir() -> str:
    """应用数据根目录：打包后用 exe 所在目录，源码运行时用项目根。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_vault_path() -> str:
    return os.environ.get("CHECKIN_VAULT_PATH") or os.path.join(
        _app_dir(), "config", "vault.json"
    )


def default_key_path() -> str:
    return os.environ.get("CHECKIN_MASTER_KEY_FILE") or os.path.join(
        _app_dir(), "config", "master.key"
    )


def resolve_master_key() -> str:
    """解析主密钥：环境变量 > 用户级 key 文件 > 兼容旧库 > 新建随机 key。"""
    env = os.environ.get("CHECKIN_MASTER_KEY")
    if env:
        return env

    key_file = default_key_path()
    try:
        if os.path.isfile(key_file):
            with open(key_file, "r", encoding="utf-8") as f:
                k = f.read().strip()
            if k:
                return k
    except OSError:
        pass

    # 已有旧库但没有 key 文件：沿用历史默认 key，绝不贸然换新 key 把旧库锁死
    if os.path.isfile(default_vault_path()):
        return LEGACY_DEFAULT_KEY

    # 全新安装：生成随机密钥并持久化，保证重启后仍能解密
    k = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(k + "\n")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
    except OSError:
        return LEGACY_DEFAULT_KEY
    return k


class LocalJsonStore(AccountStore):
    def __init__(self, path: str | None = None, master_key: str | None = None):
        self.path = path or default_vault_path()
        self.master_key = master_key or resolve_master_key()
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            self._write({"_users": [DEFAULT_USER], DEFAULT_USER: {"accounts": []}})

    # ---- 底层 IO ----
    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def _user_bucket(self, data: dict, user_id: str) -> dict:
        data.setdefault("_users", [])
        if user_id not in data["_users"]:
            data["_users"].append(user_id)
        return data.setdefault(user_id, {"accounts": []})

    def _decode(self, raw: dict) -> Account:
        d = dict(raw)
        enc = d.pop("credential_enc", None)
        if enc:
            try:
                d["credential"] = decrypt_credential(enc, self.master_key)
            except Exception:
                d["credential"] = {}
        return Account.from_any(d)

    def _encode(self, acc: Account) -> dict:
        d = acc.to_dict()
        cred = d.pop("credential", {})
        d["credential_enc"] = encrypt_credential(cred, self.master_key)
        return d

    # ---- 接口实现 ----
    def list_accounts(self, user_id: str) -> list[Account]:
        with self._lock:
            data = self._read()
        bucket = data.get(user_id, {"accounts": []})
        return [self._decode(r) for r in bucket.get("accounts", [])]

    def add_account(self, user_id: str, account: Account) -> Account:
        with self._lock:
            data = self._read()
            bucket = self._user_bucket(data, user_id)
            if not account.id:
                from uuid import uuid4

                account.id = uuid4().hex
            bucket["accounts"].append(self._encode(account))
            self._write(data)
        return account

    def update_account(self, user_id: str, account: Account) -> Account:
        with self._lock:
            data = self._read()
            bucket = self._user_bucket(data, user_id)
            for i, r in enumerate(bucket["accounts"]):
                if r.get("id") == account.id:
                    bucket["accounts"][i] = self._encode(account)
                    self._write(data)
                    return account
            bucket["accounts"].append(self._encode(account))
            self._write(data)
        return account

    def delete_account(self, user_id: str, account_id: str) -> bool:
        with self._lock:
            data = self._read()
            bucket = self._user_bucket(data, user_id)
            before = len(bucket["accounts"])
            bucket["accounts"] = [
                r for r in bucket["accounts"] if r.get("id") != account_id
            ]
            self._write(data)
            return len(bucket["accounts"]) < before

    def save_result(self, user_id: str, account_id: str,
                    last_run: str, last_result: str) -> None:
        with self._lock:
            data = self._read()
            bucket = self._user_bucket(data, user_id)
            for r in bucket["accounts"]:
                if r.get("id") == account_id:
                    r["last_run"] = last_run
                    r["last_result"] = last_result
            self._write(data)

    def list_users(self) -> list[str]:
        with self._lock:
            data = self._read()
        return [u for u in data.get("_users", []) if u]


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")
