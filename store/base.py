"""存储层接口定义。"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Account:
    platform: str
    label: str = ""
    credential: dict = field(default_factory=dict)
    enabled: bool = True
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    last_run: Optional[str] = None
    last_result: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_any(cls, d: dict) -> "Account":
        """兼容三种历史格式：
        1. 新格式（本 dataclass 字段）
        2. 旧本地配置 {platform, label, cookie, token}
        """
        if "credential" in d:
            return cls(
                platform=d.get("platform", "stub"),
                label=d.get("label", ""),
                credential=d.get("credential") or {},
                enabled=d.get("enabled", True),
                id=d.get("id") or uuid.uuid4().hex,
                last_run=d.get("last_run"),
                last_result=d.get("last_result"),
            )
        # 旧格式迁移：把散落的 cookie/token 收进 credential
        cred = {}
        for k in ("cookie", "token", "device_id", "game_id", "place", "yunyouji"):
            if k in d and d[k] not in (None, ""):
                cred[k] = d[k]
        return cls(
            platform=d.get("platform", "stub"),
            label=d.get("label", ""),
            credential=cred,
            enabled=d.get("enabled", True),
        )


class AccountStore(ABC):
    """账号存储抽象。

    云端实现必须按用户身份（openid）隔离；本地实现固定用户。
    """

    # ---- 账号 CRUD ----
    @abstractmethod
    def list_accounts(self, user_id: str) -> list[Account]:
        ...

    @abstractmethod
    def add_account(self, user_id: str, account: Account) -> Account:
        ...

    @abstractmethod
    def update_account(self, user_id: str, account: Account) -> Account:
        ...

    @abstractmethod
    def delete_account(self, user_id: str, account_id: str) -> bool:
        ...

    @abstractmethod
    def save_result(self, user_id: str, account_id: str,
                    last_run: str, last_result: str) -> None:
        ...

    # ---- 供定时任务批量遍历 ----
    @abstractmethod
    def list_users(self) -> list[str]:
        """返回所有有账号的用户 id，供定时任务遍历。"""
        ...
