"""存储层：把"账号凭据"从引擎里解耦出来。

为什么会话需要这一层（回答架构质疑）：
    引擎只负责"用凭据去签到"，不该关心凭据存在哪、属于谁。
    存储层负责：按用户身份隔离、加密落盘、增删改查、批量遍历。
    本地端用 JSON 文件，云端用云数据库 —— 两边共用同一套接口。

数据模型（Account）：
    id          账号唯一 id（uuid）
    platform    平台标识 mihoyo/kuro/yanyun/stub
    label       备注名，如"我的原神小号"
    credential  平台凭据字典，如 {"cookie": "..."} 或 {"token": "..."}
    enabled     是否参与批量签到
    last_run    上次签到时间（ISO 字符串）
    last_result 上次结果简报
"""

from .base import Account, AccountStore
from .local_store import LocalJsonStore

__all__ = ["Account", "AccountStore", "LocalJsonStore", "get_store"]


_CLOUD_SINGLETON = None


def get_store(kind: str = "local", **kwargs) -> AccountStore:
    """按后端类型取存储实例。

    kind="local"  -> 本地 JSON 文件（桌面端）
    kind="cloud"  -> 云数据库（需 CloudBase 环境，见 cloud_store.py）

    云端实例做单例缓存：云函数实例复用时可省掉重复初始化；
    降级（内存）模式下也保证同一进程内数据不丢。
    """
    if kind == "local":
        return LocalJsonStore(kwargs.get("path"))
    if kind == "cloud":
        global _CLOUD_SINGLETON
        if _CLOUD_SINGLETON is None:
            from .cloud_store import CloudBaseStore  # 延迟导入，本地无依赖也能用

            _CLOUD_SINGLETON = CloudBaseStore(**kwargs)
        return _CLOUD_SINGLETON
    raise ValueError(f"未知存储类型: {kind}")
