"""微信云开发（CloudBase）Python 云函数入口 —— 重构版。

架构（按"多用户 + 加密存储 + 批量"重做）：
    云函数用 event.userInfo.openId 识别用户（微信自动注入，无需密码）
        ↓
    store.cloud_store.CloudBaseStore 按 openid 隔离读写，凭据加密落库
        ↓
    service.run_user / run_all 批量签到
        ↓
    engine.* 适配器真正请求游戏接口

action 协议（小程序通过 data.action 指定）：
    list      列出当前用户的账号（不含凭据明文）
    add       添加账号 {account:{platform,label,credential,enabled}}
    update    修改账号 {account:{id,...}}
    remove    删除账号 {account_id}
    checkin   签到当前用户全部账号（或 {account_id} 只签一个）
    checkin_all  【仅供定时触发器】遍历所有用户批量签到

部署：
    1. 云函数目录 requirements.txt: tcb_admin
    2. 环境变量：MASTER_KEY（必填，随机串）、TCB_ENV（一般自动注入）
    3. 建集合 checkin_accounts，索引 openid
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from store import get_store               # noqa: E402
from store.base import Account            # noqa: E402
import service                            # noqa: E402


def _out(user_id: str, store) -> list[dict]:
    """账号列表（脱敏：只返回是否有凭据，不回传明文）。"""
    rows = []
    for a in store.list_accounts(user_id):
        rows.append({
            "id": a.id,
            "platform": a.platform,
            "label": a.label,
            "enabled": a.enabled,
            "has_credential": bool(a.credential),
            "last_run": a.last_run,
            "last_result": a.last_result,
        })
    return rows


def main(event, context):
    event = event or {}

    # 微信小程序调用时自动注入 openid；定时触发器没有用户上下文
    user_info = event.get("userInfo") or {}
    openid = user_info.get("openId") or event.get("openid") or ""
    action = event.get("action") or "list"

    store = get_store("cloud")

    # ---- 定时任务：遍历所有用户 ----
    if action == "checkin_all":
        summary = service.run_all(store)
        return {"ok": True, "action": action, "summary": {
            "users": summary["users"], "total": summary["total"],
            "ok": summary["ok"],
        }}

    # 以下 action 都需要用户身份
    if not openid:
        return {"ok": False, "error": "缺少用户身份（openid）。请在云函数中调用。"}

    if action == "list":
        return {"ok": True, "accounts": _out(openid, store)}

    if action == "add":
        raw = event.get("account") or {}
        acc = Account(
            platform=raw.get("platform", "stub"),
            label=raw.get("label", ""),
            credential=raw.get("credential") or {},
            enabled=raw.get("enabled", True),
        )
        store.add_account(openid, acc)
        return {"ok": True, "id": acc.id}

    if action == "update":
        raw = event.get("account") or {}
        if not raw.get("id"):
            return {"ok": False, "error": "缺少 account.id"}
        acc = Account(
            platform=raw.get("platform", "stub"),
            label=raw.get("label", ""),
            credential=raw.get("credential") or {},
            enabled=raw.get("enabled", True),
            id=raw["id"],
        )
        store.update_account(openid, acc)
        return {"ok": True}

    if action == "remove":
        aid = event.get("account_id")
        if not aid:
            return {"ok": False, "error": "缺少 account_id"}
        return {"ok": store.delete_account(openid, aid)}

    if action == "checkin":
        one = event.get("account_id")
        if one:
            # 单账号：只签这一个
            accounts = [a for a in store.list_accounts(openid) if a.id == one]
            results = []
            for a in accounts:
                ok, msg = service._check_one(a)
                store.save_result(openid, a.id, service._now(), msg)
                results.append({"id": a.id, "label": a.label or a.platform,
                                "success": ok, "message": msg})
            return {"ok": True, "results": results}
        results = service.run_user(openid, store)
        return {"ok": True, "results": results}

    return {"ok": False, "error": f"未知 action: {action}"}
