"""签到服务：把「存储层」和「引擎」粘起来。

职责：
    - 给某个用户的全部账号批量签到
    - 给所有用户的全部账号批量签到（定时任务用）
    - 更新每个账号的 last_run / last_result
    - 在登录态失效时自动续期并回写，尽量减少用户重新授权

两端共用：本地 CLI 调 run_user/run_all，云函数调同一个函数。
"""

from __future__ import annotations

import time
from datetime import datetime

from engine import get_adapter, is_implemented, unimplemented_hint
from store import credentials
from store.base import Account, AccountStore


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _payload(account: Account) -> dict:
    # 适配器需要的字段 = 平台要求的（cookie/token…），这里把顶层字段和凭据合并
    payload = {"platform": account.platform, "label": account.label}
    payload.update(account.credential or {})
    return payload


def _check_one(account: Account, store: AccountStore | None = None,
               user_id: str = "local"):
    """执行单个账号签到，返回 (success, message)。

    流程：
      1) 未实现平台直接短路，明确告知，不发起网络请求
      2) 懒补齐续期材料（从已存 cookie 抽 stoken 等，零网络请求）
      3) 正常签到 —— 成功即返回，正常路径没有任何额外开销
      4) 仅当出现「登录态失效」信号时才自动续期一次，回写后稍等重试
    """
    if not is_implemented(account.platform):
        return False, unimplemented_hint(account.platform)

    notes = credentials.prepare(account, store, user_id)
    payload = _payload(account)

    try:
        res = get_adapter(account.platform, payload).sign_in()
        ok, msg = bool(res.success), res.message
    except Exception as e:  # noqa: BLE001
        return False, f"适配器异常: {e}"

    if ok:
        return True, (f"{msg}；{notes}" if notes else msg)

    if credentials.is_auth_failure(account.platform, msg):
        renewed, note = credentials.renew(account, store, user_id)
        if renewed:
            # 服务端单活轮换：兑换后旧 token 立即作废，稍等再重试
            time.sleep(2)
            try:
                res2 = get_adapter(account.platform, _payload(account)).sign_in()
                return bool(res2.success), f"已自动续期并重试｜{res2.message}"
            except Exception as e:  # noqa: BLE001
                return False, f"已自动续期但重试异常: {e}"
        return False, f"{msg}；{note}"

    return False, msg


def run_user(user_id: str, store: AccountStore) -> list[dict]:
    """给一个用户的所有启用账号签到。"""
    accounts = store.list_accounts(user_id)
    stamp = _now()
    results = []
    for acc in accounts:
        if not acc.enabled:
            continue
        ok, msg = _check_one(acc, store, user_id)
        store.save_result(user_id, acc.id, stamp, msg)
        results.append({
            "id": acc.id,
            "label": acc.label or acc.platform,
            "platform": acc.platform,
            "success": ok,
            "message": msg,
        })
    return results


def run_all(store: AccountStore) -> dict:
    """给所有用户的全部账号签到（定时任务入口）。

    返回：{user_id: [results...]} + 汇总
    """
    by_user = {}
    total_ok = total = 0
    for uid in store.list_users():
        rs = run_user(uid, store)
        if rs:
            by_user[uid] = rs
            total_ok += sum(1 for r in rs if r["success"])
            total += len(rs)
    return {
        "users": len(by_user),
        "total": total,
        "ok": total_ok,
        "detail": by_user,
    }
