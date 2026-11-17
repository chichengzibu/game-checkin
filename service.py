"""签到服务：把「存储层」和「引擎」粘起来。

职责：
    - 给某个用户的全部账号批量签到 / 给所有用户批量签到（定时任务）
    - 结果分类：只对瞬时网络错误退避重试；登录态失效走自动续期；
      验证码与确定性失败绝不重试
    - 按账号×日期幂等：调度器可只补跑当天未完成的账号
    - 连续确定性失败自动停用，避免每天空打无效请求
    - 更新 last_run / last_result / last_ok_date / fail_streak

两端共用：本地 CLI 调 run_user/run_all，云函数调同一个函数。
"""

from __future__ import annotations

import random
import time
from datetime import datetime

from engine import get_adapter, is_implemented, unimplemented_hint
from engine.base import (
    STATUS_OK, STATUS_PARTIAL, STATUS_ALREADY, STATUS_TRANSIENT,
    STATUS_AUTH, STATUS_CAPTCHA, STATUS_FAILED,
)
from store import credentials
from store.base import Account, AccountStore

MAX_TRANSIENT_RETRY = 2          # 瞬时错误最多重试 2 次
RETRY_BASE_SECONDS = 1.0        # 退避基数 1s / 2s，叠加 0~0.6s 抖动
DISABLE_AFTER_FAILS = 2         # 连续 2 次确定性失败才自动停用


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _payload(account: Account) -> dict:
    # 适配器需要的字段 = 平台要求的（cookie/token…），这里把顶层字段和凭据合并
    payload = {"platform": account.platform, "label": account.label}
    payload.update(account.credential or {})
    return payload


def classify(res, platform: str) -> str:
    """判定一次签到结果的类别。

    适配器填了 status 就以它为准；没填（历史适配器 / 离线测试构造的
    CheckinResult）则从 success + message 兜底推断，保证旧行为不变。
    """
    status = (getattr(res, "status", "") or "").strip()
    if status:
        return status
    if not bool(res.success):
        msg = getattr(res, "message", "") or ""
        low = msg.lower()
        # 顺序要紧：登录态失效优先，避免被笼统的「异常」抢走
        if credentials.is_auth_failure(platform, msg):
            return STATUS_AUTH
        if any(s in low for s in ("1034", "人机验证", "验证码")):
            return STATUS_CAPTCHA
        if any(s in low for s in (
                "请求失败", "超时", "timed out", "connection", "连接",
                "执行异常", "适配器异常")):
            return STATUS_TRANSIENT
        return STATUS_FAILED
    return STATUS_OK


def _check_one_ex(account: Account, store: AccountStore | None = None,
                  user_id: str = "local") -> tuple[bool, str, str]:
    """执行单个账号签到，返回 (success, message, status)。

    流程：
      1) 未实现平台直接短路，明确告知，不发起网络请求
      2) 懒补齐续期材料（零网络请求）
      3) 正常签到 —— 成功即返回，正常路径没有任何额外开销
      4) 瞬时错误 → 指数退避 + 抖动，最多 2 次
      5) 登录态失效 → 自动续期并回写，稍等重试一次
      6) 验证码 / 确定性失败 → 绝不重试
    """
    if not is_implemented(account.platform):
        return False, unimplemented_hint(account.platform), STATUS_FAILED

    notes = credentials.prepare(account, store, user_id)
    payload = _payload(account)

    def attempt() -> tuple[bool, str, str]:
        try:
            res = get_adapter(account.platform, payload).sign_in()
            return bool(res.success), res.message, classify(res, account.platform)
        except Exception as e:  # noqa: BLE001
            return False, f"适配器异常: {e}", STATUS_TRANSIENT

    ok, msg, status = attempt()
    if ok:
        return True, (f"{msg}；{notes}" if notes else msg), status

    # 瞬时错误：退避重试，重试后若变成确定性失败就跳出，交给下面的常规处理
    if status == STATUS_TRANSIENT:
        for i in range(MAX_TRANSIENT_RETRY):
            time.sleep(RETRY_BASE_SECONDS * (2 ** i) + random.uniform(0, 0.6))
            ok, msg, status = attempt()
            if ok:
                return True, f"网络重试 {i + 1} 次后成功｜{msg}", status
            if status != STATUS_TRANSIENT:
                break

    if status == STATUS_AUTH:
        renewed, note = credentials.renew(account, store, user_id)
        if renewed:
            # 服务端单活轮换：兑换后旧 token 立即作废，稍等再重试
            time.sleep(2)
            try:
                res2 = get_adapter(account.platform, _payload(account)).sign_in()
                ok2 = bool(res2.success)
                return ok2, f"已自动续期并重试｜{res2.message}", (
                    STATUS_OK if ok2 else classify(res2, account.platform)
                )
            except Exception as e:  # noqa: BLE001
                return False, f"已自动续期但重试异常: {e}", STATUS_TRANSIENT
        return False, f"{msg}；{note}", status

    return False, (f"{msg}；{notes}" if notes else msg), status


def _check_one(account: Account, store: AccountStore | None = None,
               user_id: str = "local") -> tuple[bool, str]:
    """兼容旧调用方：只返回 (success, message)。"""
    ok, msg, _status = _check_one_ex(account, store, user_id)
    return ok, msg


def apply_result(account: Account, ok: bool, status: str,
                 store: AccountStore | None, user_id: str = "local") -> str:
    """把一次结果写回账号状态，返回需要追加到结果文案里的提示。

    - 完整成功（ok / already）→ 记 last_ok_date = 今天，清零连续失败
    - partial（部分游戏失败）→ 不记完成，下次调度会补跑；但不算确定性失败
    - 确定性失败（auth / failed / captcha）→ 累计 fail_streak
    - 连续 2 次确定性失败 → 自动停用，并给出明确的重新启用提示
    - transient → 不累计，避免网络抖动误禁用
    """
    if store is None:
        return ""
    completed = ok and status in (STATUS_OK, STATUS_ALREADY)
    streak = int(getattr(account, "fail_streak", 0) or 0)
    try:
        if completed:
            account.last_ok_date = _today()
            account.fail_streak = 0
        elif status == STATUS_PARTIAL:
            account.fail_streak = 0
        elif status == STATUS_TRANSIENT:
            pass
        else:
            account.fail_streak = streak + 1

        disabled = (
            not completed
            and status in (STATUS_AUTH, STATUS_FAILED)
            and account.fail_streak >= DISABLE_AFTER_FAILS
        )
        if disabled:
            account.enabled = False
        store.update_account(user_id, account)
        if disabled:
            return "（连续多次失败，已自动停用；重新登录或修复后请手动启用）"
    except Exception:  # noqa: BLE001  存储回写失败不影响本次签到结果
        pass
    return ""


def is_pending(account: Account) -> bool:
    """该账号今天是否还需要跑（供调度器定向补跑）。"""
    if not account.enabled or not is_implemented(account.platform):
        return False
    return getattr(account, "last_ok_date", None) != _today()


def run_user(user_id: str, store: AccountStore,
             only_pending: bool = False) -> list[dict]:
    """给一个用户的所有启用账号签到。

    only_pending=True 时跳过「今天已完整成功」的账号（省请求、降风控）。
    手动触发默认 False，保持原有的「点一次就全跑」行为。
    """
    accounts = store.list_accounts(user_id)
    stamp = _now()
    results = []
    for acc in accounts:
        if not acc.enabled:
            continue
        if only_pending and not is_pending(acc):
            continue
        ok, msg, status = _check_one_ex(acc, store, user_id)
        extra = apply_result(acc, ok, status, store, user_id)
        if extra:
            msg += extra
        store.save_result(user_id, acc.id, stamp, msg)
        results.append({
            "id": acc.id,
            "label": acc.label or acc.platform,
            "platform": acc.platform,
            "success": ok,
            "message": msg,
        })
    return results


def run_all(store: AccountStore, only_pending: bool = True) -> dict:
    """给所有用户的全部账号签到（定时任务入口）。

    默认只跑当天未完成的账号：一个账号失败不会拖累整天，开机补跑也只补失败的。
    """
    by_user = {}
    total_ok = total = 0
    for uid in store.list_users():
        rs = run_user(uid, store, only_pending=only_pending)
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
