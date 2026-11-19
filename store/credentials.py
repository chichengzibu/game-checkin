"""凭证生命周期：懒补齐 / 健康检查 / 自动续期 / 回写。

目标：让「登录一次」尽可能长期有效，减少用户反复扫码授权。

已核对的事实（不要凭印象改）：
- 米游社 cookie_token 会过期，但 stoken 长期有效，可用 stoken 兑换新的
  cookie_token，从而免去重新扫码。
  * 主接口 GET https://passport-api.mihoyo.com/account/auth/api/getCookieAccountInfoBySToken
    params={"stoken": ...}；cookie 需带 mid / stoken；DS 用 passport x4 salt。
  * 回退 GET https://api-takumi.mihoyo.com/auth/api/getCookieAccountInfoBySToken
    cookie: stoken=...;stuid=...（stoken 以 v2_ 开头时再加 mid=...）。
  * ⚠️ 每次兑换都会让旧 cookie_token 作废（服务端单活轮换）。所以只在
    明确判定失效时兑换、按账号串行、成功后立即回写加密库，且重试前稍等。
- stoken 来自登录响应（data.tokens[0].token / data.token.token），不是普通
  网页 Cookie。登录落库时必须结构化保存，否则续期无从谈起。
- 库街区官方没有公开的 token 刷新接口（对照 Kuro-autosignin 等实现：只有
  「登录已过期 → 自动禁用」）。因此这里只做失效识别与精确提示，
  **绝不编造 refresh 端点**。减少重复授权靠保存网页登录的 source=h5 +
  完整 token，以及失效时一步到位的重新登录指引。

策略：正常签到路径零额外网络请求；只在签到返回「登录态失效」信号时，
二次健康检查确认后兑换一次、回写、稍等、重试。
"""

from __future__ import annotations

import hashlib
import random
import threading
import time
import uuid
from datetime import datetime

from engine.base import get_session
from engine.mihoyo import APP_VERSION, GAMES, ROLES_URL, gen_ds, normalize_cookie

PASSPORT_STOKEN_URL = (
    "https://passport-api.mihoyo.com/account/auth/api/getCookieAccountInfoBySToken"
)
TAKUMI_STOKEN_URL = (
    "https://api-takumi.mihoyo.com/auth/api/getCookieAccountInfoBySToken"
)
PASSPORT_X4_SALT = "xV8v4Qu54lUKrEYFZkJhB8cuOh9Asafs"
DEVICE_FP = "38d814469b1e4"

# 按账号串行化，避免并发签到重复兑换（重复兑换会互相把对方的新 token 作废）
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()

_MI_FAIL_SIGNALS = (
    "cookie 失效", "未取到游戏角色", "请登录", "-100", "登录已过期", "登录态失效",
)
_KURO_FAIL_SIGNALS = (
    "token 无效", "已过期", "请重新登录", "登录已过期", "code=220", "令牌",
)
_SKLAND_FAIL_SIGNALS = (
    "用户未登录", "登录已过期", "已过期", "登录失效", "token 无效", "token无效",
    "凭证无效", "授权失败", "授权码", "未返回授权码", "登出",
)


def _lock_for(account_id: str) -> threading.Lock:
    with _LOCKS_GUARD:
        if account_id not in _LOCKS:
            _LOCKS[account_id] = threading.Lock()
        return _LOCKS[account_id]


# ---------------- Cookie 串工具 ----------------

def parse_cookie(raw: str) -> dict:
    """'a=1; b=2' -> {'a':'1','b':'2'}，保留首次出现顺序。"""
    out: dict[str, str] = {}
    for part in (raw or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k:
            out[k] = v
    return out


def join_cookie(d: dict) -> str:
    return "; ".join(f"{k}={v}" for k, v in d.items() if v not in (None, ""))


def enrich_mihoyo(cred: dict) -> dict:
    """把续期所需字段从 cookie 串补齐成结构化字段（幂等）。

    老账号只要当初粘贴的 Cookie 里带 stoken，就能立刻获得自动续期能力，
    无需重新登录 —— 这是「尽量减少重新授权」最关键的一步。
    """
    cred = dict(cred or {})
    d = parse_cookie(cred.get("cookie", ""))

    def pick(*names: str) -> str:
        for n in names:
            v = cred.get(n) or d.get(n)
            if v:
                return str(v)
        return ""

    stoken = pick("stoken")
    stuid = pick("stuid", "account_id_v2", "account_id", "ltuid_v2", "ltuid")
    mid = pick("mid", "account_mid_v2", "ltmid_v2", "ltmid")
    account_id = pick("account_id", "account_id_v2", "ltuid_v2", "ltuid") or stuid

    if stoken:
        cred["stoken"] = stoken
    if stuid:
        cred["stuid"] = stuid
    if mid:
        cred["mid"] = mid
    if account_id:
        cred["account_id"] = account_id
    if not cred.get("device_id"):
        cred["device_id"] = str(uuid.uuid4())
    cred["renewable"] = bool(stoken)
    return cred


def apply_new_cookie_token(cookie: str, token: str) -> str:
    """把 cookie 串里 cookie_token / cookie_token_v2 同时换成新值。

    两者都换：normalize_cookie() 只会在 V1 缺失时用 V2 的值补 V1，
    若只换其中一个，残留的旧值仍可能被 luna 系列接口读到。
    """
    d = parse_cookie(cookie)
    had = "cookie_token" in d or "cookie_token_v2" in d
    if "cookie_token" in d:
        d["cookie_token"] = token
    if "cookie_token_v2" in d:
        d["cookie_token_v2"] = token
    if not had:
        d["cookie_token"] = token
    return join_cookie(d)


def public_status(account) -> dict:
    """给 UI 看的续期能力，绝不包含任何凭据明文。"""
    platform = getattr(account, "platform", "")
    if platform == "mihoyo":
        c = enrich_mihoyo(account.credential or {})
        if c.get("stoken"):
            return {"auto_renew": True,
                    "note": "已启用自动续期（stoken 有效时无需重新登录）"}
        return {"auto_renew": False,
                "note": "未保存 stoken：请点「登录获取」扫码重登一次（约 2 分钟），"
                        "程序会保存 stoken，此后 cookie 过期也能自动续期"}
    if platform == "kuro":
        return {"auto_renew": False,
                "note": "库街区无官方刷新接口；token 失效时需重新登录一次"}
    if platform == "yanyun":
        return {"auto_renew": False, "note": "签到未实现"}
    if platform == "skland":
        return {"auto_renew": False,
                "note": "森空岛无 token 刷新接口；失效时需登录官网重取 data.content"}
    return {"auto_renew": False, "note": "该平台不支持自动续期"}


# ---------------- 健康检查与兑换 ----------------

def mihoyo_cookie_valid(cred: dict, timeout: int = 15):
    """按「签到接口」的口径检查登录态，而不是只看角色接口。

    True=有效 / False=失效 / None=网络或解析异常（无法判定）。

    实测坑：getUserGameRolesByCookie 对 V2 cookie / 半过期 cookie 仍可能返回
    retcode=0，但 luna/info、luna/sign 会返回 -100。旧版只查角色接口，于是
    手动点续期时误判「登录态正常」，真正需要续期时被挡住。
    这里先拿角色，再用其中一个已配置游戏的 luna/info 复核；两者都通过才算有效。
    """
    cookie = normalize_cookie(cred.get("cookie", ""))
    base_headers = {
        "Cookie": cookie,
        "DS": gen_ds(),
        "x-rpc-app_version": APP_VERSION,
        "x-rpc-client_type": "5",
        "x-rpc-device_id": cred.get("device_id") or "checkin-engine-device",
        "x-rpc-signgame": "hk4e",
        "Origin": "https://act.mihoyo.com",
        "Referer": "https://act.mihoyo.com/",
    }
    try:
        r = get_session().get(ROLES_URL, headers=base_headers, timeout=timeout)
        d = r.json()
    except Exception:  # noqa: BLE001
        return None
    code = d.get("retcode")
    if code == -100:
        return False
    if code != 0:
        return None
    roles = ((d.get("data") or {}).get("list") or [])
    if not roles:
        return True   # 账号没角色不是登录态问题

    for role in roles:
        cfg = GAMES.get(role.get("game_biz", ""))
        if not cfg:
            continue
        headers = dict(base_headers)
        headers["x-rpc-signgame"] = cfg["signgame"]
        headers["DS"] = gen_ds()
        try:
            rr = get_session().get(
                cfg["api"] + cfg["path"] + "/info",
                params={
                    "lang": "zh-cn", "act_id": cfg["act_id"],
                    "region": role.get("region"), "uid": role.get("game_uid"),
                },
                headers=headers, timeout=timeout,
            )
            dd = rr.json()
        except Exception:  # noqa: BLE001
            return None
        rc = dd.get("retcode")
        if rc == -100:
            return False
        if rc in (0, -5003):   # 0=未签 / -5003=今日已签，都说明登录态有效
            return True
        return None
    return True   # 有角色但都不在签到表里：角色接口已通过，无法再复核


def _ds_x4(query: str) -> str:
    t = str(int(time.time()))
    r = str(random.randint(100000, 200000))
    c = hashlib.md5(
        f"salt={PASSPORT_X4_SALT}&t={t}&r={r}&b=&q={query}".encode("utf-8")
    ).hexdigest()
    return f"{t},{r},{c}"


def exchange_cookie_token(cred: dict, timeout: int = 15) -> tuple[str | None, str]:
    """用 stoken 换新 cookie_token。返回 (新 token 或 None, 说明)，不改入参。"""
    c = enrich_mihoyo(cred)
    stoken = c.get("stoken", "")
    if not stoken:
        return None, "缺少 stoken，无法自动续期"

    stuid, mid = c.get("stuid", ""), c.get("mid", "")
    device_id = c.get("device_id") or str(uuid.uuid4())
    query = f"stoken={stoken}"
    headers_v2 = {
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) miHoYoBBS/{APP_VERSION}",
        "x-rpc-app_version": APP_VERSION,
        "x-rpc-client_type": "2",
        "x-requested-with": "com.mihoyo.hyperion",
        "Referer": "https://webstatic.mihoyo.com",
        "x-rpc-device_id": device_id,
        "x-rpc-device_fp": DEVICE_FP,
        "cookie": f"mid={mid};stoken={stoken}",
        "ds": _ds_x4(query),
        "x-rpc-aigis": "",
    }

    try:
        r = get_session().get(
            PASSPORT_STOKEN_URL, params={"stoken": stoken},
            headers=headers_v2, timeout=timeout,
        )
        d = r.json()
        tok = (d.get("data") or {}).get("cookie_token")
        if d.get("retcode") == 0 and tok:
            return str(tok), "passport 兑换成功"
        v2_note = f"passport retcode={d.get('retcode')} {d.get('message') or ''}"
    except Exception as e:  # noqa: BLE001
        v2_note = f"passport 异常 {e}"

    # 回退旧接口（对已建立会话的 stoken 通常仍有效）
    cookie = f"stoken={stoken};stuid={stuid}"
    if stoken.startswith("v2_") and mid:
        cookie += f";mid={mid}"
    try:
        r = get_session().get(
            TAKUMI_STOKEN_URL,
            headers={"Accept": "application/json", "Cookie": cookie},
            timeout=timeout,
        )
        d = r.json()
        tok = (d.get("data") or {}).get("cookie_token")
        if d.get("retcode") == 0 and tok:
            return str(tok), f"takumi 兑换成功（{v2_note}）"
        return None, (
            f"兑换失败：{v2_note} / takumi retcode={d.get('retcode')} "
            f"{d.get('message') or ''}"
        )
    except Exception as e:  # noqa: BLE001
        return None, f"兑换失败：{v2_note} / takumi 异常 {e}"


# ---------------- 供 service.py 调用的三个入口 ----------------

def prepare(account, store=None, user_id: str = "local") -> str:
    """签到前懒补齐续期材料（不发网络请求），有变化就回写加密库。"""
    if getattr(account, "platform", "") != "mihoyo":
        return ""
    old = dict(account.credential or {})
    new = enrich_mihoyo(old)
    if new == old:
        return ""
    account.credential = new
    if store is not None:
        try:
            store.update_account(user_id, account)
        except Exception:  # noqa: BLE001
            return ""
    if new.get("stoken"):
        return "已补齐 stoken，自动续期已启用（无需重新登录）"
    return "已检查续期材料"


def is_auth_failure(platform: str, message: str) -> bool:
    m = (message or "").lower()
    if platform == "mihoyo":
        return any(s in m for s in _MI_FAIL_SIGNALS)
    if platform == "kuro":
        return any(s in m for s in _KURO_FAIL_SIGNALS)
    if platform == "skland":
        return any(s in m for s in _SKLAND_FAIL_SIGNALS)
    return False


def renew(account, store=None, user_id: str = "local",
          force: bool = False) -> tuple[bool, str]:
    """确认凭证失效后调用：自动续期并回写。返回 (是否成功, 说明)。

    force=True 用于「签到接口已经明确判定登录态失效」的路径：此时不再做
    二次健康检查。实测 bind/luna-info 的检查口径可能比 luna/sign 宽松，
    用它当门闸会把真正需要续期的账号挡在门外。
    手动点续期（force=False）仍先检查，避免把还能用的 cookie_token 换掉。
    """
    platform = getattr(account, "platform", "")

    if platform == "kuro":
        return False, (
            "库街区官方没有 token 刷新接口，无法自动续期；请点「登录获取」"
            "用手机号+验证码重新登录一次，程序会自动保存新 token（source=h5）"
        )
    if platform == "skland":
        return False, (
            "森空岛 token 失效后需重新获取：登录 https://www.skland.com/ 后访问 "
            "https://web-api.skland.com/account/info/hg ，复制 data.content 的"
            "完整字符串，粘贴到账号凭据里保存即可（等同重新登录一次）"
        )
    if platform != "mihoyo":
        return False, "该平台不支持自动续期"

    with _lock_for(getattr(account, "id", "default") or "default"):
        cred = enrich_mihoyo(dict(account.credential or {}))
        if not cred.get("stoken"):
            return False, (
                "缺少 stoken，无法自动续期（这是 cookie 隔几天就失效、需要重登的根因）；"
                "请点「登录获取」用米游社账号扫码登录一次，程序会保存 stoken，"
                "以后 cookie 过期自动兑换，不用再反复扫码"
            )

        # 手动续期才做二次确认；签到已判 AUTH 时直接兑换
        if not force:
            valid = mihoyo_cookie_valid(cred)
            if valid is True:
                return False, "登录态检查正常，无需续期（未消耗 stoken）"

        token, note = exchange_cookie_token(cred)
        if not token:
            return False, f"自动续期失败（{note}）；如持续失败请重新登录一次"

        cred["cookie"] = apply_new_cookie_token(cred.get("cookie", ""), token)
        cred["last_renew"] = datetime.now().isoformat(timespec="seconds")
        account.credential = cred
        if store is not None:
            try:
                store.update_account(user_id, account)
            except Exception as e:  # noqa: BLE001
                return False, f"续期成功但回写失败: {e}（请检查账号库是否可写）"
        return True, f"已自动续期（{note}）"
