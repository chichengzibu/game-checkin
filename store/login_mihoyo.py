"""浏览器登录（自动获取凭据）。

设计目标（按用户要求）：
    用户只做一件事 —— 在弹出的登录页里扫码或输账号密码；
    程序自己在后台把凭据拿回来、加密存库、注册账号。用户不碰 Cookie。

米游社扫码登录有两条通道：
    - 首选 MihoyoSDKQRLogin：米游社 App passport 通道（bbs_cn），
      queryQRLoginStatus 的 data.tokens 直接给 stoken，再换 ltoken/cookie_token。
    - 兼容 MihoyoQRLogin：web 通道（现网 tokens 为空、无 stoken），仅作降级。
旧版从 Set-Cookie 提取 cookie 串的做法已不足以启用自动续期。

其他平台现实约束（不隐瞒）：
    库街区  网页不支持登录，只有手机号+短信验证码；需用户提供手机号并接收验证码。
    燕云    绑定微信授权，网页无法独立登录；只能扫码授权微信。
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import string
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime

APP_ID = "bll8iq97cem8"
PASSPORT = "https://passport-api.miyoushe.com"
PASSPORT_API = "https://passport-api.mihoyo.com"

# 能稳定拿到 stoken 的 SDK 扫码链路（web 扫码接口现网已不再下发 stoken）
SDK_BASE = "https://hk4e-sdk.mihoyo.com/hk4e_cn/combo/panda/qrcode"
SDK_APP_ID = "7"
TOKEN_BY_GAME_TOKEN = (
    "https://api-takumi.mihoyo.com/account/ma-cn-session/app/getTokenByGameToken"
)
GET_LTOKEN = "https://passport-api.mihoyo.com/account/auth/api/getLTokenBySToken"
DS_SALT_X4 = "xV8v4Qu54lUKrEYFZkJhB8cuOh9Asafs"
DS_SALT_K2 = "OvOIsZRXrUbXoUlpQuhEx4tgAwNVUMmp"
BBS_VERSION = "2.102.1"
BBS_UA = f"Mozilla/5.0 (Linux; Android 12) Mobile miHoYoBBS/{BBS_VERSION}"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# 二维码状态
STATUS_CREATED = "Created"
STATUS_SCANNED = "Scanned"
STATUS_CONFIRMED = "Confirmed"

# 要收集的 cookie 名（v2 优先，兼容旧版）
COOKIE_KEYS = [
    "ltuid_v2", "ltoken_v2", "ltmid_v2", "cookie_token_v2", "account_id_v2",
    "ltuid", "ltoken", "ltmid", "cookie_token", "account_id",
    "stuid", "stoken", "stoken_v2", "mid",
]


class LoginError(Exception):
    pass


def _post(path: str, payload: dict, device_id: str):
    """返回 (retcode, data, set_cookie_list)。"""
    url = PASSPORT + path
    body = json.dumps(payload, separators=(",", ":"))
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-rpc-app_id": APP_ID,
        "x-rpc-device_id": device_id,
        "x-rpc-client_type": "4",
        "Origin": "https://user.mihoyo.com",
        "Referer": "https://user.mihoyo.com/",
    }
    req = urllib.request.Request(url, data=body.encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            set_cookies = r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        set_cookies = e.headers.get_all("Set-Cookie") or []

    try:
        d = json.loads(raw)
    except Exception:
        raise LoginError(f"登录接口返回异常: {raw[:200]}")
    return d.get("retcode"), d, set_cookies


def parse_cookies(set_cookie_list: list[str]) -> dict:
    """从 Set-Cookie 头里抽出需要的 cookie 键值。"""
    found = {}
    for line in set_cookie_list:
        # Set-Cookie: k=v; Path=/; Domain=...; ...
        first = line.split(";", 1)[0]
        if "=" not in first:
            continue
        k, v = first.split("=", 1)
        k, v = k.strip(), v.strip()
        if k in COOKIE_KEYS and v:
            found[k] = v
    return found


def cookie_string(cookies: dict) -> str:
    """拼成引擎可用的 Cookie 串。"""
    return "; ".join(f"{k}={v}" for k, v in cookies.items() if v)


def _shape(value) -> dict:
    """只描述结构，不返回任何凭据值 —— 用于脱敏诊断。"""
    if isinstance(value, dict):
        return {"type": "dict", "keys": sorted(str(k) for k in value)}
    if isinstance(value, list):
        items = []
        for it in value[:10]:
            if isinstance(it, dict):
                name = it.get("name") or it.get("type") or it.get("tokenType") or ""
                items.append({"dict_keys": sorted(str(k) for k in it),
                              "name": str(name)[:30]})
            elif isinstance(it, str):
                items.append({"str_len": len(it)})
            else:
                items.append({"type": type(it).__name__})
        return {"type": "list", "len": len(value), "items": items}
    if isinstance(value, str):
        return {"type": "str", "len": len(value)}
    return {"type": type(value).__name__}


def _record_diag(data: dict, set_cookie_list: list[str], got_stoken: bool) -> None:
    """可选诊断：只写响应结构，绝不写 token / cookie 值。

    开启方式：CHECKIN_LOGIN_DIAG=1 启动服务。文件 logs/login_diag.jsonl。
    """
    if os.environ.get("CHECKIN_LOGIN_DIAG") != "1":
        return
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "logs", "login_diag.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        names = []
        for line in set_cookie_list:
            first = line.split(";", 1)[0]
            if "=" in first:
                names.append(first.split("=", 1)[0].strip())
        rec = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "data_keys": sorted(str(k) for k in data) if isinstance(data, dict) else [],
            "tokens": _shape(data.get("tokens")),
            "token": _shape(data.get("token")),
            "set_cookie_names": names,
            "got_stoken": bool(got_stoken),
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001  诊断失败绝不影响登录
        pass


def _pick_stoken(data: dict, cookies: dict) -> str:
    """兼容多种现网响应形状，提取长期续期凭据 stoken。"""
    candidates = []

    def add(v):
        if v and isinstance(v, (str, int)):
            s = str(v).strip()
            if s:
                candidates.append(s)

    if isinstance(data, dict):
        for key in ("stoken", "stoken_v2"):
            add(data.get(key))
        single = data.get("token")
        if isinstance(single, str):
            add(single)                      # 新版可能直接是字符串
        elif isinstance(single, dict):
            sname = str(single.get("name") or single.get("type") or "").lower()
            if not sname or "stoken" in sname:
                add(single.get("token") or single.get("stoken"))
        tokens = data.get("tokens")
        if isinstance(tokens, dict):
            tokens = [tokens]
        if isinstance(tokens, list):
            for item in tokens:
                if isinstance(item, str):
                    add(item)
                elif isinstance(item, dict):
                    name = str(item.get("name") or item.get("type")
                               or item.get("tokenType") or "").lower()
                    val = item.get("token") or item.get("value")
                    # 无名 token 视为 stoken；ltoken / cookie_token 不能被误当成 stoken
                    if val and (not name or "stoken" in name):
                        add(val)
    for key in ("stoken", "stoken_v2"):
        add(cookies.get(key))
    return candidates[0] if candidates else ""


class MihoyoQRLogin:
    """米游社扫码登录会话。"""

    def __init__(self):
        self.device_id = str(uuid.uuid4())

    def create(self) -> dict:
        """创建二维码，返回 {ticket, url, expire_in}。"""
        rc, d, _ = _post("/account/ma-cn-passport/web/createQRLogin",
                         {"app_id": APP_ID}, self.device_id)
        if rc != 0 or not (d.get("data") or {}).get("ticket"):
            raise LoginError(d.get("message") or "创建二维码失败")
        data = d["data"]
        return {"ticket": data["ticket"], "url": data["url"]}

    def poll(self, ticket: str) -> dict:
        """查询一次状态。返回 {status, cookies?, error?}。"""
        rc, d, set_cookies = _post(
            "/account/ma-cn-passport/web/queryQRLoginStatus",
            {"ticket": ticket}, self.device_id,
        )
        # 过期 / 取消
        if rc == -3501:
            return {"status": "Expired", "error": d.get("message")}
        if rc == -3505:
            return {"status": "Cancelled", "error": d.get("message")}
        if rc != 0:
            return {"status": "Error", "error": d.get("message") or f"retcode={rc}"}

        data = d.get("data") or {}
        status = data.get("status")

        if status == STATUS_CONFIRMED:
            cookies = parse_cookies(set_cookies)
            user = data.get("user_info") or {}

            # stoken 是长期有效的续期凭据，来自登录响应体或 Set-Cookie。
            # 现网形状不止一种：tokens 列表 / token 对象 / token 字符串 /
            # data.stoken / stoken_v2 cookie，全部兼容，避免「登录成功却没续期」。
            renewal: dict = {}
            tokens = data.get("tokens") or []
            if isinstance(tokens, dict):
                tokens = [tokens]
            for t in tokens:
                if not isinstance(t, dict) or not t.get("token"):
                    continue
                name = str(t.get("name") or "").lower()
                if name and name not in ("stoken", "stoken_v2") and name in COOKIE_KEYS:
                    cookies.setdefault(name, str(t["token"]))
            stoken_val = _pick_stoken(data, cookies)
            if stoken_val:
                renewal["stoken"] = stoken_val
            _record_diag(data, set_cookies, bool(stoken_val))

            aid = user.get("aid") or user.get("uid") or ""
            mid = user.get("mid") or ""
            if aid:
                renewal["stuid"] = str(aid)
                cookies.setdefault("ltuid_v2", str(aid))
                cookies.setdefault("account_id_v2", str(aid))
            if mid:
                renewal["mid"] = str(mid)
                cookies.setdefault("ltmid_v2", str(mid))
                cookies.setdefault("account_mid_v2", str(mid))
            # 双保险：即使上层只保存 cookie 串，续期模块也能从串里解析出 stoken
            if renewal.get("stoken"):
                cookies.setdefault("stoken", renewal["stoken"])

            if not cookies:
                return {"status": status,
                        "error": "登录已确认，但未取到 cookie（接口可能变更）"}
            return {
                "status": status,
                "cookies": cookies,
                "cookie": cookie_string(cookies),
                "renewal": renewal,          # 结构化续期材料，落库时合并保存
                "uid": cookies.get("ltuid_v2") or cookies.get("ltuid")
                       or cookies.get("account_id") or aid,
                "nickname": user.get("nickname") or "",
            }

        return {"status": status}


def _sdk_post(url: str, body, headers: dict | None = None):
    """统一 POST；body 可以是字符串（DS 已按同一字符串签好）。"""
    data = (body if isinstance(body, str)
            else json.dumps(body, separators=(",", ":"))).encode("utf-8")
    hs = {"Content-Type": "application/json", "Accept": "application/json",
          "User-Agent": BBS_UA}
    hs.update(headers or {})
    req = urllib.request.Request(url, data=data, method="POST", headers=hs)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            raise LoginError(f"接口 HTTP {e.code}: {raw[:160]}")
    except Exception as e:  # noqa: BLE001
        raise LoginError(f"请求失败: {e}")


APP_QR_BASE = "https://passport-api.mihoyo.com/account/ma-cn-passport/app"
APP_QR_VERSION = "2.90.1"


def _ds_x4_full(query: str = "", body: str = "") -> str:
    """X4 DS：query/body 都要参与签名，否则 passport 接口返回 -403。"""
    t = str(int(time.time()))
    r = str(random.randint(100000, 200000))
    c = hashlib.md5(
        f"salt={DS_SALT_X4}&t={t}&r={r}&b={body}&q={query}".encode("utf-8")
    ).hexdigest()
    return f"{t},{r},{c}"


def _app_headers(device_id: str, device_fp: str, body: str = "") -> dict:
    """米游社 App 扫码头：x-rpc-game_biz=bbs_cn 才会出米游社登录二维码。"""
    return {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": f"Mozilla/5.0 miHoYoBBS/{APP_QR_VERSION} Capture/2.2.0",
        "x-rpc-client_type": "3",
        "x-rpc-app_version": APP_QR_VERSION,
        "x-rpc-app_id": APP_ID,
        "x-rpc-sdk_version": APP_QR_VERSION,
        "x-rpc-game_biz": "bbs_cn",
        "x-rpc-device_id": device_id,
        "x-rpc-device_fp": device_fp,
        "x-rpc-device_model": "Mi 14",
        "x-rpc-device_name": "Mihoyo Capture",
        "x-rpc-account_version": APP_QR_VERSION,
        "DS": _ds_x4_full(body=body),
    }


def _app_get(url: str, headers: dict | None = None):
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            raise LoginError(f"HTTP {e.code}: {raw[:160]}")
    except Exception as e:  # noqa: BLE001
        raise LoginError(f"请求失败: {e}")


class MihoyoSDKQRLogin:
    """米游社 App 扫码登录（能稳定拿到 stoken）。

    之前用的 hk4e SDK 链路 app_id=7 实际落在「崩坏学园2」，
    而 web 扫码接口 tokens 为空、不下发 stoken。现改为米游社 App 的
    passport app 通道（x-rpc-game_biz=bbs_cn）：
      createQRLogin -> queryQRLoginStatus -> data.tokens[0].token(stoken)
      -> getLTokenBySToken / getCookieAccountInfoBySToken
    poll 的返回结构与 MihoyoQRLogin 一致，Web 层无需分叉。
    """

    def __init__(self):
        self.device_id = str(uuid.uuid4()).upper()
        self.device_fp = "".join(random.choices("0123456789abcdef", k=13))

    def create(self) -> dict:
        body = "{}"
        d = _sdk_post(f"{APP_QR_BASE}/createQRLogin", body,
                      _app_headers(self.device_id, self.device_fp, body))
        if d.get("retcode") != 0:
            raise LoginError(d.get("message") or "生成米游社二维码失败")
        data = d.get("data") or {}
        url, ticket = data.get("url"), data.get("ticket")
        if not url or not ticket:
            raise LoginError("二维码响应缺少 url/ticket")
        return {"url": url, "ticket": ticket}

    def poll(self, ticket: str) -> dict:
        body = json.dumps({"ticket": ticket}, separators=(",", ":"))
        d = _sdk_post(f"{APP_QR_BASE}/queryQRLoginStatus", body,
                      _app_headers(self.device_id, self.device_fp, body))
        if d.get("retcode") != 0:
            return {"status": "Error", "error": d.get("message") or "查询二维码失败"}
        data = d.get("data") or {}
        status = data.get("status") or "Init"
        if status in ("Init", ""):
            return {"status": "Created"}
        if status == "Scanned":
            return {"status": "Scanned"}
        if status in ("Canceled", "Cancelled", "Expired"):
            return {"status": "Expired" if "Expir" in status else "Cancelled"}
        if status != "Confirmed":
            return {"status": str(status)}

        user = data.get("user_info") or {}
        mid = str(user.get("mid") or data.get("mid") or "")
        stuid = str(user.get("aid") or data.get("aid") or "")
        stoken = _pick_stoken(data, {})
        if not stoken:
            _record_diag(data, [], False)
            return {"status": "Error",
                    "error": "已确认登录但响应里没有 stoken（请把诊断反馈给开发者）"}
        _record_diag(data, [], True)

        qp = {"stoken": stoken}
        if mid:
            qp["mid"] = mid
        base_query = urllib.parse.urlencode(qp)
        hdr = {
            "User-Agent": BBS_UA,
            "x-rpc-app_version": APP_QR_VERSION,
            "x-rpc-client_type": "2",
            "x-rpc-device_id": self.device_id,
            "x-rpc-device_fp": self.device_fp,
            "DS": _ds_x4_full(query=base_query),
        }
        ltoken = ""
        try:
            dd = _app_get(f"{PASSPORT_API}/account/auth/api/getLTokenBySToken?{base_query}", hdr)
            if dd.get("retcode") == 0:
                ltoken = str((dd.get("data") or {}).get("ltoken") or "")
        except Exception:  # noqa: BLE001  换不到 ltoken 不阻断登录
            pass
        from store.credentials import exchange_cookie_token
        ctoken, _note = exchange_cookie_token({
            "stoken": stoken, "stuid": stuid, "mid": mid,
            "device_id": self.device_id,
        })

        cookies = {
            "stoken": stoken, "stuid": stuid, "mid": mid,
            "ltuid": stuid, "ltuid_v2": stuid,
            "account_id": stuid, "account_id_v2": stuid,
            "ltmid": mid, "ltmid_v2": mid, "account_mid_v2": mid,
        }
        if ltoken:
            cookies["ltoken"] = ltoken
            cookies["ltoken_v2"] = ltoken
        if ctoken:
            cookies["cookie_token"] = ctoken
            cookies["cookie_token_v2"] = ctoken
        return {
            "status": "Confirmed",
            "cookies": cookies,
            "cookie": cookie_string(cookies),
            "renewal": {"stoken": stoken, "stuid": stuid, "mid": mid},
            "uid": stuid,
            "nickname": user.get("nickname") or "",
        }
