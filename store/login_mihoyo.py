"""浏览器登录（自动获取凭据）。

设计目标（按用户要求）：
    用户只做一件事 —— 在弹出的登录页里扫码或输账号密码；
    程序自己在后台把凭据拿回来、加密存库、注册账号。用户不碰 Cookie。

已实机打通：米游社扫码登录（见 tools/probe_qr3.py）。
    1. POST createQRLogin        -> ticket + 二维码 url
    2. POST queryQRLoginStatus   轮询 -> Scanned / Confirmed（响应头 Set-Cookie 含凭据）
    3. 从 Set-Cookie 提取 ltuid_v2 / ltoken_v2 / cookie_token_v2 等，拼成 Cookie 串

其他平台现实约束（不隐瞒）：
    库街区  网页不支持登录，只有手机号+短信验证码；需用户提供手机号并接收验证码。
    燕云    绑定微信授权，网页无法独立登录；只能扫码授权微信。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

APP_ID = "bll8iq97cem8"
PASSPORT = "https://passport-api.miyoushe.com"
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
    "stuid", "stoken", "mid",
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

            # stoken 是长期有效的续期凭据，来自登录响应体（不是 Set-Cookie）。
            # 现网见过三种形状，全部兼容：
            #   data.tokens = [{"name":"stoken","token":"v2_..."}] / [{"token":"..."}]
            #   data.token  = {"token": "..."}（短信验证码登录）
            #   Set-Cookie 里直接带 stoken=...
            renewal: dict = {}
            tokens = data.get("tokens") or []
            if isinstance(tokens, dict):
                tokens = [tokens]
            for t in tokens:
                if not isinstance(t, dict) or not t.get("token"):
                    continue
                name = (t.get("name") or "").lower()
                if not name or name == "stoken":
                    renewal.setdefault("stoken", str(t["token"]))
                elif name in COOKIE_KEYS:
                    cookies.setdefault(name, str(t["token"]))
            single = data.get("token") or {}
            if isinstance(single, dict) and single.get("token"):
                renewal.setdefault("stoken", str(single["token"]))
            if not renewal.get("stoken") and cookies.get("stoken"):
                renewal["stoken"] = cookies["stoken"]

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
