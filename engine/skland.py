"""鹰角森空岛（Skland）每日签到适配器 —— 明日方舟 + 明日方舟：终末地。

✅ 2026-11-17 新增。协议参考成熟开源实现并按本项目零依赖风格重写：
   kafuneri/Skland-Sign-In、AEtherside/skland-daily-attendance、
   yu-echo/skland-daily-attendance（签名/设备指纹/端点均交叉核对）。

账号配置字段：
    token : 森空岛 Web 登录凭证。登录 https://www.skland.com/ 后访问
            https://web-api.skland.com/account/info/hg ，复制返回 JSON 里
            data.content 的完整长字符串（等同于账号凭证，勿外泄）。
    did   : 可选。设备指纹，留空则每次签到自动生成（数美风控）。

流程：
    token --grant--> code --generate_cred_by_code--> {token, cred}
         --binding--> 绑定角色列表
         对每个明日方舟/终末地角色分别签到，逐项分类后 summarize。

所有请求签名 = md5(hex(hmac_sha256(cred_token, path+body+ts+header_ca)))，
设备指纹与加密原语在 engine/skland_crypto.py（纯标准库，已过标准向量自检 + 在线探活）。
"""

import json
import time
from urllib.parse import urlparse

from .base import (
    CheckinAdapter, CheckinResult, summarize,
    STATUS_OK, STATUS_ALREADY, STATUS_TRANSIENT, STATUS_AUTH, STATUS_FAILED,
)
from . import skland_crypto as sc

GRANT_URL = "https://as.hypergryph.com/user/oauth2/v2/grant"
CRED_URL = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code"
BINDING_URL = "https://zonai.skland.com/api/v1/game/player/binding"
ARK_ATTEND_URL = "https://zonai.skland.com/api/v1/game/attendance"
END_ATTEND_URL = "https://zonai.skland.com/web/v1/game/endfield/attendance"

APP_CODE = "4ca99fa6b56cc2ba"
SUPPORTED_APPS = ("arknights", "endfield")

USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
    "Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1"
)
LOGIN_USER_AGENT = (
    "Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0"
)

# 已签到文案特征（各家实现关键词合并）
_ALREADY_WORDS = ("已签到", "已签", "请勿重复", "重复签到", "签到过", "今日已", "already")
_AUTH_WORDS = ("登录已过期", "用户未登录", "未登录", "登录失效", "token无效", "token 无效",
               "凭证无效", "授权失败", "登录态")
_TRANSIENT_WORDS = ("timeout", "timed out", "超时", "请求失败", "连接失败", "connection",
                    "网络异常", "503", "502", "504")


def _contains(text: str, words) -> bool:
    low = (text or "").lower()
    return any(w.lower() in low for w in words)


class SkylandAdapter(CheckinAdapter):
    name = "skland"
    required_fields = ("token",)

    def __init__(self, account: dict):
        super().__init__(account)
        self._did = (self.account.get("did") or "").strip() or None

    # ---------- HTTP 抽象（便于离线 mock） ----------

    @staticmethod
    def _encode_body(body) -> str:
        """统一请求体序列化。

        签名的 body 与真正发出的 body 必须逐字节一致，所以只允许这一处编码：
        dict -> 紧凑 JSON（与官方 httpx json= 的输出一致）；str 原样；None -> 空。
        """
        if isinstance(body, dict):
            return json.dumps(body, separators=(",", ":"))
        if isinstance(body, str):
            return body
        return ""

    def _json(self, method: str, url: str, *, headers=None, body=None,
              timeout: int = 20) -> dict:
        """调用基类的 urllib session，统一返回 dict，网络异常向上抛由分类处理。"""
        h = dict(headers or {})
        payload = None
        if body is not None:
            payload = self._encode_body(body)
            if isinstance(body, dict):
                h.setdefault("Content-Type", "application/json")
        if method == "GET":
            r = self.session.get(url, headers=h, timeout=timeout)
        else:
            r = self.session.post(url, data=payload, headers=h, timeout=timeout)
        return r.json()

    def _fp_post(self, url, payload, headers, timeout):
        """给设备指纹生成器用的 HTTP 适配器。"""
        import json
        r = self.session.post(url, data=json.dumps(payload, separators=(",", ":")),
                              headers=headers, timeout=timeout)
        return r.json()

    def _device_id(self) -> str:
        if not self._did:
            self._did = sc.generate_device_id(self._fp_post)
        return self._did

    def _login_headers(self, did: str) -> dict:
        return {
            "User-Agent": LOGIN_USER_AGENT,
            "Accept-Encoding": "gzip",
            "Connection": "close",
            "dId": did,
        }

    def _signed_headers(self, method: str, url: str, cred_token: str,
                        cred: str, did: str, body_or_query: str) -> dict:
        parsed = urlparse(url)
        path = parsed.path
        timestamp = int(time.time()) - 2
        header_ca = {
            "platform": "3", "timestamp": str(timestamp),
            "dId": did, "vName": "1.0.0",
        }
        sign = sc.request_sign(cred_token, path, body_or_query, timestamp, header_ca)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "gzip",
            "Connection": "close",
            "X-Requested-With": "com.hypergryph.skland",
            "dId": did,
            "cred": cred,
            "sign": sign,
            "platform": header_ca["platform"],
            "timestamp": header_ca["timestamp"],
            "vName": header_ca["vName"],
        }
        return headers

    # ---------- 认证链 ----------

    def _get_credential(self):
        """返回 (token, cred, status, message)。status 为空表示成功。"""
        did = self._device_id()
        try:
            g = self._json("POST", GRANT_URL,
                           headers=self._login_headers(did),
                           body={"appCode": APP_CODE, "token": self.account["token"],
                                  "type": 0})
        except Exception as e:
            return None, None, STATUS_TRANSIENT, f"授权请求失败: {e}"
        if g.get("status") != 0:
            msg = g.get("message") or "授权失败"
            st = STATUS_AUTH if _contains(msg, _AUTH_WORDS) or "token" in msg.lower() else STATUS_FAILED
            return None, None, st, f"鹰角授权失败: {msg}"

        code = (g.get("data") or {}).get("code")
        if not code:
            return None, None, STATUS_AUTH, "鹰角未返回授权码，token 可能已失效"

        try:
            c = self._json("POST", CRED_URL,
                           headers=self._login_headers(did),
                           body={"code": code, "kind": 1})
        except Exception as e:
            return None, None, STATUS_TRANSIENT, f"凭证请求失败: {e}"
        if c.get("code") != 0:
            msg = c.get("message") or "凭证生成失败"
            return None, None, STATUS_AUTH, f"森空岛凭证生成失败: {msg}"
        data = c.get("data") or {}
        if not data.get("token") or not data.get("cred"):
            return None, None, STATUS_AUTH, "森空岛未返回有效凭证"
        return data["token"], data["cred"], "", ""

    def _bindings(self, cred_token: str, cred: str, did: str):
        """返回 (bindings, status, message)。"""
        url = BINDING_URL
        headers = self._signed_headers("GET", url, cred_token, cred, did, "")
        try:
            d = self._json("GET", url, headers=headers)
        except Exception as e:
            return [], STATUS_TRANSIENT, f"绑定列表请求失败: {e}"
        if d.get("code") != 0:
            msg = d.get("message") or "获取绑定失败"
            st = STATUS_AUTH if _contains(msg, _AUTH_WORDS) else STATUS_FAILED
            return [], st, msg
        raw = ((d.get("data") or {}).get("list") or [])
        out = []
        for item in raw:
            app = item.get("appCode", "")
            if app not in SUPPORTED_APPS:
                continue
            for b in (item.get("bindingList") or []):
                out.append({"app": app, "game": b.get("gameName") or app,
                            "game_id": b.get("gameId", 1 if app == "arknights" else 3),
                            "uid": b.get("uid", ""),
                            "nickname": b.get("nickName") or b.get("nickname") or "",
                            "channel": b.get("channelName") or "",
                            "roles": b.get("roles") or []})
        return out, "", ""

    # ---------- 签到 ----------

    @staticmethod
    def _judge(d: dict) -> tuple:
        """返回 (是否成功, 文案, 分类)。"""
        if not isinstance(d, dict):
            return False, "返回格式异常", STATUS_FAILED
        msg = d.get("message") or d.get("msg") or ""
        code = d.get("code")
        if code == 0:
            return True, "签到成功", STATUS_OK
        if _contains(msg, _ALREADY_WORDS):
            return True, (msg or "今日已签"), STATUS_ALREADY
        if _contains(msg, _AUTH_WORDS):
            return False, (msg or "登录态失效"), STATUS_AUTH
        if _contains(msg, _TRANSIENT_WORDS):
            return False, (msg or "请求失败"), STATUS_TRANSIENT
        return False, f"签到失败 code={code} {msg}", STATUS_FAILED

    def _sign_arknights(self, cred_token, cred, did, b) -> tuple:
        body_dict = {"gameId": b["game_id"], "uid": b["uid"]}
        body = self._encode_body(body_dict)
        url = ARK_ATTEND_URL
        headers = self._signed_headers("POST", url, cred_token, cred, did, body)
        try:
            d = self._json("POST", url, headers=headers, body=body_dict)
        except Exception as e:
            return False, f"请求失败: {e}", STATUS_TRANSIENT
        ok, msg, st = self._judge(d)
        # 奖励明细
        awards = ((d.get("data") or {}).get("awards") or []) if isinstance(d, dict) else []
        if awards and ok:
            parts = [f"{(a.get('resource') or {}).get('name', '?')}x{a.get('count', 1)}"
                     for a in awards]
            if parts:
                msg += " " + ",".join(parts)
        return ok, msg, st

    def _sign_endfield(self, cred_token, cred, did, b, role) -> tuple:
        url = END_ATTEND_URL
        headers = self._signed_headers("POST", url, cred_token, cred, did, "")
        headers["Content-Type"] = "application/json"
        headers["sk-game-role"] = f"3_{role.get('roleId', '')}_{role.get('serverId', '')}"
        headers["referer"] = "https://game.skland.com/"
        headers["origin"] = "https://game.skland.com/"
        try:
            d = self._json("POST", url, headers=headers, body=None)
        except Exception as e:
            return False, f"请求失败: {e}", STATUS_TRANSIENT
        ok, msg, st = self._judge(d)
        return ok, msg, st

    def detect_bindings(self):
        """只读：返回 (ok, message, status, bindings)，供 Web「检测角色」用，不签到。"""
        cred_token, cred, st, msg = self._get_credential()
        if st:
            return False, msg, st, []
        bindings, st, msg = self._bindings(cred_token, cred, self._device_id())
        if st:
            return False, msg, st, []
        return True, "", "", bindings

    def _do_sign(self) -> CheckinResult:
        cred_token, cred, st, msg = self._get_credential()
        if st:
            return CheckinResult(platform=self.name, success=False, status=st, message=msg)

        did = self._device_id()
        bindings, st, msg = self._bindings(cred_token, cred, did)
        if st:
            return CheckinResult(platform=self.name, success=False, status=st, message=msg)
        if not bindings:
            return CheckinResult(
                platform=self.name, success=True, status=STATUS_OK,
                message="账号未绑定明日方舟/终末地角色，无需签到", items=[],
            )

        items: list[dict] = []
        details: list[str] = []
        for b in bindings:
            label = f"{b['game']}({b['nickname']})" if b["nickname"] else b["game"]
            if b["app"] == "arknights":
                ok, m, s = self._sign_arknights(cred_token, cred, did, b)
                items.append({"name": label, "status": s, "message": m})
                details.append(f"{label} {m}")
            else:  # endfield：每个角色独立签到
                roles = b["roles"] or [{}]
                for role in roles:
                    rn = role.get("nickname") or b["nickname"] or "角色"
                    ok, m, s = self._sign_endfield(cred_token, cred, did, b, role)
                    tag = f"{label}/{rn}"
                    items.append({"name": tag, "status": s, "message": m})
                    details.append(f"{tag} {m}")

        ok, status = summarize(items)
        return CheckinResult(
            platform=self.name, success=ok, status=status,
            message="; ".join(details), items=items,
            raw={"did": did},
        )
