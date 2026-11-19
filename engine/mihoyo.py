"""米游社(原神 / 星穹铁道 / 绝区零 / 崩坏3) 每日签到适配器。

✅ 2026-11-13 实机核对通过（luna/home 全部 rc=0 返回 30 条奖励）。
   核对脚本：tools/verify_authoritative.py

依赖账号配置字段：
    cookie    : 米游社 Cookie（需含 stoken/ltoken/ltuid/cookie_token 等）
    device_id : 可选，x-rpc-device_id，不给则用稳定默认值

接口布局（已核对）：
    GET  {web}/binding/api/getUserGameRolesByCookie   取角色
    GET  {web}/event/luna/home?act_id=...&lang=zh-cn  活动奖励（公共）
    GET  {web}/event/luna/info?...                    今日是否已签（需登录）
    POST {web}/event/luna/sign                        执行签到（需登录）
    绝区零使用 act-nap-api.mihoyo.com/event/luna/zzz/*

⚠️ 盐值与 app_version 会随客户端版本轮换，失效时用 tools/ 里的脚本重新核对。

⚠️ Cookie 名字坑（2026-11-13 实机定位，必读）：
    网页 / 扫码登录只下发 V2 名 cookie：cookie_token_v2 / account_id_v2 /
    ltoken_v2 / ltuid_v2 / ltmid_v2。
    luna 系列（info / sign）**只认 V1 名** cookie_token / account_id，
    而 bind 接口（getUserGameRolesByCookie）两套名字都认。
    于是会出现「角色能查出来、签到却报 -100 请登录后重试」的假象。
    修复方式：normalize_cookie() 在请求前补齐 V1 别名（保留原有 V2）。
    无需重新登录，也无需让用户重抓 cookie。

✅ 多游戏自动发现（2026-11-13 实测）：
    getUserGameRolesByCookie **不带 game_biz 参数**时，一次返回该账号下
    全部游戏的全部角色。因此不再需要硬编码「要查哪几个游戏」：
      1) 先不带参数请求，拿到 roles（含 game_biz / region / game_uid）
      2) 按 game_biz 去 GAMES 表里查 act_id
      3) 表里没有的 = 米游社新游戏但还没配置签到活动，单独提示，不影响其他游戏

    ⚠️ act_id 目前无法通过公开接口自动获取（活动页是前端渲染），
    新游戏上线签到活动时需往 config/games.json 补一条。表外置后不用改代码。
"""

import hashlib
import json
import random
import time

from .base import (
    CheckinAdapter, CheckinResult, summarize,
    STATUS_OK, STATUS_ALREADY, STATUS_TRANSIENT, STATUS_AUTH,
    STATUS_CAPTCHA, STATUS_FAILED,
)
from .games_config import mihoyo_games

WEB_API = "https://api-takumi.mihoyo.com"
ZZZ_API = "https://act-nap-api.mihoyo.com"
ROLES_URL = f"{WEB_API}/binding/api/getUserGameRolesByCookie"

APP_VERSION = "2.109.0"                            # 已核对
SALT_WEB = "DlOUwIupfU6YespEUWDJmXtutuXV6owG"      # 已核对
SALT_DATA = "t0qEgfub6cvueAPgR5m9aQWWVciEer7v"     # 带 body/query 的请求

# game_biz -> 配置（act_id / signgame 均已实机核对）
# 实际数据在 engine/games_config.py，可被 config/games.json 覆盖（新游戏不必改代码）
GAMES = mihoyo_games()

RC_OK = 0
RC_ALREADY = -5003      # 今日已签
RC_NOT_LOGIN = -100     # 登录态失效
RC_CAPTCHA = 1034       # 触发人机验证


def gen_ds(body: str = "", salt: str = SALT_WEB) -> str:
    t = str(int(time.time()))
    r = str(random.randint(100000, 200000))
    c = hashlib.md5(f"{salt}{t}{r}{body}".encode("utf-8")).hexdigest()
    return f"{t},{r},{c}"


_V2_TO_V1 = {
    "cookie_token_v2": "cookie_token",
    "account_id_v2": "account_id",
    "ltoken_v2": "ltoken",
    "ltuid_v2": "ltuid",
    "ltmid_v2": "ltmid",
    "account_mid_v2": "account_mid",
}


def normalize_cookie(raw: str) -> str:
    """补齐 V1 cookie 别名。

    luna 系列（info/sign）只认 V1 名 cookie_token / account_id，
    而网页 / 扫码登录只会下发 cookie_token_v2 / account_id_v2。
    bind 接口两套名字都认，于是出现「能查角色、签到报 -100」的假象。
    这里在保留原有 V2 的前提下追加 V1 别名，缺 ID 时互相兜底。
    """
    pairs = [p.strip() for p in (raw or "").split(";") if "=" in p]
    if not pairs:
        return raw or ""
    d = {}
    order = []
    for p in pairs:
        k, v = p.split("=", 1)
        k, v = k.strip(), v.strip()
        if k not in d:
            order.append(k)
        d[k] = v

    added = []
    for v2, v1 in _V2_TO_V1.items():
        if v1 not in d and d.get(v2):
            d[v1] = d[v2]
            added.append(v1)
    if "account_id" not in d and d.get("ltuid"):
        d["account_id"] = d["ltuid"]
        added.append("account_id")
    if "ltuid" not in d and d.get("account_id"):
        d["ltuid"] = d["account_id"]
        added.append("ltuid")

    return "; ".join(f"{k}={d[k]}" for k in order + added)


class MihoyoAdapter(CheckinAdapter):
    name = "mihoyo"
    required_fields = ("cookie",)

    def _headers(self, signgame: str, ds: str) -> dict:
        return {
            "Cookie": normalize_cookie(self.account["cookie"]),
            "DS": ds,
            "x-rpc-app_version": APP_VERSION,
            "x-rpc-client_type": "5",
            "x-rpc-device_id": self.account.get("device_id") or "checkin-engine-device",
            "x-rpc-signgame": signgame,
            "Origin": "https://act.mihoyo.com",
            "Referer": "https://act.mihoyo.com/",
        }

    def _fetch_roles_ex(self) -> tuple[list[dict], str]:
        """取回全部角色 + 失败原因。

        reason: ""=成功 / "auth"=登录态失效 / "failed"=其他 retcode /
                "transient"=网络异常。

        必须区分「Cookie 失效」和「账号下确实没有角色」：旧版把两者混成一条
        AUTH 消息，导致没有角色的账号每次签到都白跑一次 stoken 兑换。
        """
        try:
            r = self.session.get(
                ROLES_URL,
                headers=self._headers("hk4e", gen_ds()),
                timeout=20,
            )
            data = r.json()
        except Exception:
            return [], "transient"
        code = data.get("retcode")
        if code == RC_OK:
            return data.get("data", {}).get("list", []) or [], ""
        if code == RC_NOT_LOGIN:
            return [], "auth"
        return [], "failed"

    def _fetch_roles(self) -> list[dict]:
        """兼容旧调用方（角色检测 / 诊断脚本）的只返回列表版本。"""
        return self._fetch_roles_ex()[0]

    def _is_signed_today(self, cfg: dict, region: str, uid: str):
        """查今日是否已签；None 表示查询失败（仍尝试签到）。"""
        try:
            r = self.session.get(
                cfg["api"] + cfg["path"] + "/info",
                params={
                    "lang": "zh-cn",
                    "act_id": cfg["act_id"],
                    "region": region,
                    "uid": uid,
                },
                headers=self._headers(cfg["signgame"], gen_ds()),
                timeout=20,
            )
            data = r.json()
            if data.get("retcode") == RC_OK:
                return bool((data.get("data") or {}).get("is_sign"))
        except Exception:
            return None
        return None

    def _do_sign(self) -> CheckinResult:
        roles, reason = self._fetch_roles_ex()
        if reason == "auth":
            return CheckinResult(
                platform=self.name, success=False, status=STATUS_AUTH,
                message="Cookie 失效，需重新登录",
            )
        if reason == "transient":
            return CheckinResult(
                platform=self.name, success=False, status=STATUS_TRANSIENT,
                message="查询游戏角色失败（网络异常），稍后重试",
            )
        if reason == "failed":
            return CheckinResult(
                platform=self.name, success=False, status=STATUS_FAILED,
                message="查询游戏角色失败（接口返回错误），暂不续期",
            )
        if not roles:
            # 账号下确实没有角色 —— 不是登录态问题，别浪费 stoken 兑换
            return CheckinResult(
                platform=self.name, success=False, status=STATUS_FAILED,
                message="账号下没有可签到的米游社游戏角色",
            )

        details: list[str] = []
        items: list[dict] = []
        seen = set()
        unknown: dict[str, str] = {}   # 有新角色但未配置签到活动的游戏

        def add(tag: str, status: str, text: str) -> None:
            items.append({"name": tag, "status": status, "message": text})
            details.append(f"{tag} {text}")

        for role in roles:
            biz = role.get("game_biz", "")
            cfg = GAMES.get(biz)
            if not cfg:
                # 自动发现到的新游戏（还没配 act_id），单独提示，不算失败
                unknown.setdefault(biz, role.get("nickname") or "")
                continue
            region, uid = role.get("region"), role.get("game_uid")
            if (cfg["key"], uid) in seen:
                continue
            seen.add((cfg["key"], uid))
            tag = f"{cfg['name']}({uid})"

            if self._is_signed_today(cfg, region, uid) is True:
                add(tag, STATUS_ALREADY, "今日已签")
                continue

            body = json.dumps(
                {"act_id": cfg["act_id"], "region": region, "uid": uid},
                separators=(",", ":"),
            )
            headers = self._headers(cfg["signgame"], gen_ds(body, SALT_DATA))
            headers["Content-Type"] = "application/json"
            try:
                r = self.session.post(
                    cfg["api"] + cfg["path"] + "/sign",
                    data=body, headers=headers, timeout=20,
                )
                data = r.json()
            except Exception as e:
                add(tag, STATUS_TRANSIENT, f"请求失败: {e}")
                continue

            code, msg = data.get("retcode"), (data.get("message") or "ok")
            if code == RC_OK:
                add(tag, STATUS_OK, "签到成功")
            elif code == RC_ALREADY:
                add(tag, STATUS_ALREADY, "今日已签")
            elif code == RC_NOT_LOGIN:
                add(tag, STATUS_AUTH, "Cookie 失效，需重新登录")
            elif code == RC_CAPTCHA:
                add(tag, STATUS_CAPTCHA, "触发人机验证(1034)，请到米游社 App 处理")
            else:
                add(tag, STATUS_FAILED, f"失败 retcode={code} {msg}")

        if unknown:
            # 有新游戏但本地没配 act_id —— 明确提示怎么补，而不是静默跳过
            names = "、".join(f"{biz}" for biz in unknown)
            details.append(
                f"发现新游戏未配置签到活动({names})，请在 config/games.json 补 act_id"
            )

        if not items:
            return CheckinResult(
                platform=self.name, success=False, status=STATUS_FAILED,
                message="账号角色中没有可签到的米游社游戏"
                        + ("；" + "; ".join(details) if details else ""),
                items=items,
            )
        # 不再用 `ok = ok or s`：部分成功会被如实标成 partial
        ok, status = summarize(items)
        return CheckinResult(
            platform=self.name, success=ok, status=status,
            message="; ".join(details), items=items,
        )
