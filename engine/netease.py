"""燕云十六声(网易) 小程序签到适配器 —— ⚠️ 未实现 / 实验性草稿，禁止当作可用功能。

状态说明（重要，勿删）：
    - 本文件只是按公开资料写出的协议草稿。实机「核对」仅证明 4 个端点存在、
      在无 token 时统一返回 code:-1 "未登录"，**从未用真实 access_token 端到端
      验证过签到、返回值语义、幂等与风控行为**。
    - 没有可用的 access_token 获取 / 刷新链路（该令牌是微信小程序令牌，
      网页与云游戏页拿不到），因此无法形成可用的每日签到闭环。
    - engine/__init__.py 已把 "yanyun" 标为 IMPLEMENTATION_STATUS=unimplemented，
      service.py 会直接短路、不发起任何签到请求。本文件保留仅供后续开发参考。
    - 已完成且可用的只有「唤起微信小程序」辅助功能（store/login_browser.py），
      它用于帮用户打开小程序去抓包，与签到是否实现无关。

核对脚本：tools/probe_yanyun_all.py、tools/probe_yanyun.py

协议来源：52pojie 公开脚本 + 端点探活（非真实 token 验证）。

接口：
    签到    GET {SIGN_BASE}/user/sign?access_token=xxx
    用户    GET {SIGN_BASE}/user/info?access_token=xxx
    云游记  GET {YUN_BASE}/user/{userInfo,share,goOut,play}?callback=..&token=..&_=..
            （JSONP 格式，参数名是 token 不是 access_token，这是两套不同活动/应用）

账号配置字段：
    token        : access_token（签到用）/ token（云游记用）。抓包取得，无刷新接口。
    label        : 备注名（可选）
    yunyouji     : 可选，bool，是否顺带做云游记（share/goOut/play，会消耗体力）

抓包方式（务必用真机或 PC 微信打开小程序）：
    打开燕云十六声小程序 → 签到页 → 抓请求
        https://s3.game.163.com/7540694694f2dddc/user/sign?access_token=XXX
    取 URL 里的 access_token 即可。云游记的 token 在同一域下 a38a8ca2c0f1daec 组的 userInfo 请求里。

⚠️ token 无自动刷新，会过期；部分网络环境(IP)受限，建议在家用网络运行。
"""

import json
import time

from .base import CheckinAdapter, CheckinResult

SIGN_BASE = "https://s3.game.163.com/7540694694f2dddc"
YUN_BASE = "https://s3.game.163.com/a38a8ca2c0f1daec"

# 微信小程序 UA：不带这个 UA 网易网关可能直接拒绝
WX_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 "
    "MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
    "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
    "UnifiedPCWindowsWechat(0xf2540020) XWEB/11503"
)

RC_OK = 200


class YanyunAdapter(CheckinAdapter):
    name = "yanyun"
    required_fields = ("token",)

    # ---- 头部 ----
    def _sign_headers(self) -> dict:
        return {
            "User-Agent": WX_UA,
            "xweb_xhr": "1",
            "Content-Type": "application/json",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-language": "zh-CN,zh;q=0.9",
            "Referer": "https://servicewechat.com/",
        }

    def _jsonp_headers(self) -> dict:
        return {
            "User-Agent": WX_UA,
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
            "Referer": "https://www.yysls.cn/",
            "accept-language": "zh-CN,zh;q=0.9",
        }

    # ---- 签到 ----
    def _sign(self) -> tuple[bool, str]:
        try:
            r = self.session.get(
                SIGN_BASE + "/user/sign",
                params={"access_token": self.account["token"]},
                headers=self._sign_headers(),
                timeout=20,
            )
            data = r.json()
        except Exception as e:
            return False, f"签到请求失败: {e}"

        code = data.get("code")
        msg = data.get("msg") or data.get("message") or ""
        if code == RC_OK or data.get("success") is True:
            return True, "签到成功"
        if "已签到" in msg or "已经签到" in msg:
            return True, "今日已签"
        if code == -1 and ("未登录" in msg or "登录" in msg):
            return False, "token 已失效，请重新抓包更新"
        return False, f"签到失败 code={code} {msg}"

    # ---- 云游记（可选） ----
    def _jsonp_get(self, path: str, extra: dict | None = None) -> dict:
        cb = f"jQuery1113077113649235{int(time.time() * 1000) % 100000}_1736818337241"
        params = {"callback": cb, "token": self.account["token"],
                  "_": str(int(time.time() * 1000))}
        if extra:
            params.update(extra)
        r = self.session.get(
            YUN_BASE + path, params=params, headers=self._jsonp_headers(), timeout=20
        )
        text = r.text
        inner = text[text.find("(") + 1: text.rfind(")")] if "(" in text else text
        try:
            return json.loads(inner)
        except Exception:
            return {"code": -1, "msg": f"无法解析 JSONP: {text[:80]}"}

    def _yunyouji(self) -> str:
        """分享 + 外出 + 抽奖。返回简报。失败不抛异常。"""
        steps = []
        try:
            j = self._jsonp_get("/user/userInfo")
            if j.get("code") != RC_OK:
                return f"云游记跳过({j.get('msg')})"

            j = self._jsonp_get("/user/share")
            steps.append("分享✓" if j.get("code") == RC_OK else "分享✗")

            # 外出：最多 5 次，每次消耗 10 体力
            place = str(self.account.get("place", 1))
            for _ in range(5):
                j = self._jsonp_get("/user/goOut", {"place": place})
                if j.get("code") != RC_OK:
                    break
                # 外出需约 3 分钟后才能收，简化：轮询 3 次×30s 太重，这里只发起
                steps.append("外出✓")
                break

            # 抽奖：最多 5 次
            plays = 0
            for _ in range(5):
                j = self._jsonp_get("/user/play")
                if j.get("code") != RC_OK:
                    break
                plays += 1
            steps.append(f"抽奖{plays}次")
        except Exception as e:
            steps.append(f"云游记异常:{e}")
        return "; ".join(steps) if steps else "云游记未执行"

    def _do_sign(self) -> CheckinResult:
        ok, msg = self._sign()
        detail = [msg]

        if ok and self.account.get("yunyouji"):
            detail.append(self._yunyouji())

        return CheckinResult(
            platform=self.name, success=ok, message="; ".join(detail)
        )
