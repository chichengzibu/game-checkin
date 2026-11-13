"""库街区 / 鸣潮 / 战双帕弥什 每日签到适配器。

✅ 2026-11-13 按开源实现重写并盲测验证：
   参考 suspension0/kurobbs_auto_checkin、Maojuan-lang/MingChaoSign + 实机探测。

接口（已修正，之前版本全错）：
    POST https://api.kurobbs.com/user/role/findRoleList  取角色列表（按 gameId）
    POST https://api.kurobbs.com/encourage/signIn/v2     游戏奖励签到
    POST https://api.kurobbs.com/user/signIn             社区签到

关键修正：
    ❌ 旧: 头 "x-token"           ✅ 新: 头 "token"
    ❌ 旧: /encourage/signIn      ✅ 新: /encourage/signIn/v2
    ❌ 旧: 只传 gameId            ✅ 新: gameId+serverId+roleId+userId+reqMonth
    ❌ 旧: source 写死 android    ✅ 新: 按 token 来源取（网页 h5 / App android）

✅ 多游戏自动发现（2026-11-13）：
    不再硬编码「只签鸣潮」。config 里给一份 gameId 表，运行时会：
      1) 遍历 KURO_PROBE_RANGE（1..12）调 findRoleList
      2) 接口返回 code=200 且有角色 -> 该游戏计入「已拥有」
      3) 未知 gameId 自动登记到 config/games.json 并命名为「游戏{id}」
    这样库街区上新游戏（gameId 变了或新增）无需改代码。

✅ 只报有账号的角色（2026-11-13）：
    没有角色的游戏不会出现在结果里，也不会报「失败」。
    只有拿到角色并执行签到的游戏才会输出成功/已签/失败。

账号配置字段：
    token : 库街区 App 登录态 token（请求头 token 的值）。抓包取得，会过期。
    source: h5 | android，默认 h5（网页登录拿到的 token 必须 h5）
    label : 备注名（可选）
"""

from datetime import datetime

from .base import CheckinAdapter, CheckinResult
from .games_config import KURO_PROBE_RANGE, kuro_games, save_games

API = "https://api.kurobbs.com"
FIND_ROLE_URL = API + "/user/role/findRoleList"
SIGN_URL = API + "/encourage/signIn/v2"
BBS_SIGN_URL = API + "/user/signIn"

RC_OK = 200
RC_ALREADY = 1511          # 请勿重复签到
RC_NO_GAME_CONFIG = 10100  # 游戏配置不存在（该 gameId 没有游戏）


class KuroAdapter(CheckinAdapter):
    name = "kuro"
    required_fields = ("token",)

    def _headers(self) -> dict:
        # 关键：token 来源不同，source 头必须匹配
        #   网页登录拿到的 auth_token -> source=h5
        #   App 抓包拿到的 token      -> source=android
        source = self.account.get("source") or "h5"
        is_h5 = source == "h5"

        if is_h5:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )
            devcode = self.account.get("devcode") or "checkin-engine-h5"
        else:
            user_agent = (
                "Mozilla/5.0 (Linux; Android 14; 22081212C Build/UKQ1.230917.001; wv) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
                "Chrome/124.0.6367.179 Mobile Safari/537.36 "
                "Kuro/2.2.0 KuroGameBox/2.2.0"
            )
            devcode = self.account.get("devcode") or "checkin-engine-device"

        return {
            "User-Agent": user_agent,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "source": source,
            "devcode": devcode,
            "token": self.account["token"],
            "origin": "https://web-static.kurobbs.com",
            "referer": "https://www.kurobbs.com/",
            "x-requested-with": "com.kurogame.kjq" if not is_h5 else "XMLHttpRequest",
            "accept-language": "zh-CN,zh;q=0.9",
        }

    # ---------- 发现 ----------

    def _roles(self, game_id: str) -> list[dict]:
        """取某游戏的账号角色。code=200 且非空即代表「用户有这个游戏」。"""
        roles, _ = self._roles_status(game_id)
        return roles

    def _roles_status(self, game_id: str) -> tuple[list[dict], int]:
        """同 _roles，额外返回原始 code 用于判断「gameId 不存在」。"""
        try:
            r = self.session.post(
                FIND_ROLE_URL, data={"gameId": game_id},
                headers=self._headers(), timeout=20,
            )
            d = r.json()
            code = d.get("code")
            if code == RC_OK and isinstance(d.get("data"), list):
                return d["data"], code
            return [], code
        except Exception:
            return [], -1

    def discover_games(self) -> dict[str, list[dict]]:
        """遍历 gameId 找出用户实际拥有的游戏 -> {gameId: [roles]}。

        顺序：先扫 config 里已知的 gameId（命中率高、快），
        再扫探测范围内的剩余 ID；连续 4 个「游戏配置不存在」即判定
        后面已经没有更多游戏，提前结束（库街区 gameId 递增分配，
        留 4 个空位的余量，避免中间有未启用的 ID 时误判）。
        """
        known_ids = [int(g) for g in kuro_games() if str(g).isdigit()]
        scan = known_ids + [g for g in KURO_PROBE_RANGE if g not in known_ids]

        owned: dict[str, list[dict]] = {}
        missing_streak = 0
        for gid in scan:
            roles, code = self._roles_status(str(gid))
            if roles:
                owned[str(gid)] = roles
                missing_streak = 0
                continue
            if code == RC_NO_GAME_CONFIG:
                missing_streak += 1
                if missing_streak >= 4:
                    break
            else:
                missing_streak = 0
        return owned

    # ---------- 签到 ----------

    def _sign_reward(self, game_id: str, server_id: str, role_id: str, user_id: str):
        data = {
            "gameId": game_id,
            "serverId": server_id,
            "roleId": role_id,
            "userId": user_id,
            "reqMonth": datetime.now().strftime("%m"),
        }
        try:
            r = self.session.post(SIGN_URL, data=data, headers=self._headers(), timeout=20)
            return r.json()
        except Exception as e:
            return {"code": -1, "msg": f"请求失败: {e}"}

    def _bbs_sign(self) -> dict:
        try:
            r = self.session.post(
                BBS_SIGN_URL, data={"gameId": "2"},
                headers=self._headers(), timeout=20,
            )
            return r.json()
        except Exception as e:
            return {"code": -1, "msg": f"请求失败: {e}"}

    @staticmethod
    def _judge(d: dict) -> tuple[bool, str]:
        code = d.get("code")
        msg = d.get("msg") or d.get("message") or ""
        success = d.get("success")
        if code == RC_OK or success is True:
            return True, "签到成功"
        if code == RC_ALREADY or any(k in msg for k in ("已签", "重复", "已经签")):
            return True, "今日已签"
        if code == 220 or "令牌" in msg or "登录" in msg:
            return False, "token 无效/已过期，请重新登录"
        return False, f"失败 code={code} {msg}"

    def _do_sign(self) -> CheckinResult:
        owned = self.discover_games()

        # token 失效的判定：连一个游戏都查不到，且社区签到也报登录失效
        if not owned:
            bbs = self._bbs_sign()
            s, m = self._judge(bbs)
            if not s and ("token" in m or "登录" in m):
                return CheckinResult(
                    platform=self.name, success=False,
                    message=f"未发现任何游戏账号：{m}",
                )
            return CheckinResult(
                platform=self.name, success=s,
                message=f"该账号在库街区没有可签到的游戏; 社区 {m}",
            )

        known = kuro_games()
        details, ok = [], False
        newly = {}

        for gid, roles in sorted(owned.items(), key=lambda kv: int(kv[0])):
            # 未知 gameId 自动登记（下次直接有名字）
            if gid not in known:
                name = f"游戏{gid}"
                newly[gid] = name
                known[gid] = name
            gname = known[gid]

            for role in roles:
                server_id = str(role.get("serverId", ""))
                role_id = str(role.get("roleId", ""))
                user_id = str(role.get("userId", ""))
                role_name = role.get("roleName") or ""
                tag = f"{gname}{f'({role_name})' if role_name else ''}"
                d = self._sign_reward(str(role.get("gameId", gid)), server_id, role_id, user_id)
                s, m = self._judge(d)
                ok = ok or s
                details.append(f"{tag} {m}")

        if newly:
            try:
                save_games({"kuro": newly})
            except Exception:
                pass

        # 社区签到（与游戏奖励相互独立）
        d = self._bbs_sign()
        s, m = self._judge(d)
        ok = ok or s
        details.append(f"社区 {m}")

        return CheckinResult(platform=self.name, success=ok, message="; ".join(details))
