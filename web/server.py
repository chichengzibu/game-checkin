#!/usr/bin/env python3
"""本地可视化界面服务端（零依赖，仅标准库）。

启动：
    python web/server.py            # 默认 http://127.0.0.1:8899
    python web/server.py --port 9000

只监听 127.0.0.1（本机），不对外暴露。
界面：web/index.html
API：
    GET    /api/accounts            账号列表（脱敏）
    POST   /api/accounts            新增账号
    PUT    /api/accounts/<id>       修改账号
    DELETE /api/accounts/<id>       删除账号
    POST   /api/accounts/<id>/toggle 启用/停用
    POST   /api/accounts/<id>/renew  手动检查并续期凭证
    GET    /api/platforms           各平台实现状态
    POST   /api/checkin             发起签到（全部或指定），返回 task_id
    GET    /api/checkin/status?task_id=  查询进度
    GET    /api/health              健康检查
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import service                                  # noqa: E402
from engine import (                             # noqa: E402
    IMPLEMENTATION_STATUS, is_implemented, platform_status, status_text,
    unimplemented_hint,
)
from store import credentials, get_store         # noqa: E402
from store.base import Account                   # noqa: E402
from store.login_mihoyo import (                 # noqa: E402
    LoginError, MihoyoQRLogin,
)
from store.login_browser import (                # noqa: E402
    PLATFORMS as BROWSER_PLATFORMS, BrowserLoginSession,
    open_yanyun_miniprogram, find_wechat_applet_appid,
    find_yanyun_shortcut, find_wechat_exe, set_yanyun_link,
)

LOCAL_USER = "local"
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

# 签到任务表：task_id -> {done, total, results[], finished, started}
TASKS: dict[str, dict] = {}
TASKS_LOCK = threading.Lock()

# 登录会话表：session_id -> MihoyoQRLogin 实例（内存，进程内有效）
LOGIN_SESSIONS: dict[str, MihoyoQRLogin] = {}
LOGIN_LOCK = threading.Lock()

# 浏览器登录会话：session_id -> BrowserLoginSession
BROWSER_SESSIONS: dict[str, BrowserLoginSession] = {}
BROWSER_LOCK = threading.Lock()


def store():
    # 支持 CHECKIN_VAULT_PATH 覆盖（测试 / 多实例隔离用）
    return get_store("local", path=os.environ.get("CHECKIN_VAULT_PATH") or None)


def acct_public(a: Account) -> dict:
    """脱敏：不回传凭据明文，只告诉前端有没有。"""
    return {
        "id": a.id,
        "platform": a.platform,
        "label": a.label,
        "enabled": a.enabled,
        "has_credential": bool(a.credential),
        "last_run": a.last_run,
        "last_result": a.last_result,
        "implemented": is_implemented(a.platform),
        "status_text": status_text(a.platform),
        "renew": credentials.public_status(a),
    }


def detect_account(user_id: str, account_id: str) -> dict:
    """检测一个账号「实际拥有哪些游戏的账号」。

    不执行签到，只探测角色列表，明确告诉前端：
      - games: 该平台下用户实际有角色的游戏（会被纳入签到）
      - note:  没有角色的 / 未配置活动的说明
    """
    from engine import get_adapter
    from engine.games_config import mihoyo_games, kuro_games

    for a in store().list_accounts(user_id):
        if a.id != account_id:
            continue
        payload = {"platform": a.platform, "label": a.label}
        payload.update(a.credential or {})
        games: list[dict] = []
        note = ""
        try:
            ad = get_adapter(a.platform, payload)
            if a.platform == "kuro":
                owned = ad.discover_games()
                names = kuro_games()
                for gid, roles in sorted(owned.items(), key=lambda kv: int(kv[0])):
                    games.append({
                        "id": gid,
                        "name": names.get(gid, f"游戏{gid}"),
                        "roles": [r.get("roleName") or r.get("roleId") for r in roles],
                    })
                if not games:
                    note = "该账号在库街区下没有可识别的游戏角色（token 可能已失效）"
            elif a.platform == "mihoyo":
                cfg = mihoyo_games()
                roles = ad._fetch_roles() if hasattr(ad, "_fetch_roles") else []
                for role in roles:
                    biz = role.get("game_biz", "")
                    gname = cfg.get(biz, {}).get("name") or biz
                    games.append({
                        "id": biz,
                        "name": gname,
                        "roles": [role.get("nickname") or role.get("game_uid")],
                    })
                if not games:
                    note = "未取到角色：Cookie 可能已失效"
            else:
                note = f"平台 {a.platform} 暂不支持角色检测"
        except Exception as e:  # noqa: BLE001
            note = f"检测异常: {e}"
        return {"ok": True, "platform": a.platform, "games": games, "note": note}
    return {"ok": False, "error": "账号不存在"}


# ---------------- 签到任务（后台线程 + 轮询进度） ----------------

def _run_task(task_id: str, only_id: str | None) -> None:
    st = store()
    accounts = st.list_accounts(LOCAL_USER)
    if only_id:
        accounts = [a for a in accounts if a.id == only_id]

    with TASKS_LOCK:
        # POST /api/checkin 已同步占位；这里只补 total，避免轮询撞上 404
        t = TASKS.setdefault(task_id, {
            "done": 0, "total": 0, "results": [],
            "finished": False, "started": False,
        })
        t["total"] = len(accounts)
        t["started"] = True

    for acc in accounts:
        # 传 store 让续期结果能回写加密库，否则服务端单活轮换会让旧 token 彻底失效
        ok, msg = service._check_one(acc, st, LOCAL_USER)
        st.save_result(LOCAL_USER, acc.id, service._now(), msg)
        with TASKS_LOCK:
            t = TASKS[task_id]
            t["results"].append({
                "id": acc.id,
                "label": acc.label or acc.platform,
                "platform": acc.platform,
                "success": ok,
                "message": msg,
            })
            t["done"] += 1

    with TASKS_LOCK:
        TASKS[task_id]["finished"] = True


# ---------------- HTTP 处理 ----------------

class Handler(BaseHTTPRequestHandler):
    server_version = "CheckinUI/1.0"

    # --- 工具 ---
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def log_message(self, fmt, *args):
        pass  # 静音默认访问日志

    # --- 路由 ---
    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)

        if path in ("/", "/index.html"):
            return self._serve_file("index.html", "text/html; charset=utf-8")
        if path == "/api/health":
            return self._json(200, {"ok": True, "time": service._now()})
        if path == "/api/platforms":
            return self._json(200, {
                "ok": True,
                "platforms": {
                    p: {"status": platform_status(p), "text": status_text(p),
                        "implemented": is_implemented(p)}
                    for p in IMPLEMENTATION_STATUS
                },
            })
        if path == "/api/accounts":
            accs = [acct_public(a) for a in store().list_accounts(LOCAL_USER)]
            return self._json(200, {"ok": True, "accounts": accs})
        if path == "/api/checkin/status":
            tid = (qs.get("task_id") or [""])[0]
            with TASKS_LOCK:
                t = TASKS.get(tid)
                if not t:
                    return self._json(404, {"ok": False, "error": "任务不存在"})
                return self._json(200, {"ok": True, **t})

        # /api/accounts/<id>/detect —— 检测该账号在哪些游戏下有角色
        if path.startswith("/api/accounts/") and path.endswith("/detect"):
            aid = path[len("/api/accounts/"):-len("/detect")]
            return self._json(200, detect_account(LOCAL_USER, aid))
        # 静态资源
        name = path.lstrip("/")
        if name and "/" not in name and ".." not in name:
            ctype = "text/css" if name.endswith(".css") else (
                "application/javascript" if name.endswith(".js") else "text/plain")
            return self._serve_file(name, ctype + "; charset=utf-8")
        return self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/accounts":
            data = self._body()
            platform = (data.get("platform") or "").strip()
            if platform not in ("mihoyo", "kuro", "yanyun", "stub"):
                return self._json(400, {"ok": False, "error": "平台不合法"})
            cred = data.get("credential") or {}
            if not cred:
                return self._json(400, {"ok": False, "error": "凭据不能为空"})
            # 手填米游社 Cookie 时，顺手把 stoken 等续期材料补齐，
            # 老账号因此无需重新登录就能获得自动续期能力。
            if platform == "mihoyo":
                cred = credentials.enrich_mihoyo(cred)
            acc = Account(
                platform=platform,
                label=(data.get("label") or "").strip() or platform,
                credential=cred,
                enabled=bool(data.get("enabled", True)),
            )
            store().add_account(LOCAL_USER, acc)
            resp = {"ok": True, "id": acc.id}
            if not is_implemented(platform):
                resp["warning"] = unimplemented_hint(platform)
            return self._json(200, resp)

        if path == "/api/checkin":
            data = self._body()
            only = (data.get("account_id") or "").strip() or None
            tid = uuid.uuid4().hex[:12]
            # 同步占位：否则 POST 返回后立刻轮询 status 可能撞上 404
            with TASKS_LOCK:
                TASKS[tid] = {
                    "done": 0, "total": 0, "results": [],
                    "finished": False, "started": False,
                }
            threading.Thread(target=_run_task, args=(tid, only), daemon=True).start()
            return self._json(200, {"ok": True, "task_id": tid})

        # /api/accounts/<id>/toggle
        if path.startswith("/api/accounts/") and path.endswith("/toggle"):
            aid = path[len("/api/accounts/"):-len("/toggle")]
            for a in store().list_accounts(LOCAL_USER):
                if a.id == aid:
                    a.enabled = not a.enabled
                    store().update_account(LOCAL_USER, a)
                    return self._json(200, {"ok": True, "enabled": a.enabled})
            return self._json(404, {"ok": False, "error": "账号不存在"})

        # /api/accounts/<id>/renew —— 手动检查并续期（便于验证 / 主动维护）
        if path.startswith("/api/accounts/") and path.endswith("/renew"):
            aid = path[len("/api/accounts/"):-len("/renew")]
            st = store()
            for a in st.list_accounts(LOCAL_USER):
                if a.id == aid:
                    if not is_implemented(a.platform):
                        return self._json(200, {
                            "ok": False, "note": unimplemented_hint(a.platform),
                        })
                    ok, note = credentials.renew(a, st, LOCAL_USER)
                    return self._json(200, {
                        "ok": ok, "note": note,
                        "renew": credentials.public_status(a),
                    })
            return self._json(404, {"ok": False, "error": "账号不存在"})

        # ---------------- 登录（自动获取凭据） ----------------
        if path == "/api/login/start":
            data = self._body()
            platform = (data.get("platform") or "").strip()
            if platform != "mihoyo":
                return self._json(400, {
                    "ok": False,
                    "error": "该平台暂不支持网页登录，请用「手动填写」方式添加",
                    "unsupported": True,
                })
            try:
                sess = MihoyoQRLogin()
                qr = sess.create()
                sid = uuid.uuid4().hex[:12]
                with LOGIN_LOCK:
                    LOGIN_SESSIONS[sid] = sess
                return self._json(200, {
                    "ok": True,
                    "session_id": sid,
                    "ticket": qr["ticket"],
                    "qr_url": qr["url"],
                })
            except LoginError as e:
                return self._json(502, {"ok": False, "error": str(e)})

        if path == "/api/login/poll":
            data = self._body()
            sid = (data.get("session_id") or "").strip()
            with LOGIN_LOCK:
                sess = LOGIN_SESSIONS.get(sid)
            if not sess:
                return self._json(404, {"ok": False, "error": "登录会话不存在或已过期"})
            try:
                st = sess.poll(data.get("ticket") or "")
            except LoginError as e:
                return self._json(502, {"ok": False, "error": str(e)})

            status = st.get("status")
            if status == "Confirmed":
                # 结构化保存续期材料：stoken/stuid/mid 来自登录响应体，
                # cookie 串保留完整登录态；再由 enrich 补齐可派生字段。
                cred = credentials.enrich_mihoyo({
                    "cookie": st["cookie"],
                    "device_id": sess.device_id,
                    **(st.get("renewal") or {}),
                })
                acc = Account(
                    platform="mihoyo",
                    label=data.get("label") or f"米游社 {st.get('nickname') or st.get('uid') or ''}".strip(),
                    credential=cred,
                    enabled=True,
                )
                store().add_account(LOCAL_USER, acc)
                with LOGIN_LOCK:
                    LOGIN_SESSIONS.pop(sid, None)
                return self._json(200, {
                    "ok": True, "status": status, "account_id": acc.id,
                    "label": acc.label,
                    "nickname": st.get("nickname"), "uid": st.get("uid"),
                    "auto_renew": bool(cred.get("stoken")),
                })

            if status in ("Expired", "Cancelled", "Error"):
                with LOGIN_LOCK:
                    LOGIN_SESSIONS.pop(sid, None)
            return self._json(200, {
                "ok": True, "status": status, "error": st.get("error"),
            })

        # ---------------- 浏览器登录（官方登录页 + 自动抓 cookie） ----------------
        if path == "/api/login/browser/start":
            data = self._body()
            platform = (data.get("platform") or "").strip()
            if platform == "yanyun":
                return self._json(400, {
                    "ok": False,
                    "error": "燕云签到尚未实现，且不支持网页自动登录：其 access_token 是微信小程序令牌，网页拿不到。",
                    "unsupported": True,
                })
            if platform not in BROWSER_PLATFORMS:
                return self._json(400, {
                    "ok": False,
                    "error": f"不支持的平台: {platform}",
                    "supported": list(BROWSER_PLATFORMS),
                })
            try:
                sess = BrowserLoginSession(platform)
                info = sess.start()
                sid = uuid.uuid4().hex[:12]
                with BROWSER_LOCK:
                    BROWSER_SESSIONS[sid] = sess
                return self._json(200, {
                    "ok": True, "session_id": sid,
                    "platform": platform,
                    "label": info["label"],
                    "hint": info["hint"],
                    "login_url": info["login_url"],
                })
            except Exception as e:  # noqa: BLE001
                return self._json(502, {"ok": False, "error": str(e)})

        if path == "/api/login/browser/poll":
            data = self._body()
            sid = (data.get("session_id") or "").strip()
            with BROWSER_LOCK:
                sess = BROWSER_SESSIONS.get(sid)
            if not sess:
                return self._json(404, {"ok": False, "error": "登录会话不存在"})

            st = sess.poll_cookies()
            status = st.get("status")

            if status == "Confirmed":
                # 统一取到 token/cookie 值
                token_val = st.get("token")
                cookie_val = st.get("cookie")

                if sess.platform == "kuro":
                    # 库街区要的是 token 值本身；网页登录的 token 必须声明 source=h5。
                    # 官方无刷新接口，保存完整 token + source 是减少重复授权的关键。
                    cred = {"token": token_val or cookie_val, "source": "h5"}
                elif sess.platform == "mihoyo":
                    cred = credentials.enrich_mihoyo({
                        "cookie": cookie_val,
                        "device_id": str(uuid.uuid4()),
                        **(st.get("renewal") or {}),
                    })
                else:
                    cred = {"token": token_val} if token_val else {"cookie": cookie_val}

                label = (data.get("label") or "").strip() or BROWSER_PLATFORMS[sess.platform]["label"]
                acc = Account(platform=sess.platform, label=label,
                              credential=cred, enabled=True)
                store().add_account(LOCAL_USER, acc)
                sess.close()
                with BROWSER_LOCK:
                    BROWSER_SESSIONS.pop(sid, None)
                return self._json(200, {
                    "ok": True, "status": "Confirmed",
                    "account_id": acc.id, "label": acc.label,
                    "source": st.get("source"),
                    "auto_renew": bool(cred.get("stoken")),
                })

            if status in ("BrowserClosed",):
                with BROWSER_LOCK:
                    BROWSER_SESSIONS.pop(sid, None)
                return self._json(200, {
                    "ok": False, "status": "BrowserClosed",
                    "error": st.get("error") or "浏览器已关闭，登录未完成",
                })

            return self._json(200, {"ok": True, "status": status})

        if path == "/api/login/yanyun/open":
            try:
                return self._json(200, open_yanyun_miniprogram())
            except Exception as e:  # noqa: BLE001
                return self._json(502, {"ok": False, "error": str(e)})

        if path == "/api/login/yanyun/set-link":
            # 用户粘贴小程序链接（#小程序:// 或 weixin://dl/business/?appid=），尽力解析 appid
            data = self._body()
            link = (data.get("link") or "").strip()
            try:
                return self._json(200, set_yanyun_link(link))
            except Exception as e:  # noqa: BLE001
                return self._json(502, {"ok": False, "error": str(e)})

        if path == "/api/login/yanyun/discover":
            # 探测本机是否已能自动定位燕云小程序（无需用户建快捷方式/手填 appid）
            try:
                appid = find_wechat_applet_appid("燕云")
                shortcut = find_yanyun_shortcut("燕云")
                wechat = find_wechat_exe()
                if appid:
                    hint = "已自动从本机微信缓存定位到燕云小程序，点「登录获取」可直接唤起（注意：燕云签到尚未实现）"
                    method = "auto_appid"
                elif shortcut:
                    hint = "桌面已存在燕云快捷方式，点「登录获取」会直接打开它（注意：燕云签到尚未实现）"
                    method = "shortcut"
                elif wechat:
                    hint = ("已找到微信客户端，但缓存里还没有燕云小程序——请先在微信里打开一次"
                            "「燕云十六声」（注意：燕云签到尚未实现）")
                    method = "wechat_only"
                else:
                    hint = ("未找到微信客户端，也未定位到燕云小程序：请先安装并登录微信 Windows 客户端，"
                            "或在微信里打开一次「燕云十六声」小程序")
                    method = "none"
                return self._json(200, {
                    "ok": True,
                    "auto_appid": bool(appid),
                    "appid": appid,
                    "has_shortcut": bool(shortcut),
                    "wechat_found": bool(wechat),
                    "method": method,
                    "implemented": is_implemented("yanyun"),
                    "hint": hint,
                })
            except Exception as e:  # noqa: BLE001
                return self._json(502, {"ok": False, "error": str(e)})

        if path == "/api/login/browser/cancel":
            data = self._body()
            sid = (data.get("session_id") or "").strip()
            with BROWSER_LOCK:
                sess = BROWSER_SESSIONS.pop(sid, None)
            if sess:
                sess.close()
            return self._json(200, {"ok": True})

        return self._json(404, {"ok": False, "error": "not found"})

    def do_PUT(self):
        path = urlparse(self.path).path
        if path.startswith("/api/accounts/"):
            aid = path[len("/api/accounts/"):]
            data = self._body()
            st = store()
            for a in st.list_accounts(LOCAL_USER):
                if a.id == aid:
                    if data.get("label") is not None:
                        a.label = data["label"].strip() or a.label
                    if data.get("platform"):
                        a.platform = data["platform"]
                    if data.get("enabled") is not None:
                        a.enabled = bool(data["enabled"])
                    # 只有传了新凭据才覆盖
                    if data.get("credential"):
                        cred = data["credential"]
                        if a.platform == "mihoyo":
                            cred = credentials.enrich_mihoyo(cred)
                        a.credential = cred
                    st.update_account(LOCAL_USER, a)
                    return self._json(200, {"ok": True})
            return self._json(404, {"ok": False, "error": "账号不存在"})
        return self._json(404, {"ok": False, "error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/api/accounts/"):
            aid = path[len("/api/accounts/"):]
            ok = store().delete_account(LOCAL_USER, aid)
            return self._json(200 if ok else 404, {"ok": ok})
        return self._json(404, {"ok": False, "error": "not found"})

    def _serve_file(self, name: str, ctype: str) -> None:
        p = os.path.join(WEB_DIR, name)
        if not os.path.isfile(p):
            return self._json(404, {"ok": False, "error": "文件不存在"})
        with open(p, "rb") as f:
            self._send(200, f.read(), ctype)


def main() -> None:
    ap = argparse.ArgumentParser(description="签到可视化界面")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args()

    if not os.environ.get("CHECKIN_MASTER_KEY"):
        print("[提示] 未设置 CHECKIN_MASTER_KEY，使用用户级密钥文件或历史默认密钥。")
        print("      设置方法：export CHECKIN_MASTER_KEY='你的随机长串'")

    from store.local_store import resolve_master_key  # noqa: WPS433
    resolve_master_key()  # 首次运行即生成并持久化，保证重启后不用重新登录

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print("=" * 56)
    print(f"  签到界面已启动： {url}")
    print("  按 Ctrl+C 停止")
    print("=" * 56)
    if not args.no_browser:
        try:
            import webbrowser
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
