#!/usr/bin/env python3
"""可视化界面端到端测试：验证所有 API 端点 + 前端按钮绑定。

分两部分：
  A. 后端 API 全链路测试（真实起服务、真实 HTTP 请求）
  B. 前端静态检查：index.html 里每个按钮 id 都有对应事件绑定，每个 bind 的
     功能都有实现，防止"按钮摆着没接线"。

    python tools/test_web.py        # 退出码 0 = 全部通过
"""

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  ({detail})" if detail and not cond else ""))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return None, {"error": str(e)}


def wait_up(base, timeout=20) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        code, _ = http("GET", base + "/api/health")
        if code == 200:
            return True
        time.sleep(0.25)
    return False


# ---------------------------------------------------------------- A. API
def test_api():
    print("\n[A] 后端 API 端到端")
    port = free_port()
    tmpdir = tempfile.mkdtemp()
    vault = os.path.join(tmpdir, "vault.json")

    env = dict(os.environ)
    env["CHECKIN_MASTER_KEY"] = "web-test-key"
    env["CHECKIN_VAULT_PATH"] = vault

    # 让 server 用临时 vault：通过环境变量注入（server 里已支持）
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "web", "server.py"), "--port", str(port)],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        if not wait_up(base):
            check("服务启动", False, "健康检查超时")
            return
        check("服务启动", True)

        # health
        code, d = http("GET", base + "/api/health")
        check("GET /api/health", code == 200 and d.get("ok"))

        # 首页 HTML
        code, _ = http("GET", base + "/")
        # 首页返回 HTML 不是 JSON，用普通请求单独测
        try:
            with urllib.request.urlopen(base + "/", timeout=10) as r:
                html = r.read().decode()
            check("GET / 返回 HTML", "游戏签到中心" in html)
        except Exception as e:
            check("GET / 返回 HTML", False, str(e))

        # 初始列表为空
        code, d = http("GET", base + "/api/accounts")
        check("GET 账号列表(初始为空)", code == 200 and d["accounts"] == [])

        # 新增
        code, d = http("POST", base + "/api/accounts", {
            "platform": "mihoyo", "label": "测试大号",
            "credential": {"cookie": "ltuid=1; ltoken=FAKE"},
        })
        check("POST 新增账号", code == 200 and d.get("ok") and d.get("id"))
        aid = d.get("id")

        # 新增校验：空凭据被拒
        code, d = http("POST", base + "/api/accounts",
                       {"platform": "kuro", "credential": {}})
        check("POST 空凭据被拒", code == 400)

        # 新增校验：非法平台被拒
        code, d = http("POST", base + "/api/accounts",
                       {"platform": "hack", "credential": {"x": "y"}})
        check("POST 非法平台被拒", code == 400)

        # 列表含账号且脱敏
        code, d = http("GET", base + "/api/accounts")
        raw = json.dumps(d, ensure_ascii=False)
        check("列表含新账号", len(d["accounts"]) == 1)
        check("列表不泄露凭据明文", "FAKE" not in raw)
        check("列表有 has_credential", d["accounts"][0]["has_credential"] is True)

        # 修改（改名，不改凭据）
        code, d = http("PUT", base + f"/api/accounts/{aid}", {"label": "改名后"})
        check("PUT 修改账号", code == 200 and d.get("ok"))
        code, d = http("GET", base + "/api/accounts")
        check("修改生效", d["accounts"][0]["label"] == "改名后")

        # 修改不存在的账号
        code, d = http("PUT", base + "/api/accounts/nonexist", {"label": "x"})
        check("PUT 不存在账号返回 404", code == 404)

        # 启用/停用
        code, d = http("POST", base + f"/api/accounts/{aid}/toggle", {})
        check("POST toggle 停用", code == 200 and d.get("enabled") is False)
        code, d = http("POST", base + f"/api/accounts/{aid}/toggle", {})
        check("POST toggle 再启用", code == 200 and d.get("enabled") is True)

        # 签到任务（假凭据，应跑完但不成功）
        code, d = http("POST", base + "/api/checkin", {})
        check("POST 发起签到返回 task_id", code == 200 and d.get("task_id"))
        tid = d.get("task_id")

        # 轮询状态
        finished = False
        last = {}
        for _ in range(120):
            code, s = http("GET", base + f"/api/checkin/status?task_id={tid}")
            last = s
            if s.get("finished"):
                finished = True
                break
            time.sleep(0.5)
        check("签到任务能完成", finished)
        check("签到有结果返回", isinstance(last.get("results"), list) and len(last["results"]) == 1)

        # 不存在的任务
        code, d = http("GET", base + "/api/checkin/status?task_id=xxx")
        check("不存在的 task 返回 404", code == 404)

        # 删除
        code, d = http("DELETE", base + f"/api/accounts/{aid}")
        check("DELETE 删除账号", code == 200 and d.get("ok"))
        code, d = http("GET", base + "/api/accounts")
        check("删除后列表为空", d["accounts"] == [])

        # 删除不存在
        code, d = http("DELETE", base + "/api/accounts/nonexist")
        check("DELETE 不存在返回 404", code == 404)

        # ---------------- 登录接口（真实调用米游社） ----------------
        print("\n[A2] 扫码登录接口（真实请求米游社 passport）")
        code, d = http("POST", base + "/api/login/start", {"platform": "mihoyo"})
        check("POST 创建二维码", code == 200 and d.get("session_id") and d.get("ticket"))
        check("返回二维码 URL", "user.mihoyo.com" in (d.get("qr_url") or ""))
        sid = d.get("session_id")
        ticket = d.get("ticket")

        code, d = http("POST", base + "/api/login/poll",
                       {"session_id": sid, "ticket": ticket})
        check("未扫码状态为 Created", code == 200 and d.get("status") == "Created")

        # 不支持的平台
        code, d = http("POST", base + "/api/login/start", {"platform": "kuro"})
        check("非米游社平台明确拒绝", code == 400 and d.get("unsupported") is True)

        # 不存在的会话
        code, d = http("POST", base + "/api/login/poll",
                       {"session_id": "nosuch", "ticket": "x"})
        check("不存在的登录会话返回 404", code == 404)

        # 二维码静态资源可访问
        try:
            with urllib.request.urlopen(base + "/qrcode.min.js", timeout=10) as r:
                js = r.read().decode("utf-8", "replace")
            check("本地二维码库可加载", "QRCode" in js or "qrcode" in js.lower())
        except Exception as e:
            check("本地二维码库可加载", False, str(e))

        # ---------------- 浏览器登录接口 ----------------
        print("\n[A3] 浏览器登录接口（启动真实浏览器）")
        code, d = http("POST", base + "/api/login/browser/start", {"platform": "kuro"})
        if code == 200 and d.get("session_id"):
            check("启动浏览器登录会话", True)
            check("返回登录页 URL", "kurobbs.com" in (d.get("login_url") or ""))
            bsid = d["session_id"]

            # 立即轮询：此时应 Waiting（未登录）
            code, d = http("POST", base + "/api/login/browser/poll", {"session_id": bsid})
            check("未登录状态为 Waiting", code == 200 and d.get("status") == "Waiting")

            # 取消
            code, d = http("POST", base + "/api/login/browser/cancel", {"session_id": bsid})
            check("取消登录会话", code == 200 and d.get("ok"))

            # 取消后再轮询应 404
            code, d = http("POST", base + "/api/login/browser/poll", {"session_id": bsid})
            check("取消后会话失效", code == 404)
        else:
            # 无浏览器环境时不应崩溃，应给出明确错误
            check("无浏览器时优雅报错", code == 502 and d.get("error"))
            print(f"     （本机无浏览器或启动失败：{d.get('error')}）")

        # 不支持的平台
        code, d = http("POST", base + "/api/login/browser/start", {"platform": "nosuch"})
        check("浏览器登录拒绝未知平台", code == 400)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


# ---------------------------------------------------------------- B. 前端绑定
def test_frontend():
    print("\n[B] 前端按钮绑定 / 功能实现")
    p = os.path.join(ROOT, "web", "index.html")
    html = open(p, encoding="utf-8").read()

    # 1) 每个带 id 的【静态】按钮，都必须在 JS 的 addEventListener 或选择器里出现
    #    （动态模板里的 ${...} 由事件委托统一处理，单独在下面验证）
    btn_ids = re.findall(r'<button[^>]*id="([^"]+)"', html)
    static_ids = [b for b in btn_ids if "${" not in b]
    check("静态按钮数量 ≥ 5", len(static_ids) >= 5, f"实际 {len(static_ids)}")

    for bid in static_ids:
        bound = (f'$("{bid}").addEventListener' in html
                 or f'getElementById("{bid}")' in html)
        check(f'按钮 #{bid} 有事件绑定', bound)

    # 1b) 动态卡片按钮 → 必须有事件委托
    has_dynamic = any("${" in b for b in btn_ids)
    check("存在动态卡片按钮", has_dynamic)
    check("动态按钮通过事件委托绑定",
          'account-list").addEventListener("click"' in html
          and 'closest("button[data-act]")' in html)

    # 2) 关键函数都已定义
    required_funcs = [
        "load", "renderStats", "renderList", "doCheckin", "pollTask",
        "openModal", "closeModal", "saveAccount", "deleteAccount",
        "toggleAccount", "api", "toast",
    ]
    for fn in required_funcs:
        check(f"函数 {fn}() 已定义", re.search(rf"function\s+{fn}\s*\(", html)
              or re.search(rf"const\s+{fn}\s*=", html))

    # 3) 卡片按钮事件委托（4 种动作都要有分支）
    for act in ["sign", "edit", "toggle", "del"]:
        check(f'卡片动作 "{act}" 有处理分支', f'act === "{act}"' in html)

    # 4) API 路径与后端一致
    for path in ["/api/accounts", "/api/checkin", "/api/checkin/status"]:
        check(f"前端调用 {path}", path in html)

    # 5) 关键交互细节
    check("回车保存已支持", 'e.key === "Enter"' in html)
    check("ESC 关闭弹窗", 'e.key === "Escape"' in html)
    check("点击遮罩关闭", 'e.target.id === "modal"' in html)
    check("删除有二次确认", "confirm(" in html)
    check("签到按钮防重复点击", "disabled = true" in html)
    check("平台切换更新凭据提示", "updateCredLabel" in html)

    # 6) 三平台选项齐全
    for pf in ["mihoyo", "kuro", "yanyun"]:
        check(f'平台选项 {pf}', f'value="{pf}"' in html)

    # 7) 样式：无外部依赖（离线可用）
    check("无外链 CSS/JS（离线可用）",
          "http://" not in html.split("<script>")[0].replace("http://127.0.0.1", ""))
    check("无 CDN 引用", "cdn." not in html and "unpkg" not in html and "jsdelivr" not in html)

    # 8) 凭据获取帮助面板
    check("有「如何获取」面板", 'id="help-toggle"' in html and 'id="help-steps"' in html)
    check("帮助面板有折叠绑定", '"help-toggle").addEventListener' in html)
    for pf in ["mihoyo", "kuro", "yanyun"]:
        check(f"帮助内容含 {pf}", re.search(rf"\b{pf}\s*:\s*\{{", html) is not None)
    check("帮助随平台切换刷新", 'HELP[p] || HELP.mihoyo' in html)
    check("帮助含风险提示字段", "help-warn" in html and "warn:" in html)

    # 9) 自动登录（扫码）
    check("有「登录获取」按钮", 'id="btn-login-start"' in html)
    check("登录按钮有绑定", '"btn-login-start").addEventListener' in html)
    check("有二维码容器", 'id="qr-canvas"' in html and 'id="qr-wrap"' in html)
    check("引入本地二维码库", '/qrcode.min.js' in html)
    check("登录轮询逻辑存在", "loginPollTimer" in html and "stopLoginPoll" in html)
    check("手动填写为备用（有折叠）",
          'id="manual-toggle"' in html and "openManual" in html)
    for st in ["Scanned", "Confirmed", "Expired"]:
        check(f"处理登录状态 {st}", st in html)
    check("登录成功自动关闭并刷新",
          "closeModal(); await load();" in html)

    # 10) 浏览器登录（官方登录页 + 自动抓 cookie）
    for fn in ["startBrowserLogin", "startMihoyoQR", "startLogin", "onLoginSuccess"]:
        check(f"登录函数 {fn}()", f"function {fn}" in html)
    check("有浏览器登录状态区", 'id="browser-wrap"' in html)
    check("按平台分流", 'if (platform === "mihoyo") return startMihoyoQR' in html)
    check("调用浏览器登录接口", "/api/login/browser/start" in html)
    check("调用浏览器轮询接口", "/api/login/browser/poll" in html)
    check("支持取消登录", "/api/login/browser/cancel" in html)


def main():
    print("=" * 66)
    print("可视化界面测试")
    print("=" * 66)
    test_frontend()
    test_api()
    print("\n" + "=" * 66)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项:")
        for f in FAIL:
            print("  -", f)
    print("=" * 66)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
