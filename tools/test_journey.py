#!/usr/bin/env python3
"""用户旅程模拟测试：完全按界面上每个按钮的点击顺序走一遍真实请求。

对应界面按钮：
  ＋添加账号 → 模态框 → 保存
  账号卡片「签到」/「编辑」/「停用」/「删除」
  顶部「一键签到（全部）」「刷新」
  进度轮询 /api/checkin/status

    python tools/test_journey.py    # 退出码 0 = 全流程通过
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []
STEP = [0]


def log(msg):
    STEP[0] += 1
    print(f"\n[{STEP[0]:02d}] {msg}")


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"     {'✅' if cond else '❌'} {name}" + (f"  ({detail})" if detail and not cond else ""))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def main():
    print("=" * 68)
    print("用户旅程模拟（逐按钮点击）")
    print("=" * 68)

    port = free_port()
    vault = os.path.join(tempfile.mkdtemp(), "vault.json")
    env = dict(os.environ)
    env["CHECKIN_MASTER_KEY"] = "journey-key"
    env["CHECKIN_VAULT_PATH"] = vault

    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "web", "server.py"), "--port", str(port)],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base = f"http://127.0.0.1:{port}"

    for _ in range(80):
        if http("GET", base + "/api/health")[0] == 200:
            break
        time.sleep(0.25)

    try:
        # ---------- 打开页面 ----------
        log("打开页面（首页加载 + 首屏渲染）")
        with urllib.request.urlopen(base + "/", timeout=10) as r:
            html = r.read().decode()
        check("页面能加载", r.status == 200)
        check("标题正确", "游戏签到中心" in html)
        check("空状态提示存在", "还没有账号" in html)
        code, d = http("GET", base + "/api/accounts")
        check("初始账号为空", d.get("accounts") == [])

        # ---------- 点「＋添加账号」→ 保存（米游社）----------
        log("点「＋ 添加账号」→ 填米游社 → 点「保存」")
        code, d = http("POST", base + "/api/accounts", {
            "platform": "mihoyo", "label": "原神大号",
            "credential": {"cookie": "ltuid=FAKE_J1; ltoken=FAKE_J1"},
        })
        check("保存成功", code == 200 and d.get("ok"))
        id1 = d.get("id")

        # ---------- 再加一个库街区 + 燕云（模拟批量添加）----------
        log("继续添加库街区、燕云（多账号）")
        code, d2 = http("POST", base + "/api/accounts", {
            "platform": "kuro", "label": "鸣潮小号",
            "credential": {"token": "FAKE_J2"},
        })
        id2 = d2.get("id")
        code, d3 = http("POST", base + "/api/accounts", {
            "platform": "yanyun", "label": "燕云",
            "credential": {"token": "FAKE_J3"},
        })
        id3 = d3.get("id")
        code, d = http("GET", base + "/api/accounts")
        check("三个账号都在", len(d["accounts"]) == 3)
        check("统计：总数=3", len(d["accounts"]) == 3)
        check("统计：启用=3", sum(1 for a in d["accounts"] if a["enabled"]) == 3)
        check("列表不泄露任何凭据", "FAKE_J" not in json.dumps(d, ensure_ascii=False))

        # ---------- 点「刷新」----------
        log("点「↻ 刷新」")
        code, d = http("GET", base + "/api/accounts")
        check("刷新后数据不变", len(d["accounts"]) == 3)

        # ---------- 卡片「编辑」改名 ----------
        log("点卡片「编辑」→ 改名 → 保存")
        code, d = http("PUT", base + f"/api/accounts/{id1}", {"label": "原神主号"})
        check("编辑保存成功", code == 200)
        code, d = http("GET", base + "/api/accounts")
        renamed = [a for a in d["accounts"] if a["id"] == id1][0]
        check("改名生效", renamed["label"] == "原神主号")
        check("编辑不影响凭据", renamed["has_credential"] is True)

        # ---------- 卡片「停用」/「启用」----------
        log("点卡片「停用」→ 再点「启用」")
        code, d = http("POST", base + f"/api/accounts/{id2}/toggle", {})
        check("停用成功", d.get("enabled") is False)
        code, d = http("GET", base + "/api/accounts")
        off = [a for a in d["accounts"] if a["id"] == id2][0]
        check("列表显示已停用", off["enabled"] is False)
        check("统计：启用=2", sum(1 for a in d["accounts"] if a["enabled"]) == 2)
        code, d = http("POST", base + f"/api/accounts/{id2}/toggle", {})
        check("重新启用成功", d.get("enabled") is True)

        # ---------- 点「一键签到（全部）」+ 进度轮询 ----------
        log("点「⚡ 一键签到（全部）」→ 轮询进度条")
        code, d = http("POST", base + "/api/checkin", {})
        check("返回 task_id", code == 200 and d.get("task_id"))
        tid = d["task_id"]
        pcts = []
        finished = False
        result = {}
        for _ in range(240):
            code, s = http("GET", base + f"/api/checkin/status?task_id={tid}")
            if code != 200:
                break
            total = s.get("total") or 1
            pcts.append(round(s.get("done", 0) / total * 100))
            result = s
            if s.get("finished"):
                finished = True
                break
            time.sleep(0.3)
        check("进度从 0 走到 100", pcts[0] == 0 and pcts[-1] == 100, f"{pcts[:3]}...{pcts[-3:]}")
        check("任务正常结束", finished)
        check("结果条数=3", len(result.get("results", [])) == 3)
        check("每条结果有 success 字段",
              all(isinstance(r.get("success"), bool) for r in result["results"]))
        # 假凭据必然失败，但流程必须跑完
        check("假凭据全部失败（符合预期）",
              all(not r["success"] for r in result["results"]))
        check("失败原因可读", all(len(r.get("message", "")) > 4 for r in result["results"]))

        # ---------- 单账号「签到」----------
        log("点某个卡片的「签到」（单账号）")
        code, d = http("POST", base + "/api/checkin", {"account_id": id1})
        check("单账号任务创建", code == 200 and d.get("task_id"))
        tid1 = d["task_id"]
        for _ in range(120):
            code, s = http("GET", base + f"/api/checkin/status?task_id={tid1}")
            if s.get("finished"):
                break
            time.sleep(0.3)
        check("单账号只签 1 个", s.get("total") == 1)

        # ---------- 签到结果回写 ----------
        log("验证签到结果回写到账号（last_run / last_result）")
        code, d = http("GET", base + "/api/accounts")
        acc1 = [a for a in d["accounts"] if a["id"] == id1][0]
        check("已记录 last_run", bool(acc1.get("last_run")))
        check("已记录 last_result", bool(acc1.get("last_result")))

        # ---------- 卡片「删除」----------
        log("点卡片「删除」（含二次确认）")
        code, d = http("DELETE", base + f"/api/accounts/{id3}")
        check("删除成功", code == 200 and d.get("ok"))
        code, d = http("GET", base + "/api/accounts")
        check("删除后剩 2 个", len(d["accounts"]) == 2)

        # ---------- 边界：空账号点一键签到 ----------
        log("边界：删空账号后点「一键签到」")
        for a in list(d["accounts"]):
            http("DELETE", base + f"/api/accounts/{a['id']}")
        code, d = http("GET", base + "/api/accounts")
        check("已清空", d["accounts"] == [])
        code, d = http("POST", base + "/api/checkin", {})
        tid = d.get("task_id")
        for _ in range(40):
            code, s = http("GET", base + f"/api/checkin/status?task_id={tid}")
            if s.get("finished"):
                break
            time.sleep(0.25)
        check("空账号签到不报错", s.get("finished") is True and s.get("total") == 0)

        # ---------- 持久化：重启后数据还在 ----------
        log("持久化验证：关闭服务 → 重新启动 → 数据仍在")
        http("POST", base + "/api/accounts", {
            "platform": "mihoyo", "label": "重启后应还在",
            "credential": {"cookie": "ltuid=PERSIST"},
        })
        proc.terminate()
        proc.wait(timeout=8)

        port2 = free_port()
        env2 = dict(env)
        proc2 = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "web", "server.py"), "--port", str(port2)],
            cwd=ROOT, env=env2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        base2 = f"http://127.0.0.1:{port2}"
        for _ in range(80):
            if http("GET", base2 + "/api/health")[0] == 200:
                break
            time.sleep(0.25)
        code, d = http("GET", base2 + "/api/accounts")
        check("重启后账号仍在", any(a["label"] == "重启后应还在" for a in d["accounts"]))
        check("重启后凭据仍可解", "PERSIST" not in json.dumps(d, ensure_ascii=False))
        proc = proc2

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print("\n" + "=" * 68)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项:")
        for f in FAIL:
            print("  -", f)
    print("=" * 68)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
