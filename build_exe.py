#!/usr/bin/env python3
"""把本地 Web 版打包成 Windows exe（PyInstaller --onedir）。

    python -m pip install pyinstaller
    python build_exe.py

产物：dist/GameCheckin/GameCheckin.exe （双击即可，自动打开浏览器）

设计要点：
    - 静态资源 index.html / qrcode.min.js 用 --add-data 带进 web/ 子目录
    - 账号库、主密钥、游戏表都在 exe 同目录 config/，运行时生成，
      **绝不打包进 exe**（否则会把本机真实账号带出去）
    - 打包后做一次「用户数据泄漏」检查，发现问题立即报错
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
NAME = "GameCheckin"
DIST = os.path.join(ROOT, "dist", NAME)


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("缺少 PyInstaller，请先执行：python -m pip install pyinstaller")
        return 1

    sep = os.pathsep  # Windows 为 ';'，类 Unix 为 ':'
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onedir", "--console",
        "--name", NAME,
        "--add-data", f"web/index.html{sep}web",
        "--add-data", f"web/qrcode.min.js{sep}web",
        "--hidden-import", "store.cloud_store",
        "--hidden-import", "engine.games_config",
        "--hidden-import", "engine.ds",
        "app_main.py",
    ]
    print("打包命令：", " ".join(cmd))
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        print("PyInstaller 打包失败")
        return r.returncode

    # 附一份说明（README 不含任何凭据）
    src_readme = os.path.join(ROOT, "README.md")
    if os.path.isfile(src_readme):
        shutil.copy2(src_readme, os.path.join(DIST, "README.md"))

    # ---- 安全闸：exe 目录里绝不允许出现任何用户数据 ----
    forbidden = []
    for base, _dirs, files in os.walk(DIST):
        for fn in files:
            low = fn.lower()
            if low in ("vault.json", "master.key", "games.json") or \
               low.endswith((".log", ".key", ".pem", ".tmp")):
                forbidden.append(os.path.relpath(os.path.join(base, fn), DIST))
    if forbidden:
        print("❌ 打包目录里发现用户数据文件，禁止交付：")
        for f in forbidden:
            print("   -", f)
        return 2

    exe = os.path.join(DIST, NAME + (".exe" if os.name == "nt" else ""))
    print("✅ 打包完成：", exe)
    print("   账号库将于首次运行时创建在 exe 同目录 config/ 下")
    print("   安全闸：未发现 vault / master.key / 日志被打包 ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
