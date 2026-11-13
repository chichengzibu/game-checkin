#!/usr/bin/env python3
"""统一启动入口（源码运行 & PyInstaller 打包共用）。

    python app_main.py --port 8899        # 源码
    GameCheckin.exe --port 8899           # 打包后

为什么需要单独入口（而不是直接打包 web/server.py）：
    1. 打包后 __file__ 指向 PyInstaller 临时解包目录 _MEIPASS，
       账号库 / 主密钥绝不能放那里（重启即丢 = 逼用户重新登录）。
       这里把数据目录固定到 exe 同目录，并用 sys.frozen 判定。
    2. 把程序根加进 sys.path，保证 engine / store / service 以顶层包导入。
    3. 提前 setdefault 环境变量，让 store.local_store 与 web.server
       拿到完全一致的路径（一条数据路径，避免解密失败）。
"""

from __future__ import annotations

import os
import sys


def base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE = base_dir()
if BASE not in sys.path:
    sys.path.insert(0, BASE)

# 所有用户数据都放在 exe / 项目根的 config/ 下，且可被环境变量覆盖
os.environ.setdefault("CHECKIN_VAULT_PATH", os.path.join(BASE, "config", "vault.json"))
os.environ.setdefault("CHECKIN_MASTER_KEY_FILE", os.path.join(BASE, "config", "master.key"))
os.environ.setdefault("CHECKIN_GAMES_CONFIG", os.path.join(BASE, "config", "games.json"))


def main() -> None:
    from web.server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
