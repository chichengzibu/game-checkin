#!/usr/bin/env python3
"""生成「只含程序本体」的 GitHub 发布目录，并做敏感信息扫描。

    python prepare_release.py            # 生成 release/
    python prepare_release.py --verify   # 只扫描已生成的 release/，不重建

为什么用白名单而不是 .gitignore：
    .gitignore 是「黑名单」，任何一个新产生的用户文件（新日志、新缓存、
    抓包样本）都可能被漏掉。发布目录用显式白名单复制，物理隔离，
    工作区里的账号库 / 主密钥 / 日志 / 提示词根本不会被拷进来。

绝不进入 release/ 的内容：
    config/vault.json、config/master.key、config/games.json
    logs/、*.log、*.key、.env*、dist/、build/、*.spec
    .workbuddy/、memory/、*prompt*、*提示词*
    tools/diag_*、probe_*、verify_*（开发期脚本，会读本机真实账号库）
"""

from __future__ import annotations

import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "release")

# 根目录下允许的文件（显式列出）
ROOT_FILES = [
    "README.md", "requirements.txt", "app_main.py", "service.py",
    "build_exe.py", "prepare_release.py",
]

# 目录 -> 允许的扩展名（None 表示只要 .py）
DIRS: dict[str, set[str] | None] = {
    "engine": None,
    "store": None,
    "local": None,
    "web": {".py", ".html", ".js", ".css"},
    "cloud": {".py", ".json", ".txt"},
    "miniprogram": {".js", ".json", ".wxss", ".wxml", ".png", ".jpg", ".svg"},
}

# tools/ 只放「纯 mock / 临时库」的回归测试，显式白名单
TOOLS_FILES = [
    "selftest_engine.py", "selftest_store.py", "test_web.py",
    "test_journey.py", "test_credential_refresh.py", "test_stage_a.py",
]

RELEASE_GITIGNORE = """# 发布仓库自身的忽略规则（用户数据永不入库）
config/vault.json
config/master.key
config/games.json
logs/
*.log
*.key
*.pem
*.tmp
.env
.env.*
dist/
build/
__pycache__/
*.py[cod]
.workbuddy/
*prompt*
*提示词*
"""

# 敏感特征：命中即判定为「疑似用户数据」，直接失败
FORBIDDEN_NAMES = {
    "vault.json", "master.key", "games.json", ".env", "credentials.json",
}
FORBIDDEN_DIRS = {"logs", ".workbuddy", "dist", "build", "__pycache__"}
FORBIDDEN_NAME_PARTS = ("prompt", "提示词", "memory", "备份", "backup")
CONTENT_MARKERS = [
    # 拼接而非字面量：否则扫描器会在自己源码里命中自己（自指误报）
    "local-" + "demo-key-" + "please-change",   # 本机真实主密钥
    "credential_enc" + '\": \"' + "gcm$",        # 真实加密凭据密文
    "credential_enc" + '\": \"' + "hmac$",
]
CONTENT_PATTERNS = [
    re.compile(r"v2_[A-Za-z0-9_\-]{30,}"),                 # 真实 stoken
    re.compile(r"cookie_token(?:_v2)?=[A-Za-z0-9_\-]{30,}"),
    re.compile(r"ltuid(?:_v2)?=\d{8,}"),                   # 真实米游社 UID
    re.compile(r"account_id(?:_v2)?=\d{8,}"),
    re.compile(r"access_token=[A-Za-z0-9_\-]{30,}"),
]
# 这些是明确的假值 / 文档占位，不算泄漏
SAFE_VALUES = ("fake", "test", "selftest", "xxx", "example", "placeholder",
               "12345678", "abcdefgh", "your-cloud-env-id", "touristappid")


def _allowed(fn: str, exts: set[str] | None) -> bool:
    if exts is None:
        return fn.endswith(".py")
    return os.path.splitext(fn)[1].lower() in exts


def build() -> None:
    if os.path.isdir(OUT):
        # 保留 .git：用户可能已在发布目录里 git init / commit 过，
        # 重建白名单内容不能顺手销毁本地提交历史。
        for name in os.listdir(OUT):
            if name == ".git":
                continue
            p = os.path.join(OUT, name)
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
    else:
        os.makedirs(OUT)

    copied = 0
    for fn in ROOT_FILES:
        src = os.path.join(ROOT, fn)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(OUT, fn))
            copied += 1

    for d, exts in DIRS.items():
        src_dir = os.path.join(ROOT, d)
        if not os.path.isdir(src_dir):
            continue
        for base, dirs, files in os.walk(src_dir):
            dirs[:] = [x for x in dirs if x not in FORBIDDEN_DIRS]
            for fn in files:
                if not _allowed(fn, exts):
                    continue
                rel = os.path.relpath(os.path.join(base, fn), src_dir)
                dst = os.path.join(OUT, d, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(os.path.join(base, fn), dst)
                copied += 1

    tools_out = os.path.join(OUT, "tools")
    os.makedirs(tools_out, exist_ok=True)
    for fn in TOOLS_FILES:
        src = os.path.join(ROOT, "tools", fn)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(tools_out, fn))
            copied += 1

    with open(os.path.join(OUT, ".gitignore"), "w", encoding="utf-8") as f:
        f.write(RELEASE_GITIGNORE)

    # 空 config/ 目录 + 示例（示例里没有任何真实值）
    cfg = os.path.join(OUT, "config")
    os.makedirs(cfg, exist_ok=True)
    with open(os.path.join(cfg, "games.example.json"), "w", encoding="utf-8") as f:
        f.write('{\n  "mihoyo": {},\n  "kuro": {}\n}\n')
    with open(os.path.join(cfg, "README.md"), "w", encoding="utf-8") as f:
        f.write(
            "# 运行时数据目录\n\n"
            "程序首次运行会在此生成 `vault.json`（加密凭据）与 `master.key`（主密钥）。\n"
            "这两个文件**永远不会**被提交到 GitHub（见 .gitignore）。\n"
            "`games.example.json` 是可选的游戏表覆盖示例。\n"
        )
    copied += 2
    print(f"已复制 {copied} 个文件到 {OUT}")


def verify() -> int:
    if not os.path.isdir(OUT):
        print("release/ 不存在，请先运行 python prepare_release.py")
        return 1
    problems: list[str] = []
    files: list[str] = []
    for base, dirs, names in os.walk(OUT):
        # .git 是发布仓库自身，合法；跳过遍历，避免把对象文件当成源码扫描
        dirs[:] = [d for d in dirs if d != ".git"]
        for d in list(dirs):
            low = d.lower()
            if low in FORBIDDEN_DIRS or any(p in low for p in FORBIDDEN_NAME_PARTS):
                problems.append(f"禁止的目录: {os.path.relpath(os.path.join(base, d), OUT)}")
                dirs.remove(d)
        for fn in names:
            p = os.path.join(base, fn)
            rel = os.path.relpath(p, OUT)
            files.append(rel)
            low = fn.lower()
            if low in FORBIDDEN_NAMES or low.endswith((".log", ".key", ".pem", ".tmp", ".pyc")):
                problems.append(f"禁止的文件: {rel}")
            if any(part in low for part in FORBIDDEN_NAME_PARTS):
                problems.append(f"疑似提示词/记忆文件: {rel}")
            try:
                with open(p, "r", encoding="utf-8") as f:
                    text = f.read()
            except (UnicodeDecodeError, OSError):
                continue
            for m in CONTENT_MARKERS:
                if m in text:
                    problems.append(f"命中敏感标记 {m!r}: {rel}")
            for pat in CONTENT_PATTERNS:
                hit = pat.search(text)
                if hit and not any(s in hit.group(0).lower() for s in SAFE_VALUES):
                    problems.append(f"疑似真实凭据 {hit.group(0)[:40]!r}: {rel}")

    print(f"扫描 {len(files)} 个发布文件")
    if problems:
        print("❌ 敏感信息扫描未通过：")
        for p in problems:
            print("   -", p)
        return 2
    print("✅ 敏感信息扫描通过：未发现账号库、主密钥、日志、提示词或真实凭据")
    print("发布文件清单：")
    for rel in sorted(files):
        print("   ", rel)
    return 0


if __name__ == "__main__":
    if "--verify" not in sys.argv:
        build()
    raise SystemExit(verify())
