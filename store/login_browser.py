"""浏览器登录：调起真实浏览器打开官方登录页，用户手动登录，程序自动抓 cookie。

为什么这样做（关键设计决策）：
    库街区 / 燕云 都有极验、风控、微信授权，任何"模拟登录"都不可靠且违法风险高。
    正确做法 = 打开官方登录页 + 用户自己正常登录 + 程序读浏览器 cookie。
    这样：验证码用户自己过、风控认为是真人、登录方式完全是官方的。
    用户视角：点按钮 → 弹出登录窗 → 登录 → 自动完成。

实现：Chrome DevTools Protocol（CDP），纯标准库（websocket 用最小实现）。
    1. 启动 Chrome/Edge：--remote-debugging-port + 独立 user-data-dir
    2. 通过 CDP 打开目标登录页
    3. 轮询 Network.getAllCookies，直到看到目标 cookie 出现
    4. 返回 cookie 串，清理进程

支持平台：
    mihoyo   https://user.mihoyo.com/  （也可直接扫码）
    kuro     https://www.kurobbs.com/login
    yanyun   https://cg.163.com/static/game/yysls  （燕云云游戏页；登录后由 CDP 网络层自动拦截 access_token）
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

# 各平台：登录页 + 判定登录成功的关键 cookie 名
#   storage_keys：token 存在 localStorage 时用的 key（库街区就是这样）
PLATFORMS = {
    "mihoyo": {
        "login_url": "https://user.mihoyo.com/",
        "cookie_names": ["ltuid_v2", "ltoken_v2", "ltuid", "ltoken"],
        "storage_keys": [],
        "label": "米游社",
        "hint": "在打开的页面里扫码或输账号密码登录",
    },
    "kuro": {
        "login_url": "https://www.kurobbs.com/login",
        # 库街区网页把登录态放在 localStorage.auth_token，不是 cookie
        "cookie_names": ["token"],
        "storage_keys": ["auth_token", "token", "Authorization"],
        "label": "库街区",
        "hint": "在打开的页面里用手机号+验证码登录（验证码由你手动完成）",
    },
    "yanyun": {
        # 燕云每日签到的 access_token 是【微信小程序】令牌，网页/云游戏页拿不到，
        # 故 yanyun 不再走浏览器自动登录（server 已对 browser/start 显式拒绝）。
        # 此 entry 仅保留给 tools/selftest_yanyun.py 构造 BrowserLoginSession 以单测
        # _capture_token 正则（URL/JSON/cookie/单引号 四种形态），不参与真实登录流程。
        "login_url": "https://www.yysls.cn/",
        "cookie_names": ["access_token", "token", "NTES_SESS", "P_INFO"],
        "storage_keys": ["access_token", "token"],
        "token_param": "access_token",
        "label": "燕云十六声",
        "hint": "燕云请走微信小程序抓包后手动粘贴 access_token（网页自动抓取不可行）",
    },
    "skland": {
        # 森空岛：登录后由页面上下文 fetch info/hg 拿 data.content（即签到 token）。
        # 该接口对 www.skland.com 放行 CORS 且 Allow-Credentials=true，
        # 所以页面内 fetch(credentials:'include') 可带上登录态拿到 content。
        "login_url": "https://www.skland.com/",
        "cookie_names": [],
        "storage_keys": [],
        "fetch_token_url": "https://web-api.skland.com/account/info/hg",
        "label": "森空岛",
        "hint": "在打开的页面里用鹰角账号登录（手机号/验证码或扫码）；登录后程序自动读取凭证，无需手动复制",
    },
}

# ---------------- 燕云小程序唤起（Windows 微信 明文 URL Scheme） ----------------
# access_token 是微信小程序令牌：本机微信打开小程序后，用户在小程序里签到触发请求，
# 用抓包工具（Fiddler/Charles/Stream）拿到 access_token 再粘回程序即可。
# 唤起小程序优先自动发现：扫描本机微信已缓存小程序（WeChat Files/<wxid>/Applet/<appid>/info.json）
# 拿到燕云真实 appid，自己拼 weixin:// scheme 直接打开——用户无需建桌面快捷方式、无需手填 appid。
# 仍可用 YANYUN_MINIAPP_APPID 覆盖（显式优先）。
YANYUN_MINIAPP_APPID = os.environ.get("YANYUN_MINIAPP_APPID", "")
YANYUN_MINIAPP_PATH = os.environ.get("YANYUN_MINIAPP_PATH", "")

# 用户粘贴的小程序链接解析结果（由 /api/login/yanyun/set-link 写入）：
#   YANYUN_LINK_APPID：从链接里解出的 appid，可直接 weixin:// 唤起（最稳）
#   YANYUN_LINK_RAW  ：解不出 appid 的原始 #小程序:// 链接，只能尽力用系统协议打开
YANYUN_LINK_APPID = ""
YANYUN_LINK_RAW = ""


def _try_decode_miniprogram_code(code: str) -> str | None:
    """尽力从 #小程序:// 的 code 段解出 appid。能解出来就返回 appid，否则 None。

    #小程序://名称/code 的 code 是 base64 变体：微信可能用了与标准不同的字母表
    （例如大小写对调），解码后形如 `appid\\x00path`。这里尝试多种字母表假设，
    命中 `wx...` 即视为 appid。解不出返回 None（该 code 是服务端令牌，离线无法还原）。
    """
    import base64 as _b64
    code = (code or "").strip()
    if not code:
        return None
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    lowfirst = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    for alpha in (std, lowfirst):
        tr = str.maketrans(alpha, std)
        s = code.translate(tr)
        s += "=" * (-len(s) % 4)
        for fn in (_b64.b64decode, _b64.urlsafe_b64decode):
            try:
                raw = fn(s)
            except Exception:
                continue
            head = raw.split(b"\x00")[0]
            if head.startswith(b"wx") and 8 <= len(head) <= 30:
                return head.decode("ascii", "ignore")
    return None


def parse_miniprogram_link(link: str) -> tuple[str, str | None]:
    """解析用户粘贴的小程序链接，返回 (kind, value)。

    kind:
      "appid" -> value 是 appid，可直接拼 weixin:// 唤起（最佳）
      "raw"   -> value 是原始链接，只能尽力用系统协议打开（微信可能接管 #小程序://）
    支持形态：
      - weixin://dl/business/?appid=wx....   直接拿到 appid
      - #小程序://名称/code                 先尝试解出 appid，失败则作为 raw 链接尽力打开
      - 纯 appid 字符串                      直接当作 appid
    """
    link = (link or "").strip()
    if not link:
        return ("none", None)
    # 形态一：weixin://dl/business/?appid=wxXXXX
    m = re.search(r"appid=([A-Za-z0-9_-]{8,})", link)
    if m:
        return ("appid", m.group(1))
    # 形态二：#小程序://名称/code
    if "#小程序://" in link:
        m = re.search(r"#小程序://[^/]+/(.+)$", link)
        if m:
            appid = _try_decode_miniprogram_code(m.group(1).strip())
            if appid:
                return ("appid", appid)
        return ("raw", link)
    # 兜底：看起来就是个 appid
    if re.match(r"^wx[A-Za-z0-9_-]{6,}$", link):
        return ("appid", link)
    return ("raw", link)


def set_yanyun_link(link: str) -> dict:
    """记录用户粘贴的小程序链接，并尽力解析出 appid。返回诊断结果供前端展示。"""
    global YANYUN_LINK_APPID, YANYUN_LINK_RAW
    kind, value = parse_miniprogram_link(link)
    if kind == "appid" and value:
        YANYUN_LINK_APPID = value
        YANYUN_LINK_RAW = ""
        return {"ok": True, "kind": "appid", "appid": value,
                "hint": f"已从链接解析出 appid（{value}），点「登录获取」即可直接唤起燕云小程序。"}
    if kind == "raw" and value:
        YANYUN_LINK_APPID = ""
        YANYUN_LINK_RAW = value
        return {
            "ok": True, "kind": "raw", "link": value,
            "hint": ("已记录该小程序链接。#小程序:// 是微信私有短链，Windows 无法像普通网址一样直接唤起它；"
                     "点「登录获取」时程序会自动把链接复制到剪贴板并打开微信，"
                     "你只需在微信里（可发给「文件传输助手」）按 Ctrl+V 粘贴发送再点一下，即可打开小程序。"
                     "打开过一次后微信会缓存它，本程序就能自动发现 appid，以后一键直达。"),
        }
    return {"ok": False, "kind": "none", "hint": "链接为空或格式无法识别。"}


def _copy_to_clipboard(text: str) -> bool:
    """把文本放进 Windows 剪贴板（纯标准库 ctypes，无第三方依赖）。

    用途：#小程序:// 是微信私有短链，系统层面无法直接唤起；把链接复制到剪贴板，
    用户只需在微信里 Ctrl+V 发送并点开即可（微信会把它渲染成可点击的小程序卡片）。
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes
        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        u32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        u32.OpenClipboard.argtypes = [wintypes.HWND]
        u32.OpenClipboard.restype = wintypes.BOOL
        u32.EmptyClipboard.restype = wintypes.BOOL
        u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        u32.SetClipboardData.restype = wintypes.HANDLE
        u32.CloseClipboard.restype = wintypes.BOOL
        k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k32.GlobalAlloc.restype = wintypes.HGLOBAL
        k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        k32.GlobalLock.restype = wintypes.LPVOID
        k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        data = text.encode("utf-16-le") + b"\x00\x00"
        h = k32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not h:
            return False
        ptr = k32.GlobalLock(h)
        if not ptr:
            k32.GlobalFree(h)
            return False
        ctypes.memmove(ptr, data, len(data))
        k32.GlobalUnlock(h)
        if not u32.OpenClipboard(None):
            k32.GlobalFree(h)
            return False
        u32.EmptyClipboard()
        u32.SetClipboardData(CF_UNICODETEXT, h)
        u32.CloseClipboard()
        return True
    except Exception:
        return False


# 微信 Windows 客户端可执行名：新版（3.x）叫 Weixin.exe，旧版叫 WeChat.exe，两者都认。
# 这是「未能唤起」的核心坑——本机装的是 D:\Soft\Weixin\Weixin.exe，只认 WeChat.exe 会全盘漏掉。
WEIXIN_EXE_NAMES = ("Weixin.exe", "WeChat.exe")


def _extract_wechat_exe(cand: str) -> str | None:
    """给定注册表/快捷方式里读到的路径（可能是 .exe 也可能是目录），返回真实存在的微信 exe。

    只会返回文件名为 `Weixin.exe` / `WeChat.exe` 的可执行文件，避免把其它 .exe（如
    DeepSeek Harness.exe）误判成微信。兼容 `DisplayIcon` 形如 `C:\\...\\Weixin.exe,0`
    （带逗号序号），以及 `InstallLocation` 只是目录的情况。
    """
    if not cand:
        return None
    cand = cand.split(",")[0].strip().strip('"').strip()
    if not cand:
        return None
    names_lower = tuple(n.lower() for n in WEIXIN_EXE_NAMES)
    if cand.lower().endswith(".exe"):
        # 只有真的是微信 exe 才直接认；否则退化为在其所在目录里找微信
        if os.path.basename(cand).lower() in names_lower and os.path.isfile(cand):
            return cand
        d = os.path.dirname(cand)
    else:
        d = cand
    if os.path.isdir(d):
        for alt in WEIXIN_EXE_NAMES:
            p = os.path.join(d, alt)
            if os.path.isfile(p):
                return p
    return None


def _start_uri(uri: str) -> bool:
    """唤起一个 URI scheme（如 weixin://）。多策略兜底，返回是否成功。

    os.startfile 在部分 Windows 上对自定义协议会抛 WinError 1155，
    因此失败后再用 `cmd /c start`（最稳，能处理自定义协议）与 explorer 兜底。
    """
    try:
        os.startfile(uri)
        return True
    except Exception:
        pass
    try:
        subprocess.run(
            ["cmd", "/c", "start", "", uri],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, shell=False,
        )
        return True
    except Exception:
        pass
    try:
        subprocess.run(
            ["explorer", uri],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        return True
    except Exception:
        pass
    return False


def _read_url_shortcut(url_path: str) -> str | None:
    """读取 .url 文件里的 URL=（微信小程序桌面快捷方式有时是 .url）。"""
    try:
        with open(url_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.lower().startswith("url="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return None


def find_yanyun_shortcut(name_hint: str = "燕云") -> str | None:
    """扫描桌面找燕云小程序的桌面快捷方式（.lnk 或 .url，两种都支持）。

    匹配规则宽松：文件名含提示词，或快捷方式目标里含 weixin:// / 燕云 / 已知 appid。
    （微信生成的名字不一定含「燕云」，也可能是 .url，所以两层都扫。）
    也可用环境变量 YANYUN_DESKTOP_SHORTCUT 指定精确路径。
    """
    env_path = os.environ.get("YANYUN_DESKTOP_SHORTCUT")
    if env_path and os.path.isfile(env_path):
        return env_path
    roots = []
    roots.append(os.path.expanduser("~/Desktop"))
    roots.append(os.path.expandvars(r"%USERPROFILE%\Desktop"))
    roots.append(os.path.expandvars(r"%PUBLIC%\Desktop"))
    od = os.environ.get("OneDrive")
    if od:
        roots.append(os.path.join(od, "Desktop"))
    seen = set()
    for root in roots:
        if not root or root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        try:
            files = [f for f in os.listdir(root)
                     if f.lower().endswith((".lnk", ".url"))]
        except Exception:
            continue
        # 先按文件名匹配
        for f in files:
            if name_hint.lower() in f.lower():
                return os.path.join(root, f)
        # 再按目标内容匹配（文件名不含燕云，但目标是微信小程序）
        for f in files:
            p = os.path.join(root, f)
            tgt = (read_shortcut_target(p) if f.lower().endswith(".lnk")
                   else _read_url_shortcut(p))
            if tgt and ("weixin://" in tgt.lower() or name_hint.lower() in tgt.lower()):
                return p
    return None


def _wechat_from_process() -> str | None:
    """正在运行的微信进程直接取 exe 路径（最准：用户此刻多半开着微信）。"""
    if os.name != "nt":
        return None
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Process -Filter \"Name='WeChat.exe' OR Name='Weixin.exe'\" "
             "-ErrorAction SilentlyContinue | Select-Object -First 1).ExecutablePath"],
            capture_output=True, text=True, errors="ignore", timeout=10,
        )
        p = (out.stdout or "").strip().strip('"')
        if p and os.path.isfile(p) and p.lower().endswith(WEIXIN_EXE_NAMES):
            return p
    except Exception:
        pass
    return None


def _wechat_from_registry() -> str | None:
    """从卸载注册表动态查找微信安装位置（不写死路径）。"""
    if os.name != "nt":
        return None
    try:
        import winreg
    except Exception:
        return None
    bases = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, base in bases:
        try:
            with winreg.OpenKey(hive, base) as k:
                count = winreg.QueryInfoKey(k)[0]
                for i in range(count):
                    name = winreg.EnumKey(k, i)
                    try:
                        with winreg.OpenKey(k, name) as sk:
                            disp = winreg.QueryValueEx(sk, "DisplayName")[0]
                    except Exception:
                        continue
                    if not disp or ("wechat" not in disp.lower()
                                   and "微信" not in disp):
                        continue
                    for val in ("InstallLocation", "DisplayIcon", "UninstallString"):
                        try:
                            v = winreg.QueryValueEx(sk, val)[0]
                        except Exception:
                            continue
                        exe = _extract_wechat_exe(v)
                        if exe:
                            return exe
        except Exception:
            continue
    # 微信自己的注册表键（3.x 写在这里，最可靠）：HKCU/HKLM\Software\Tencent\WeChat\InstallPath
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE,
                 winreg.HKEY_LOCAL_MACHINE):
        for sub in (r"Software\Tencent\WeChat",
                    r"SOFTWARE\WOW6432Node\Tencent\WeChat"):
            try:
                with winreg.OpenKey(hive, sub) as k:
                    try:
                        ip = winreg.QueryValueEx(k, "InstallPath")[0]
                    except Exception:
                        continue
                    exe = _extract_wechat_exe(ip)
                    if exe:
                        return exe
            except Exception:
                continue
    return None


def _wechat_from_startmenu() -> str | None:
    """在开始菜单快捷方式里找微信（动态扫描，不写死路径）。"""
    if os.name != "nt":
        return None
    roots = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs"),
    ]
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, _, files in os.walk(root):
                for f in files:
                    fl = f.lower()
                    if not fl.endswith(".lnk"):
                        continue
                    # 只对有微信/wechat/weixin 字样的快捷方式才调 powershell 读目标，
                    # 否则开始菜单几百个 .lnk 每个都起一个 powershell 会让检测卡 30s+
                    if not ("微信" in f or "wechat" in fl or "weixin" in fl):
                        continue
                    tgt = read_shortcut_target(os.path.join(dirpath, f)) or ""
                    exe = _extract_wechat_exe(tgt)
                    if exe:
                        return exe
        except Exception:
            continue
    return None


_WECHAT_EXE_CACHE = None  # 微信安装位置本次进程内基本不变，缓存避免每次检测都扫 30s


def find_wechat_exe() -> str | None:
    """动态检测本机是否安装了微信 Windows 客户端（不写死安装路径）。

    检测顺序：① 正在运行的微信进程直接取路径；② 卸载注册表（按 DisplayName 找 WeChat，
    读 InstallLocation / DisplayIcon）；③ 开始菜单快捷方式；④ 桌面微信/小程序快捷方式反推；
    ⑤ PATH。任一命中即返回 exe 路径；都找不到返回 None（代表本机没装微信客户端）。
    结果进程内缓存，避免每次点击都重新全盘扫描。
    """
    global _WECHAT_EXE_CACHE
    if _WECHAT_EXE_CACHE is not None:
        return _WECHAT_EXE_CACHE
    if os.name != "nt":
        return None
    # 各动态探测，按可靠度从高到低
    for fn in (_wechat_from_process, _wechat_from_registry,
               _wechat_from_startmenu):
        p = fn()
        if p:
            _WECHAT_EXE_CACHE = p
            return p
    # 桌面微信 / 小程序快捷方式目标反推（含 Public 桌面，本机正是靠这个找到 D:\Soft\Weixin\Weixin.exe）
    try:
        for root in [os.path.expanduser("~/Desktop"),
                     os.path.expandvars(r"%USERPROFILE%\Desktop"),
                     os.path.expandvars(r"%PUBLIC%\Desktop")]:
            if not root or not os.path.isdir(root):
                continue
            for f in os.listdir(root):
                if not f.lower().endswith((".lnk", ".url")):
                    continue
                p = os.path.join(root, f)
                tgt = (read_shortcut_target(p) if f.lower().endswith(".lnk")
                       else _read_url_shortcut(p)) or ""
                if "weixin" in tgt.lower() or "wechat" in tgt.lower():
                    exe = _extract_wechat_exe(tgt)
                    if exe:
                        _WECHAT_EXE_CACHE = exe
                        return exe
    except Exception:
        pass
    # PATH 兜底
    p = shutil.which("WeChat.exe") or shutil.which("wechat")
    if p:
        _WECHAT_EXE_CACHE = p
        return p
    _WECHAT_EXE_CACHE = None
    return None


def _wechat_files_dirs() -> list[str]:
    """本机微信文件目录（含各登录账号的小程序缓存）。"""
    env = os.environ.get("WECHAT_FILES_DIR")
    if env and os.path.isdir(env):
        return [env]
    roots = [
        os.path.expandvars(r"%USERPROFILE%\Documents\WeChat Files"),
        os.path.expandvars(r"%USERPROFILE%\WeChat Files"),
        os.path.expanduser("~/Documents/WeChat Files"),
        os.path.expanduser("~/WeChat Files"),
    ]
    dirs = []
    for r in roots:
        if r and os.path.isdir(r):
            dirs.append(r)
    return dirs


def _iter_applet_dirs() -> list[str]:
    """枚举微信里所有已缓存小程序的目录（.../Applet/<appid>）。"""
    out = []
    for wf in _wechat_files_dirs():
        # 结构 A：WeChat Files/Applet/<appid>
        top = os.path.join(wf, "Applet")
        if os.path.isdir(top):
            out.append(top)
        # 结构 B：WeChat Files/<wxid>/Applet/<appid>
        try:
            for wxid in os.listdir(wf):
                ar = os.path.join(wf, wxid, "Applet")
                if os.path.isdir(ar):
                    out.append(ar)
        except Exception:
            pass
        # 结构 C：WeChat Files/WMPF/applet/<appid>（小程序框架缓存，新版微信常见）
        wmpf = os.path.join(wf, "WMPF", "applet")
        if os.path.isdir(wmpf):
            out.append(wmpf)
    return out


def find_wechat_applet_appid(name_hint: str = "燕云") -> str | None:
    """自动从本机微信已打开过的小程序缓存里定位燕云小程序的真实 appid。

    微信把每个用过的小程序缓存在 WeChat Files/<wxid>/Applet/<appid>/info.json，
    内含 nickName。命中名称即可拿到 appid，进而程序自己拼 weixin:// scheme 直接唤起——
    **用户无需在小程序里手动「添加到桌面」，也不用手填 appid**。

    返回 appid（形如 wx........）；找不到返回 None。
    """
    hint = name_hint.lower()
    for applet_root in _iter_applet_dirs():
        try:
            entries = os.listdir(applet_root)
        except Exception:
            continue
        for appid in entries:
            cand = os.path.join(applet_root, appid)
            if not os.path.isdir(cand):
                continue
            nick = ""
            info_path = os.path.join(cand, "info.json")
            aid = appid
            if os.path.isfile(info_path):
                try:
                    with open(info_path, encoding="utf-8", errors="ignore") as f:
                        info = json.load(f)
                    nick = (info.get("nickName") or info.get("name") or "")
                    if info.get("appId"):
                        aid = info["appId"]
                except Exception:
                    pass
            if not re.match(r"^wx[a-zA-Z0-9]{6,}$", aid or ""):
                continue
            if hint in (nick + " " + (aid or "")).lower():
                return aid
    return None


def read_shortcut_target(lnk_path: str) -> str | None:
    """读取 .lnk 快捷方式的目标路径（Windows）。失败返回 None。"""
    if os.name != "nt" or not os.path.isfile(lnk_path):
        return None
    ps = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
        + lnk_path.replace("'", "''")
        + "'); $s.TargetPath"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, errors="ignore", timeout=15,
        )
        t = (out.stdout or "").strip()
        return t or None
    except Exception:
        return None


def _open_miniprogram_by_appid(appid: str, source: str,
                               detail: dict, rec) -> dict | None:
    """用 appid 拼 weixin:// 明文 Scheme 唤起小程序；成功返回结果 dict，失败返回 None。"""
    path = YANYUN_MINIAPP_PATH or "pages/index/index"
    scheme = (f"weixin://dl/business/?appid={appid}"
              f"&path={path}&env_version=release")
    if _start_uri(scheme):
        rec(source, True, True, appid)
        return {"ok": True, "opened": "miniprogram",
                "source": source, "appid": appid, "detail": detail}
    rec(source, True, False, "scheme 唤起未生效")
    return None


def open_yanyun_miniprogram() -> dict:
    """唤起燕云小程序，优先级（从最精确到最兜底）：
      1) 用户粘贴链接解出的 appid（#小程序:// 或 weixin://dl/business/?appid=）→ 直达；
      2) 环境变量 YANYUN_MINIAPP_APPID → 直达；
      3) 本机微信缓存自动发现的燕云 appid → 直达（用户打开过一次后即可，无需任何配置）；
      4) 桌面燕云快捷方式（.lnk/.url）→ 直接启动该文件（等同双击）；
      5) #小程序:// 私有短链 → 复制链接到剪贴板 + 打开微信（半自动：微信内粘贴发送点开）；
      6) 只打开微信本体，由用户手动进入；
      7) 都失败 → 返回逐层诊断。

    全程带诊断信息（detail.methods），任何一步都说明做了什么、结果如何。
    """
    detail = {"wechat": None, "auto_appid": None, "shortcut": None,
              "link": None, "methods": []}

    def rec(name, tried, ok, note=""):
        detail["methods"].append({"name": name, "tried": tried,
                                  "ok": ok, "note": note})

    if os.name != "nt":
        return {"ok": False, "error": "唤起燕云小程序仅支持 Windows（需安装微信客户端）",
                "detail": detail,
                "hint": "当前非 Windows 系统，请在 Windows 上运行本程序并安装微信客户端。"}

    # 1) 用户粘贴链接里解出的 appid（最高优先级：这是用户明确指定的小程序）
    detail["link"] = YANYUN_LINK_APPID or YANYUN_LINK_RAW or None
    if YANYUN_LINK_APPID:
        r = _open_miniprogram_by_appid(YANYUN_LINK_APPID, "link_appid",
                                       detail, rec)
        if r:
            return r
    else:
        rec("link_appid", False, False, "未从粘贴的链接解出 appid")

    # 2) 环境变量显式配置的 appid
    if YANYUN_MINIAPP_APPID:
        r = _open_miniprogram_by_appid(YANYUN_MINIAPP_APPID, "config_appid",
                                       detail, rec)
        if r:
            return r
    else:
        rec("config_appid", False, False, "未配置 YANYUN_MINIAPP_APPID")

    # 3) 自动从微信缓存发现 appid（核心：用户无需建快捷方式、无需填 appid）
    auto_appid = find_wechat_applet_appid("燕云")
    detail["auto_appid"] = auto_appid
    if auto_appid:
        r = _open_miniprogram_by_appid(auto_appid, "auto_appid", detail, rec)
        if r:
            return r
    else:
        rec("auto_appid", False, False, "微信缓存中未发现燕云小程序（多半还没在微信里打开过）")

    # 4) 桌面已有燕云快捷方式（.lnk/.url）→ 直接启动该文件，等同于用户双击
    shortcut = find_yanyun_shortcut("燕云")
    detail["shortcut"] = shortcut
    if shortcut and os.path.isfile(shortcut):
        try:
            os.startfile(shortcut)
            rec("shortcut", True, True, shortcut)
            return {"ok": True, "opened": "shortcut",
                    "path": shortcut, "detail": detail}
        except Exception as e:  # noqa: BLE001
            rec("shortcut", True, False, f"启动失败: {e}")
    else:
        rec("shortcut", False, False, "桌面未找到燕云快捷方式")

    # 5) #小程序:// 私有短链：外部程序无法直接唤起（微信没把它注册成系统协议），
    #    最可靠的做法 = 复制到剪贴板 + 打开微信，让用户在微信里粘贴发送并点开。
    #    一旦点开过，微信会缓存小程序，下次就走第 3 步自动直达。
    wechat = find_wechat_exe()
    detail["wechat"] = wechat
    if YANYUN_LINK_RAW:
        copied = _copy_to_clipboard(YANYUN_LINK_RAW)
        if wechat:
            try:
                subprocess.Popen([wechat])
            except Exception:
                pass
        rec("link_raw", True, True,
            f"已复制链接到剪贴板={copied}，打开微信={bool(wechat)}")
        return {
            "ok": True, "opened": "link_handoff", "detail": detail,
            "link": YANYUN_LINK_RAW,
            "copied": copied,
            "hint": (
                "你贴的是 #小程序:// 微信私有短链，Windows 无法像普通网址那样直接唤起它。"
                + ("已把链接复制到剪贴板并打开微信：请在微信里（可发给「文件传输助手」）按 Ctrl+V 粘贴发送，"
                   "再点一下这条消息就能打开燕云十六声。"
                   if copied else
                   "已打开微信：请手动把该链接粘贴到微信聊天里发送后点开。")
                + " 打开过一次之后，本程序会自动发现它的 appid，以后点「登录获取」即可一键直达。"
            ),
        }

    # 6) 只开微信
    if wechat:
        try:
            subprocess.Popen([wechat])
            rec("wechat", True, True, wechat)
            return {
                "ok": True, "opened": "wechat", "detail": detail,
                "hint": (
                    f"已为你打开微信客户端（{wechat}）。本机微信缓存里还没有「燕云十六声」小程序，"
                    "所以暂时无法直接跳进小程序——请这次在微信里手动打开一次「燕云十六声」并完成签到抓包；"
                    "之后微信会把小程序缓存下来，再点「登录获取」就能一键直接唤起它。"
                ),
            }
        except Exception as e:  # noqa: BLE001
            rec("wechat", True, False, f"启动失败: {e}")

    # 全失败：仍未定位到微信
    return {
        "ok": False,
        "error": "未能自动唤起燕云小程序",
        "detail": detail,
        "hint": (
            "在本机动态检测了微信客户端（运行进程 / 卸载注册表 / 微信自注册表键 / 开始菜单 / 桌面快捷方式 / PATH），"
            "均未能定位到微信可执行文件（Weixin.exe 或 WeChat.exe）——很可能本机未安装微信 Windows 客户端，"
            "或装在了极特殊的位置。解决：① 安装并登录微信 Windows 客户端；"
            "② 或在微信里打开一次「燕云十六声」小程序后重试；"
            "③ 或设 YANYUN_DESKTOP_SHORTCUT=桌面燕云快捷方式完整路径 强制指定。"
        ),
    }


BROWSER_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_browser() -> str | None:
    for p in BROWSER_CANDIDATES:
        if os.path.isfile(p):
            return p
    # PATH 里找
    for name in ("chrome", "google-chrome", "chromium", "msedge"):
        p = shutil.which(name)
        if p:
            return p
    return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------- 最小 WebSocket 客户端（仅够用于 CDP） ----------------

class _WS:
    """够用的 WebSocket 实现（文本帧 + 无掩码客户端帧）。CDP 只需这些。"""

    def __init__(self, url: str, timeout: float = 30):
        # ws://host:port/path
        assert url.startswith("ws://")
        rest = url[5:]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {hostport}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(handshake.encode())
        # 读握手响应
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WS 握手失败")
            buf += chunk

    def send(self, text: str) -> None:
        data = text.encode("utf-8")
        header = bytearray([0x81])  # FIN + text
        n = len(data)
        mask = os.urandom(4)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        def readn(n):
            buf = b""
            while len(buf) < n:
                c = self.sock.recv(n - len(buf))
                if not c:
                    raise ConnectionError("连接关闭")
                buf += c
            return buf

        b1, b2 = readn(2)
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", readn(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", readn(8))[0]
        masked = b2 & 0x80
        mask = readn(4) if masked else None
        payload = readn(length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

        if opcode == 0x8:
            raise ConnectionError("对端关闭")
        if opcode == 0x9:  # ping -> pong
            self.sock.sendall(bytes([0x8A, 0x80]) + os.urandom(4))
            return self.recv()
        return payload.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class BrowserLoginSession:
    """一次浏览器登录会话。"""

    def __init__(self, platform: str):
        self.platform = platform
        cfg = PLATFORMS[platform]
        self.cfg = cfg
        self.proc: subprocess.Popen | None = None
        self.ws: _WS | None = None
        self.port = free_port()
        self.user_data = tempfile.mkdtemp(prefix="checkin-login-")
        self.msg_id = 0
        self.started = False
        # 网络拦截抓到的 access_token 等（key -> 首次出现的 url/上下文）
        self.network_tokens: dict[str, str] = {}
        self._pending: dict[int, dict] = {}
        self._pending_lock = threading.Lock()
        self._pump_running = False
        self._pump_thread: threading.Thread | None = None

    # ---- 启动浏览器 ----
    def start(self) -> dict:
        browser = find_browser()
        if not browser:
            raise RuntimeError("未找到 Chrome / Edge 浏览器，请先安装其一")

        args = [
            browser,
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.user_data}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=Translate",
            f"--app={self.cfg['login_url']}",
        ]
        # Windows 下不弹黑框
        creationflags = 0
        if os.name == "nt":
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        self.proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

        # 等调试端口就绪
        ws_url = None
        for _ in range(80):
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/json/list", timeout=2
                ) as r:
                    tabs = json.loads(r.read().decode())
                for t in tabs:
                    if t.get("webSocketDebuggerUrl") and t.get("type") == "page":
                        ws_url = t["webSocketDebuggerUrl"]
                        break
                if ws_url:
                    break
            except Exception:
                pass
            time.sleep(0.25)

        if not ws_url:
            raise RuntimeError("浏览器调试端口未就绪")

        self.ws = _WS(ws_url)
        self.started = True
        return {
            "ok": True,
            "platform": self.platform,
            "label": self.cfg["label"],
            "hint": self.cfg["hint"],
            "login_url": self.cfg["login_url"],
        }

    # ---- CDP 调用 ----
    def _call(self, method: str, params: dict | None = None) -> dict:
        self._ensure_pump()
        self.msg_id += 1
        mid = self.msg_id
        self.ws.send(json.dumps({"id": mid, "method": method,
                                 "params": params or {}}))
        # 等后台 pump 线程把对应 id 的响应放进 _pending
        deadline = time.time() + 30
        while time.time() < deadline:
            with self._pending_lock:
                r = self._pending.pop(mid, None)
            if r is not None:
                return r
            time.sleep(0.02)
        return {"error": "timeout", "id": mid}

    def _ensure_pump(self) -> None:
        if self._pump_running:
            return
        self._pump_running = True
        self._pump_thread = threading.Thread(target=self._pump, daemon=True)
        self._pump_thread.start()

    def _pump(self) -> None:
        """后台线程：独占读取 WS，区分「命令响应」与「事件」。

        事件（Network.requestWillBeSent / responseReceived / loadingFinished）
        会实时扫描 access_token 等目标参数，不论它在 URL 还是响应体里。
        """
        try:
            while self._pump_running:
                try:
                    raw = self.ws.recv()
                except Exception:
                    return
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue

                mid = msg.get("id")
                if mid is not None:
                    with self._pending_lock:
                        self._pending[mid] = msg
                    continue

                # 事件：抓 access_token（只扫请求 URL 即可，避免与 pump 线程互锁）
                # 云游戏页查询/签到时会在 URL 里带 ?access_token=，拦截请求就能拿到
                method = msg.get("method", "")
                params = msg.get("params") or {}
                try:
                    if method == "Network.requestWillBeSent":
                        req = params.get("request") or {}
                        self._capture_token(req.get("url", ""))
                except Exception:
                    pass
        finally:
            self._pump_running = False

    _TOKEN_RE = re.compile(r'access_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.%\-]{16,})')

    def _capture_token(self, text: str) -> None:
        if not text or "access_token" not in text:
            return
        for m in self._TOKEN_RE.findall(text):
            tok = m
            # URL 里常带 & 后缀，截断
            tok = tok.split("&")[0].split('"')[0].split("'")[0]
            if len(tok) >= 16:
                self.network_tokens.setdefault(tok, text[:80])

    def get_cookies(self) -> list[dict]:
        resp = self._call("Network.getAllCookies")
        return (resp.get("result") or {}).get("cookies") or []

    def _enable_domains(self) -> None:
        """首次调用前启用 Network / Runtime 域（否则 getAllCookies 可能为空）。"""
        if getattr(self, "_domains_inited", False):
            return
        try:
            self._call("Network.enable")
        except Exception:
            pass
        try:
            self._call("Runtime.enable")
        except Exception:
            pass
        try:
            self._call("Page.enable")
        except Exception:
            pass
        self._domains_inited = True

    def get_local_storage(self) -> dict:
        """读取当前页面 origin 的 localStorage（库街区 token 存在这里）。"""
        try:
            self._enable_domains()
            resp = self._call(
                "Runtime.evaluate",
                {
                    "expression": (
                        "JSON.stringify((()=>{const o={};"
                        "try{for(let i=0;i<localStorage.length;i++){"
                        "const k=localStorage.key(i);o[k]=localStorage.getItem(k);}}"
                        "catch(e){}return o;})())"
                    ),
                    "returnByValue": True,
                    "awaitPromise": False,
                },
            )
            val = (((resp.get("result") or {}).get("result") or {}).get("value"))
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    def _cur_url(self) -> str:
        try:
            resp = self._call("Runtime.evaluate", {
                "expression": "location.href", "returnByValue": True})
            return ((resp.get("result") or {}).get("result") or {}).get("value") or ""
        except Exception:
            return ""

    def fetch_json(self, url: str) -> dict:
        """在页面上下文里带登录态 fetch 一个 JSON 接口并返回解析后的 dict。

        用于森空岛：登录态在浏览器 cookie/localStorage，页面内 fetch 才能带上；
        info/hg 对 www.skland.com 放行 CORS + credentials，故可跨子域读取。
        """
        try:
            self._enable_domains()
            # 用 async IIFE + awaitPromise，确保拿到响应体再返回
            expr = (
                "(async()=>{try{"
                "const r=await fetch(" + json.dumps(url) +
                ",{credentials:'include',headers:{'Accept':'application/json'}});"
                "return await r.text();"
                "}catch(e){return '__ERR__'+String(e)}})()"
            )
            resp = self._call("Runtime.evaluate", {
                "expression": expr, "returnByValue": True, "awaitPromise": True,
            })
            val = ((resp.get("result") or {}).get("result") or {}).get("value")
            if not val or str(val).startswith("__ERR__"):
                return {}
            return json.loads(val)
        except Exception:
            return {}

    def poll_cookies(self) -> dict:
        """检查是否已登录。返回 {status, cookies?, token?, cookie?}。"""
        if not self.started:
            return {"status": "NotStarted"}
        if self.proc and self.proc.poll() is not None:
            return {"status": "BrowserClosed"}

        try:
            self._enable_domains()
            cookies = self.get_cookies()
        except Exception as e:  # 连接断了
            return {"status": "BrowserClosed", "error": str(e)}

        wanted = set(self.cfg["cookie_names"])
        found = {}
        for c in cookies:
            if c.get("name") in wanted:
                found[c["name"]] = c.get("value")

        # 同时读 localStorage（库街区的 auth_token 在这里）
        ls_hit = {}
        keys = self.cfg.get("storage_keys") or []
        if keys:
            ls = self.get_local_storage()
            for k in keys:
                if ls.get(k):
                    ls_hit[k] = ls[k]
            # 库街区：若当前页已跳走（无 localStorage），尝试在主域再读一次
            if not ls_hit and self.platform == "kuro":
                cur = self._cur_url()
                if cur and "kurobbs.com" not in cur:
                    try:
                        self._call("Page.navigate", {"url": "https://www.kurobbs.com/"})
                        time.sleep(1.2)
                        ls = self.get_local_storage()
                        for k in keys:
                            if ls.get(k):
                                ls_hit[k] = ls[k]
                    except Exception:
                        pass

        # 森空岛：登录后 fetch info/hg，取 data.content 作为 token
        if self.platform == "skland":
            fetch_url = self.cfg.get("fetch_token_url")
            d = self.fetch_json(fetch_url) if fetch_url else {}
            content = ((d.get("data") or {}).get("content") or "") if isinstance(d, dict) else ""
            if content:
                return {"status": "Confirmed", "token": content,
                        "cookie": content, "source": "info/hg"}
            return {"status": "Waiting", "url": self._cur_url()}

        # 库街区：优先用 localStorage.auth_token
        if self.platform == "kuro":
            tok = (ls_hit.get("auth_token") or ls_hit.get("token")
                   or found.get("token"))
            if tok:
                return {"status": "Confirmed",
                        "cookies": {"auth_token": tok},
                        "token": tok, "cookie": tok,
                        "source": "localStorage" if (ls_hit.get("auth_token")
                                                     or ls_hit.get("token")) else "cookie"}
            return {"status": "Waiting", "url": self._cur_url()}

        # 米游社需要成套（ltuid+ltoken 或 v2）
        if self.platform == "mihoyo":
            has_old = "ltuid" in found and "ltoken" in found
            has_new = "ltuid_v2" in found and "ltoken_v2" in found
            if not (has_old or has_new):
                return {"status": "Waiting", "partial": list(found)}

        # 燕云：cookie / localStorage / 网络拦截 任一命中即可（access_token 最可能是网络拦截拿到的）
        if not found and ls_hit:
            k, v = next(iter(ls_hit.items()))
            return {"status": "Confirmed", "cookies": {k: v},
                    "token": v, "cookie": v, "source": "localStorage"}
        # 网络拦截抓到的 access_token 优先（这是云游戏签到的真正令牌）
        if self.network_tokens:
            tok = next(iter(self.network_tokens))
            return {"status": "Confirmed", "cookies": {"access_token": tok},
                    "token": tok, "cookie": f"access_token={tok}",
                    "source": "network"}
        if not found:
            return {"status": "Waiting", "url": self._cur_url()}

        cookie_str = "; ".join(f"{k}={v}" for k, v in found.items())
        return {"status": "Confirmed", "cookies": found, "cookie": cookie_str,
                "source": "cookie"}

    def close(self):
        self._pump_running = False
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        # 清理临时 profile
        try:
            shutil.rmtree(self.user_data, ignore_errors=True)
        except Exception:
            pass
