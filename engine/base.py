"""签到适配器基类与公共工具。

仅依赖 Python 标准库（urllib），无需 pip install，方便本地端与云函数直接跑。
若希望用 requests，把 _Session 换成 requests.Session 即可，对外接口保持一致。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class CheckinResult:
    platform: str
    success: bool
    message: str = ""
    raw: Optional[dict] = None  # 平台原始返回，便于排错


class _Response:
    def __init__(self, body: bytes, status: int):
        self._body = body
        self.status_code = status

    def json(self) -> dict:
        return json.loads(self._body.decode("utf-8", "replace"))

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", "replace")


class _Session:
    """极简 requests 兼容层（urllib 实现）。"""

    def __init__(self):
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
        }

    def _req(self, method, url, data=None, params=None, headers=None, timeout=15):
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)
        h = dict(self.headers)
        if headers:
            h.update(headers)
        # urllib 要求头值为 latin-1 可编码；非 ASCII（如误粘中文）做安全替换避免崩溃
        h = {
            k: (v.encode("latin-1", "replace").decode("latin-1") if isinstance(v, str) else v)
            for k, v in h.items()
        }
        if isinstance(data, str):
            body = data.encode("utf-8")
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode("utf-8")
        elif data is None:
            body = None
        else:
            body = data
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _Response(resp.read(), resp.status)
        except urllib.error.HTTPError as e:
            return _Response(e.read(), e.code)
        except Exception as e:  # 网络错误等，交给上层转成失败结果
            raise

    def get(self, url, **kw):
        return self._req("GET", url, **kw)

    def post(self, url, **kw):
        return self._req("POST", url, **kw)


def get_session() -> _Session:
    return _Session()


class CheckinAdapter:
    """所有平台适配器的基类。

    子类必须实现 _do_sign()，并约定好 account 字典里需要哪些字段
    （例如 mihoyo 需要 "cookie"，kuro 需要 "token"）。
    """

    name = "base"
    # 该平台账号配置所需的必填字段，用于本地端做配置校验。
    required_fields: tuple[str, ...] = ()

    def __init__(self, account: dict):
        self.account = account or {}
        self.session = get_session()

    def _validate(self) -> Optional[str]:
        missing = [f for f in self.required_fields if not self.account.get(f)]
        if missing:
            return f"账号配置缺少字段: {missing}"
        return None

    def sign_in(self) -> CheckinResult:
        err = self._validate()
        if err:
            return CheckinResult(platform=self.name, success=False, message=err)
        try:
            return self._do_sign()
        except Exception as e:  # 网络/解析异常统一成失败结果，不抛出
            return CheckinResult(
                platform=self.name, success=False, message=f"执行异常: {e}"
            )

    def _do_sign(self) -> CheckinResult:
        raise NotImplementedError
