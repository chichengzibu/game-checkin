"""共享签到引擎。

同一套适配器既可在本地 Python 客户端运行，也可被微信云开发云函数 import。
新增平台：在 engine/ 下写一个继承 CheckinAdapter 的模块，并在 REGISTRY 注册即可。

IMPLEMENTATION_STATUS 是「发布说明 / Web UI / 签到调度」共用的唯一事实来源：
    stable         已实现、已实机核对，参与自动签到
    unimplemented  未实现，签到服务直接短路，不发起网络请求
    placeholder    占位示例
"""

from .base import CheckinAdapter, CheckinResult, get_session
from .mihoyo import MihoyoAdapter
from .kuro import KuroAdapter
from .netease import YanyunAdapter
from .others import GenericStubAdapter

# 平台名 -> 适配器类。账号配置里用 "platform" 字段指定。
REGISTRY = {
    "mihoyo": MihoyoAdapter,
    "kuro": KuroAdapter,
    "yanyun": YanyunAdapter,
    "stub": GenericStubAdapter,
}

# ⚠️ 燕云十六声：当前只完成了「唤起微信小程序」这个辅助功能。
# engine/netease.py 里的签到协议是按公开资料写的实验代码，从未用真实
# access_token 端到端验证过（探活只证明端点存在、无 token 时返回"未登录"），
# 也没有可用的 token 获取 / 刷新链路。因此明确标记为「未实现」：
# 签到服务会跳过它并给出说明，避免让用户误以为已经签到成功。
IMPLEMENTATION_STATUS = {
    "mihoyo": "stable",
    "kuro": "stable",
    "yanyun": "unimplemented",
    "stub": "placeholder",
}

STATUS_TEXT = {
    "stable": "已实现",
    "unimplemented": "未实现",
    "placeholder": "占位示例",
    "unknown": "未知",
}

UNIMPLEMENTED_HINT = {
    "yanyun": (
        "燕云十六声签到【未实现】：现有协议代码未经真实 access_token 验证，"
        "不参与自动签到；「唤起小程序」仅供抓包参考"
    ),
}


def platform_status(platform: str) -> str:
    return IMPLEMENTATION_STATUS.get(platform, "unknown")


def status_text(platform: str) -> str:
    return STATUS_TEXT.get(platform_status(platform), "未知")


def is_implemented(platform: str) -> bool:
    return platform_status(platform) == "stable"


def unimplemented_hint(platform: str) -> str:
    return UNIMPLEMENTED_HINT.get(
        platform, f"平台 {platform} 签到未实现，暂不参与自动签到"
    )


def get_adapter(platform: str, account: dict) -> CheckinAdapter:
    cls = REGISTRY.get(platform)
    if cls is None:
        raise KeyError(f"未知平台: {platform}，可选 {list(REGISTRY)}")
    return cls(account)
