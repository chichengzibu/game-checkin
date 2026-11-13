"""其他平台（叠纸 / 鹰角 / 等等）通用占位适配器。

用法：当某个平台还没有专属适配器时，用 "stub" 占位，避免本地端因未知平台崩溃。
等抓到真实接口后，仿照 mihoyo.py / kuro.py 写独立适配器并在 engine/__init__.py 注册。
"""

from .base import CheckinAdapter, CheckinResult


class GenericStubAdapter(CheckinAdapter):
    name = "stub"

    def _do_sign(self) -> CheckinResult:
        return CheckinResult(
            platform=self.name,
            success=False,
            message=(
                "通用占位适配器：该平台尚未实现签到逻辑。请在 engine/ 下新增专属适配器"
                "(参考 mihoyo.py / kuro.py)，并在 REGISTRY 注册后使用。"
            ),
        )
