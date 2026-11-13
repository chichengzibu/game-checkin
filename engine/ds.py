"""米游社(miHoYo) 动态签名 DS 生成。

⚠️ 重要：miHoYo 的 DS 盐值会随客户端版本轮换，下面给的是长期使用的经典 WEB 盐。
若运行时返回 -1/-100 等签名错误，需要按当前官方 App/网页版本的算法重新核对盐值与拼接方式。
参考实现见社区项目（如 cvrjs/mihoyo 系列），但请以你抓包到的真实请求为准。
"""

import hashlib
import random
import time

# 经典 Web 端盐（历史长期可用）。新版 App 端盐不同，需实机核对。
WEB_SALT = "xV8v4Qu54lUKrEYFZkJhB8bi6Wr4u9p7"
# 部分接口使用的移动端盐（如 e2023 系列活动），预留。
MOBILE_SALT = "t0qEgfub2bkY6o0a"


def gen_ds(body: str = "", salt: str = WEB_SALT) -> str:
    """生成 DS 头。

    DS 格式： "<timestamp>,<random>,<md5(salt+timestamp+random+body)>"
    - GET 请求 body 传 ""（用空串拼，不要传 query）
    - POST 请求 body 传序列化后的请求体字符串
    """
    t = str(int(time.time()))
    r = str(random.randint(100000, 200000))
    c = hashlib.md5(f"{salt}{t}{r}{body}".encode("utf-8")).hexdigest()
    return f"{t},{r},{c}"
