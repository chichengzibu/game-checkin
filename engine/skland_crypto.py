"""森空岛（Skland）签名所需的加密原语 —— 全部纯标准库实现，无需 pip。

为什么需要这些：
    森空岛 Web API 的每次请求都要带 `sign` 头，算法是
        sign = md5( hex( hmac_sha256(cred_token, path+body+timestamp+header_ca_json) ) )
    hmac_sha256 / md5 标准库直接有；而首次登录要生成设备指纹 `dId`，
    需要 RSA-PKCS1v1.5 / DES-ECB / AES-128-CBC / gzip 组合出一个加密包发给
    数美（fp-it.portal101.cn）。pycryptodome 在本项目里不可用（引擎层坚持零依赖），
    所以这里用纯 Python 实现三个原语，并用标准测试向量自检。

    所有实现都只用于「构造发给森空岛官方 API 的登录/签名请求」，
    与本地账号库加密（store/crypto.py）无关。

对外接口：
    md5_hex(s: str|bytes) -> str
    hmac_sha256_hex(key: str, data: str) -> str
    request_sign(cred_token, path, body_or_query, timestamp, header_ca) -> str
    generate_device_id(...) -> str     # 见 engine/skland.py 调用
    selftest() -> bool                 # 标准向量自检
"""

from __future__ import annotations

import base64
import functools
import gzip
import hashlib
import hmac
import json
import os
import struct
import time
import uuid

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

def md5_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def hmac_sha256_hex(key: str, data: str) -> str:
    return hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# DES / 3DES 单密钥 ECB（无填充，调用方已手动补 \x00）
# 标准实现，测试向量：key=133457799BBCDFF1, plain=0123456789ABCDEF
#                    -> cipher=85E813540F0AB405
# ---------------------------------------------------------------------------

_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
       62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
       57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
       61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
       38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
       36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
       34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
      16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
      2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
        26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
        51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_SBOX = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
  0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
  15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
  3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
  13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
  13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
  1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
  13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
  3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
  14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
  11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
  10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
  4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
  13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
  6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
  1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
  2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

def _permute(block: int, table: list, in_bits: int) -> int:
    out = 0
    for pos in table:
        out = (out << 1) | ((block >> (in_bits - pos)) & 1)
    return out


def _des_subkeys(key8: bytes) -> list:
    k = int.from_bytes(key8, "big")
    k56 = _permute(k, _PC1, 64)
    c, d = (k56 >> 28) & 0x0FFFFFFF, k56 & 0x0FFFFFFF
    keys = []
    for s in _SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & 0x0FFFFFFF
        d = ((d << s) | (d >> (28 - s))) & 0x0FFFFFFF
        keys.append(_permute((c << 28) | d, _PC2, 56))
    return keys


def _des_crypt_block(block: int, keys: list) -> int:
    ip = _permute(block, _IP, 64)
    l, r = (ip >> 32) & 0xFFFFFFFF, ip & 0xFFFFFFFF
    for key in keys:
        exp = _permute(r, _E, 32)
        x = exp ^ key
        out = 0
        for i in range(8):
            six = (x >> (42 - 6 * i)) & 0x3F
            row = ((six & 0x20) >> 4) | (six & 1)
            col = (six >> 1) & 0xF
            out = (out << 4) | _SBOX[i][row * 16 + col]
        out = _permute(out, _P, 32)
        l, r = r, l ^ out
    return _permute((r << 32) | l, _FP, 64)


def des_ecb_encrypt(data: bytes, key8: bytes) -> bytes:
    """DES-ECB，key 取前 8 字节；data 由调用方保证是 8 的倍数。"""
    key8 = key8[:8].ljust(8, b"\x00")
    keys = _des_subkeys(key8)
    out = bytearray()
    for i in range(0, len(data), 8):
        blk = int.from_bytes(data[i:i + 8], "big")
        out += _des_crypt_block(blk, keys).to_bytes(8, "big")
    return bytes(out)


# ---------------------------------------------------------------------------
# AES-128-CBC（标准实现；测试向量 FIPS-197）
# key=000102...0f, plain=001122...eeff -> 69c4e0d86a7b0430d8cdb78070b4c55a
# ---------------------------------------------------------------------------

_SBOX_AES = [
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(x: int) -> int:
    return ((x << 1) ^ 0x11B) & 0xFF if x & 0x80 else (x << 1) & 0xFF

def _aes_expand_key(key: bytes) -> list:
    nk, nr = 4, 10
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX_AES[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w

def _aes_encrypt_block(block: bytes, w: list) -> bytes:
    # AES state 是列优先：state[r][c] = block[4*c + r]
    s = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            s[r][c] = block[4 * c + r]

    def add_round(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[4 * rnd + c][r]

    add_round(0)
    for rnd in range(1, 11):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX_AES[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        if rnd != 10:
            for c in range(4):
                a = [s[r][c] for r in range(4)]
                s[0][c] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
                s[1][c] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
                s[2][c] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
                s[3][c] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])
        add_round(rnd)
    return bytes(s[r][c] for c in range(4) for r in range(4))

def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(key) == 16 and len(iv) == 16 and len(data) % 16 == 0
    w = _aes_expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _aes_encrypt_block(blk, w)
        out += prev
    return bytes(out)


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 加密（公钥来自固定 DER；只需加密，不需要私钥）
# ---------------------------------------------------------------------------

def _der_read_len(buf: bytes, i: int) -> tuple:
    first = buf[i]; i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    return int.from_bytes(buf[i:i + n], "big"), i + n

def _der_next(buf: bytes, i: int, tag: int) -> tuple:
    assert buf[i] == tag, f"DER tag 期望 {tag:02x} 实得 {buf[i]:02x}"
    length, i = _der_read_len(buf, i + 1)
    return buf[i:i + length], i + length

def rsa_encrypt_pkcs1_v15(message: bytes, pubkey_der: bytes) -> bytes:
    """解析 SubjectPublicKeyInfo DER，取 (n,e)，做 PKCS1 v1.5 type-2 加密。"""
    spki, _ = _der_next(pubkey_der, 0, 0x30)
    alg, i = _der_next(spki, 0, 0x30)   # AlgorithmIdentifier（跳过）
    bitstr, _ = _der_next(spki, i, 0x03)
    assert bitstr[0] == 0x00
    rsa_der = bitstr[1:]
    seq, _ = _der_next(rsa_der, 0, 0x30)
    n_b, i = _der_next(seq, 0, 0x02)
    e_b, _ = _der_next(seq, i, 0x02)
    n = int.from_bytes(n_b, "big")
    e = int.from_bytes(e_b, "big")
    k = (n.bit_length() + 7) // 8
    if len(message) > k - 11:
        raise ValueError("RSA 明文过长")
    while True:
        ps = bytearray(os.urandom(k - len(message) - 3))
        ps = bytes(b or 1 for b in ps)          # 非零填充
        em = b"\x00\x02" + ps + b"\x00" + message
        m = int.from_bytes(em, "big")
        if m < n:
            break
    c = pow(m, e, n)
    return c.to_bytes(k, "big")


# ---------------------------------------------------------------------------
# 设备指纹 dId（数美 fp-it.portal101.cn /deviceprofile/v4）
# ---------------------------------------------------------------------------

# 字段名 -> (DES key, 是否加密, 混淆后字段名)
_DES_RULE = {
    "appId": ("uy7mzc4h", 1, "xx"), "box": (None, 0, "jf"),
    "canvas": ("snrn887t", 1, "yk"), "clientSize": ("cpmjjgsu", 1, "zx"),
    "organization": ("78moqjfc", 1, "dp"), "os": ("je6vk6t4", 1, "pj"),
    "platform": ("pakxhcd2", 1, "gm"), "plugins": ("v51m3pzl", 1, "kq"),
    "pmf": ("2mdeslu3", 1, "vw"), "protocol": (None, 0, "protocol"),
    "referer": ("y7bmrjlc", 1, "ab"), "res": ("whxqm2a7", 1, "hf"),
    "rtype": ("x8o2h2bl", 1, "lo"), "sdkver": ("9q3dcxp2", 1, "sc"),
    "status": ("2jbrxxw4", 1, "an"), "subVersion": ("eo3i2puh", 1, "ns"),
    "svm": ("fzj3kaeh", 1, "qr"), "time": ("q2t3odsk", 1, "nb"),
    "timezone": ("1uv05lj5", 1, "as"), "tn": ("x9nzj1bp", 1, "py"),
    "trees": ("acfs0xo4", 1, "pi"), "ua": ("k92crp1t", 1, "bj"),
    "url": ("y95hjkoo", 1, "cf"), "version": (None, 0, "version"),
    "vpw": ("r9924ab5", 1, "ca"),
}
_DES_TARGET = {
    "protocol": 102, "organization": "UWXspnCCJN4sfYlNfqps",
    "appId": "default", "os": "web", "version": "3.0.0", "sdkver": "3.0.0",
    "box": "", "rtype": "all", "subVersion": "1.0.0", "time": 0,
}
_BROWSER_ENV = {
    "plugins": ("MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,"
                "MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1"),
    "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"),
    "canvas": "259ffe69", "timezone": -480, "platform": "Win32",
    "url": "https://www.skland.com/", "referer": "",
    "res": "1920_1080_24_1.25",
    "clientSize": "0_0_1080_1920_1920_1080_1920_1080", "status": "0011",
}
_RSA_PUB_DER = base64.b64decode(
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoin"
    "PkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sK"
    "mwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRBy"
    "fRsK2gdl7llqCwIDAQAB")
_FP_URL = "https://fp-it.portal101.cn/deviceprofile/v4"


def _get_tn(data: dict) -> str:
    out = ""
    for k in sorted(data):
        v = data[k]
        if isinstance(v, int):
            out += str(v * 10000)
        elif isinstance(v, dict):
            out += _get_tn(v)
        else:
            out += str(v) if v else ""
    return out


def _apply_des_rules(data: dict) -> dict:
    out = {}
    for k, v in data.items():
        key, enc, alias = _DES_RULE.get(k, (None, 0, k))
        if key and enc == 1:
            raw = str(v).encode("utf-8")
            pad = 8 - (len(raw) % 8)
            raw += b"\x00" * pad
            out[alias] = base64.b64encode(des_ecb_encrypt(raw, key.encode())).decode()
        else:
            out[alias] = v
    return out


def generate_device_id(http_post, timeout: int = 20) -> str:
    """生成并返回森空岛设备指纹 dId（形如 'B<base64...>'）。

    http_post(url, json_payload, headers, timeout) -> dict
        由调用方（适配器）注入 HTTP 实现，便于离线 mock 测试。
    """
    tstr = time.strftime("%Y%m%d%H%M%S")
    v = f"{tstr}{md5_hex(str(uuid.uuid4()))}00"
    suffix = hashlib.md5(f"smsk_web_{v}".encode()).digest()[:7].hex()
    smid = f"{v}{suffix}0"

    uid = str(uuid.uuid4())
    pri_id = hashlib.md5(uid.encode()).digest()[:8]
    ep = base64.b64encode(rsa_encrypt_pkcs1_v15(uid.encode(), _RSA_PUB_DER)).decode()

    now_ms = int(time.time() * 1000)
    browser = dict(_BROWSER_ENV)
    browser["vpw"] = str(uuid.uuid4())
    browser["trees"] = str(uuid.uuid4())
    browser["svm"] = now_ms
    browser["pmf"] = now_ms
    target = dict(_DES_TARGET)
    target["smid"] = smid
    target.update(browser)
    target["tn"] = md5_hex(_get_tn(target))

    json_str = json.dumps(_apply_des_rules(target), separators=(",", ":"))
    compressed = gzip.compress(json_str.encode("utf-8"), compresslevel=2)
    key = pri_id.hex().encode("ascii")  # 16 字节 ASCII -> AES-128
    b64 = base64.b64encode(compressed)
    pad = 16 - (len(b64) % 16)
    if pad < 16:
        b64 += b"\x00" * pad
    p = 16 - (len(b64) % 16)
    b64 += bytes([p]) * p                # PKCS7
    encrypted = aes_cbc_encrypt(b64, key, b"0102030405060708").hex()

    payload = {
        "appId": "default", "compress": 2, "data": encrypted, "encode": 5,
        "ep": ep, "organization": "UWXspnCCJN4sfYlNfqps", "os": "web",
    }
    resp = http_post(_FP_URL, payload,
                     {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
                     timeout)
    if resp.get("code") != 1100:
        raise RuntimeError(f"设备指纹获取失败: {resp.get('message') or resp.get('code')}")
    return "B" + resp["detail"]["deviceId"]


# ---------------------------------------------------------------------------
# 森空岛请求签名（核心，最常用）
# ---------------------------------------------------------------------------

def request_sign(cred_token: str, path: str, body_or_query: str,
                 timestamp: int, header_ca: dict) -> str:
    """与官方实现一致：
        s = path + body_or_query + str(timestamp) + json.dumps(header_ca, separators=(',',':'))
        sign = md5( hmac_sha256_hex(cred_token, s) )
    """
    ca = json.dumps(header_ca, separators=(",", ":"))
    s = f"{path}{body_or_query}{timestamp}{ca}"
    return md5_hex(hmac_sha256_hex(cred_token, s))


# ---------------------------------------------------------------------------
# 自检：标准测试向量
# ---------------------------------------------------------------------------

def selftest() -> bool:
    # DES 标准向量
    des = des_ecb_encrypt(bytes.fromhex("0123456789ABCDEF"),
                          bytes.fromhex("133457799BBCDFF1"))
    assert des.hex().upper() == "85E813540F0AB405", f"DES 向量失败: {des.hex()}"
    # AES-128 标准向量（FIPS-197）
    aes = aes_cbc_encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),
                          bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                          b"\x00" * 16)
    assert aes.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", f"AES 向量失败: {aes.hex()}"
    # HMAC-SHA256 RFC 4231 测试向量 1
    hm = hmac.new(b"key", b"The quick brown fox jumps over the lazy dog", hashlib.sha256).hexdigest()
    assert hm == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    # RSA：用固定公钥加密后长度应为 128 字节（1024-bit key）
    pub_der = base64.b64decode(
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoin"
        "PkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sK"
        "mwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRBy"
        "fRsK2gdl7llqCwIDAQAB")
    ct = rsa_encrypt_pkcs1_v15(b"skland-selftest", pub_der)
    assert len(ct) == 128, f"RSA 密文长度异常: {len(ct)}"
    return True


if __name__ == "__main__":
    ok = selftest()
    print("skland_crypto 自检", "通过 ✅" if ok else "失败 ❌")
