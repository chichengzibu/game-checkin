"""凭据加密：AES-256-GCM。

为什么不直接用明文 / 不复用 requests：
    凭据是 cookie / token，泄露等于账号被盗。落盘和上传都必须加密。
    优先用 cryptography(如果云函数环境装了)，否则回退纯标准库实现。

标准库回退方案说明：
    Python 标准库没有 AES。为了"零依赖也能跑"，这里提供一个基于
    HMAC-SHA256 的流式加密（Encrypt-then-MAC 结构）。
    它安全性弱于 AES-GCM（没有硬件加速、密钥流由 HMAC 派生），
    但对"防止数据库/文件被直接翻看"这一目标足够，且完全零依赖。
    生产环境请装 cryptography，代码会自动优先使用 AES-GCM。

统一接口：
    enc = get_cipher(master_key)
    blob = enc.encrypt("secret string")   # -> 可存字符串
    text = enc.decrypt(blob)              # -> 原文
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets

# ---- 优先：AES-256-GCM（若安装了 cryptography） ----
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

    _HAS_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAS_CRYPTO = False


class _AesGcmCipher:
    algo = "aes-256-gcm"

    def __init__(self, master_key: bytes):
        # 用主密钥派生固定 32 字节密钥
        self.key = hashlib.sha256(master_key).digest()
        self.aead = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = self.aead.encrypt(nonce, plaintext.encode("utf-8"), None)
        return "gcm$" + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, blob: str) -> str:
        if not blob.startswith("gcm$"):
            raise ValueError("不是 AES-GCM 密文")
        raw = base64.urlsafe_b64decode(blob[4:])
        nonce, ct = raw[:12], raw[12:]
        return self.aead.decrypt(nonce, ct, None).decode("utf-8")


class _HmacStreamCipher:
    """零依赖回退：HMAC-SHA256 计数器模式 + HMAC 认证（Encrypt-then-MAC）。

    结构： keystream = HMAC(key_enc, nonce || counter)
           ciphertext = plaintext XOR keystream
           tag = HMAC(key_mac, nonce || ciphertext)
    存储： "hmac$" + base64(nonce || ciphertext || tag)
    """

    algo = "hmac-sha256-ctr"

    def __init__(self, master_key: bytes):
        k = hashlib.sha256(master_key).digest()
        self.key_enc = hmac.new(k, b"enc", hashlib.sha256).digest()
        self.key_mac = hmac.new(k, b"mac", hashlib.sha256).digest()

    def _keystream(self, nonce: bytes, n: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < n:
            block = hmac.new(
                self.key_enc, nonce + counter.to_bytes(8, "big"), hashlib.sha256
            ).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:n])

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode("utf-8")
        nonce = os.urandom(16)
        ks = self._keystream(nonce, len(data))
        ct = bytes(a ^ b for a, b in zip(data, ks))
        tag = hmac.new(self.key_mac, nonce + ct, hashlib.sha256).digest()
        return "hmac$" + base64.urlsafe_b64encode(nonce + ct + tag).decode()

    def decrypt(self, blob: str) -> str:
        if not blob.startswith("hmac$"):
            raise ValueError("不是 HMAC 密文")
        raw = base64.urlsafe_b64decode(blob[5:])
        nonce, tag = raw[:16], raw[-32:]
        ct = raw[16:-32]
        expect = hmac.new(self.key_mac, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):  # 防篡改
            raise ValueError("密文被篡改或密钥错误")
        ks = self._keystream(nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8")


def get_cipher(master_key: str):
    """按优先级返回可用加密器。"""
    kb = master_key.encode("utf-8") if isinstance(master_key, str) else master_key
    return _AesGcmCipher(kb) if _HAS_CRYPTO else _HmacStreamCipher(kb)


def encrypt_credential(credential: dict, master_key: str) -> str:
    return get_cipher(master_key).encrypt(json.dumps(credential, ensure_ascii=False))


def decrypt_credential(blob: str, master_key: str) -> dict:
    return json.loads(get_cipher(master_key).decrypt(blob))


def gen_master_key() -> str:
    """生成一个随机主密钥（部署时写入环境变量 MASTER_KEY）。"""
    return secrets.token_urlsafe(32)
