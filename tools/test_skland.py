#!/usr/bin/env python3
"""森空岛（Skland）适配器离线回归测试 —— 纯 mock，不联网、不碰真实账号库。

覆盖：
    1. 加密原语标准向量（DES / AES / HMAC-SHA256 / RSA）
    2. 请求签名算法（与官方实现独立重算比对）
    3. 设备指纹 dId 生成（mock 指纹服务）
    4. 认证链：grant -> cred -> binding
    5. 明日方舟签到 / 终末地签到（逐角色）
    6. 状态分类：已签 / 登录失效 / 网络瞬时 / 确定性失败
    7. token 失效短路
    8. 引擎注册表与实现状态门闸
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import skland_crypto as sc
from engine.skland import SkylandAdapter
from engine.base import (
    STATUS_OK, STATUS_ALREADY, STATUS_AUTH, STATUS_TRANSIENT, STATUS_FAILED,
)
import engine


# --------------------------------------------------------------------------
# mock 传输层
# --------------------------------------------------------------------------

class _MockAdapter(SkylandAdapter):
    """把 HTTP 调用全部换成脚本化响应，记录请求以供断言。"""

    def __init__(self, account, routes):
        super().__init__(account)
        self.routes = routes
        self.calls = []

    def _fp_post(self, url, payload, headers, timeout):
        self.calls.append(("FP", url, payload, dict(headers)))
        return self.routes.get("__fp__", {"code": 1100, "detail": {"deviceId": "TESTDEVICEID"}})

    def _json(self, method, url, *, headers=None, body=None, timeout=20):
        # 记录「真正上线的字节」：与签名所用 body 必须完全一致
        encoded = self._encode_body(body) if body is not None else ""
        self.calls.append((method, url, encoded, dict(headers or {})))
        key = url
        if url.endswith("/user/oauth2/v2/grant"):
            key = "grant"
        elif url.endswith("/generate_cred_by_code"):
            key = "cred"
        elif url.endswith("/game/player/binding"):
            key = "binding"
        elif url.endswith("/game/attendance"):
            key = "ark"
        elif url.endswith("/endfield/attendance"):
            key = "end"
        entry = self.routes.get(key)
        if entry is None:
            raise AssertionError(f"未预置的路由: {key} ({url})")
        if isinstance(entry, Exception):
            raise entry
        if callable(entry):
            return entry(data, dict(headers or {}))
        return entry


def _ok_bindings():
    return {"code": 0, "data": {"list": [
        {"appCode": "arknights", "bindingList": [
            {"gameName": "明日方舟", "gameId": 1, "uid": "100000001",
             "nickName": "博士", "channelName": "官服", "roles": []},
        ]},
        {"appCode": "endfield", "bindingList": [
            {"gameName": "终末地", "gameId": 3, "uid": "200000002",
             "nickName": "管理员", "channelName": "官服",
             "roles": [{"roleId": "r1", "serverId": "s1", "nickname": "角色A"},
                       {"roleId": "r2", "serverId": "s2", "nickname": "角色B"}]},
        ]},
    ]}}


def _base_routes(**over):
    r = {
        "grant": {"status": 0, "data": {"code": "AUTHCODE"}},
        "cred": {"code": 0, "data": {"token": "CREDTOKEN", "cred": "CREDVALUE"}},
        "binding": _ok_bindings(),
        "ark": {"code": 0, "data": {"awards": [
            {"resource": {"name": "源石"}, "count": 1}]}},
        "end": {"code": 0, "data": {"awardIds": [{"id": "a1"}],
                                    "resourceInfoMap": {"a1": {"name": "配装", "count": 3}}}},
    }
    r.update(over)
    return r


def _adapter(routes=None, account=None):
    return _MockAdapter(account or {"token": "TOKENVALUE"}, routes or _base_routes())


# --------------------------------------------------------------------------
# 1. 加密原语
# --------------------------------------------------------------------------

class TestCrypto(unittest.TestCase):
    def test_selftest_passes(self):
        self.assertTrue(sc.selftest())

    def test_des_vector(self):
        out = sc.des_ecb_encrypt(bytes.fromhex("0123456789ABCDEF"),
                                 bytes.fromhex("133457799BBCDFF1"))
        self.assertEqual(out.hex().upper(), "85E813540F0AB405")

    def test_aes_vector(self):
        out = sc.aes_cbc_encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),
                                 bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                                 b"\x00" * 16)
        self.assertEqual(out.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_hmac_vector(self):
        got = sc.hmac_sha256_hex("key", "The quick brown fox jumps over the lazy dog")
        self.assertEqual(got, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")

    def test_rsa_length(self):
        pub = base64.b64decode(
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoin"
            "PkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sK"
            "mwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRBy"
            "fRsK2gdl7llqCwIDAQAB")
        ct = sc.rsa_encrypt_pkcs1_v15(b"hello", pub)
        self.assertEqual(len(ct), 128)

    def test_request_sign_matches_reference(self):
        """与官方实现等价：md5(hex(hmac_sha256(token, path+body+ts+ca_json)))。"""
        token, path, body, ts = "CREDTOKEN", "/api/v1/game/attendance", '{"gameId":1}', 1700000000
        ca = {"platform": "3", "timestamp": str(ts), "dId": "Bxxx", "vName": "1.0.0"}
        expect = hashlib.md5(hmac.new(
            token.encode(),
            f"{path}{body}{ts}{json.dumps(ca, separators=(',', ':'))}".encode(),
            hashlib.sha256).hexdigest().encode()).hexdigest()
        self.assertEqual(sc.request_sign(token, path, body, ts, ca), expect)


# --------------------------------------------------------------------------
# 2. 设备指纹
# --------------------------------------------------------------------------

class TestDeviceId(unittest.TestCase):
    def test_generate_device_id_shape(self):
        got = sc.generate_device_id(lambda *a: {"code": 1100,
                                                 "detail": {"deviceId": "ABC"}})
        self.assertTrue(got.startswith("B"))
        self.assertEqual(got, "BABC")

    def test_generate_device_id_failure_raises(self):
        with self.assertRaises(RuntimeError):
            sc.generate_device_id(lambda *a: {"code": 9101, "message": "no permission"})

    def test_adapter_caches_did(self):
        ad = _adapter()
        ad._device_id()
        ad._device_id()
        fp_calls = [c for c in ad.calls if c[0] == "FP"]
        self.assertEqual(len(fp_calls), 1, "dId 应在单次适配器实例内缓存复用")


# --------------------------------------------------------------------------
# 3. 认证链
# --------------------------------------------------------------------------

class TestAuthChain(unittest.TestCase):
    def test_grant_and_cred_headers(self):
        ad = _adapter()
        ad._get_credential()
        grant = [c for c in ad.calls if "oauth2" in c[1]][0]
        self.assertIn("dId", grant[3])
        self.assertIn("Skland/", grant[3]["User-Agent"])
        cred = [c for c in ad.calls if "generate_cred_by_code" in c[1]][0]
        self.assertEqual(json.loads(cred[2])["kind"], 1)

    def test_token_invalid_is_auth(self):
        ad = _adapter(_base_routes(grant={"status": -1, "message": "token 已失效"}))
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertEqual(res.status, STATUS_AUTH)

    def test_no_auth_code_is_auth(self):
        ad = _adapter(_base_routes(grant={"status": 0, "data": {}}))
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertEqual(res.status, STATUS_AUTH)

    def test_cred_failure_is_auth(self):
        ad = _adapter(_base_routes(cred={"code": 401, "message": "凭证无效"}))
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertEqual(res.status, STATUS_AUTH)

    def test_network_error_is_transient(self):
        ad = _adapter(_base_routes(grant=OSError("timeout")))
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertEqual(res.status, STATUS_TRANSIENT)


# --------------------------------------------------------------------------
# 4. 签到主流程
# --------------------------------------------------------------------------

class TestSignIn(unittest.TestCase):
    def test_ark_and_end_all_ok(self):
        ad = _adapter()
        res = ad.sign_in()
        self.assertTrue(res.success)
        self.assertEqual(res.status, STATUS_OK)
        # 明日方舟 1 个 + 终末地 2 个角色 = 3 项
        self.assertEqual(len(res.items), 3)
        names = [i["name"] for i in res.items]
        self.assertTrue(any("明日方舟" in n for n in names))
        self.assertEqual(sum(1 for n in names if "终末地" in n), 2)

    def test_ark_request_body_and_signature_headers(self):
        ad = _adapter()
        ad.sign_in()
        ark = [c for c in ad.calls if c[1].endswith("/api/v1/game/attendance")][0]
        body = json.loads(ark[2])
        self.assertEqual(body["gameId"], 1)
        self.assertEqual(body["uid"], "100000001")
        h = ark[3]
        for k in ("sign", "cred", "dId", "timestamp", "platform", "vName"):
            self.assertIn(k, h, f"缺少签名头 {k}")
        self.assertEqual(h["cred"], "CREDVALUE")

    def test_endfield_role_header(self):
        ad = _adapter()
        ad.sign_in()
        ends = [c for c in ad.calls if c[1].endswith("/endfield/attendance")]
        self.assertEqual(len(ends), 2)
        self.assertEqual(ends[0][3]["sk-game-role"], "3_r1_s1")
        self.assertEqual(ends[1][3]["sk-game-role"], "3_r2_s2")
        self.assertEqual(ends[0][3]["origin"], "https://game.skland.com/")

    def test_signature_is_verifiable(self):
        """用捕获到的 sign 头独立重算，必须匹配。"""
        ad = _adapter()
        ad.sign_in()
        ark = [c for c in ad.calls if c[1].endswith("/api/v1/game/attendance")][0]
        h = ark[3]
        ca = {"platform": h["platform"], "timestamp": h["timestamp"],
              "dId": h["dId"], "vName": h["vName"]}
        expect = hashlib.md5(hmac.new(
            b"CREDTOKEN",
            f"/api/v1/game/attendance{ark[2]}{h['timestamp']}"
            f"{json.dumps(ca, separators=(',', ':'))}".encode(),
            hashlib.sha256).hexdigest().encode()).hexdigest()
        self.assertEqual(h["sign"], expect)

    def test_already_signed_is_already(self):
        ad = _adapter(_base_routes(ark={"code": 5001, "message": "请勿重复签到"}))
        res = ad.sign_in()
        # 明日方舟已签（幂等成功）+ 终末地成功 -> overall ok
        self.assertTrue(res.success)
        ark_item = [i for i in res.items if "明日方舟" in i["name"]][0]
        self.assertEqual(ark_item["status"], STATUS_ALREADY)

    def test_auth_failure_marks_auth(self):
        ad = _adapter(_base_routes(ark={"code": 401, "message": "用户未登录"}))
        res = ad.sign_in()
        ark_item = [i for i in res.items if "明日方舟" in i["name"]][0]
        self.assertEqual(ark_item["status"], STATUS_AUTH)

    def test_partial_when_one_role_fails(self):
        def end_role(data, headers):
            if headers.get("sk-game-role", "").endswith("r2_s2"):
                return {"code": 999, "message": "签到失败"}
            return {"code": 0, "data": {}}

        ad = _adapter(_base_routes(end=end_role))
        res = ad.sign_in()
        self.assertTrue(res.success)
        self.assertEqual(res.status, "partial",
                         "部分失败应标 partial，而不是被 ok=ok or s 吞掉")

    def test_all_fail_marks_failed(self):
        ad = _adapter(_base_routes(
            ark={"code": 999, "message": "未知错误"},
            end={"code": 999, "message": "未知错误"}))
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertEqual(res.status, STATUS_FAILED)

    def test_network_error_in_sign_is_transient(self):
        ad = _adapter(_base_routes(ark=OSError("connection reset")))
        res = ad.sign_in()
        ark_item = [i for i in res.items if "明日方舟" in i["name"]][0]
        self.assertEqual(ark_item["status"], STATUS_TRANSIENT)

    def test_no_binding_is_ok_noop(self):
        ad = _adapter(_base_routes(binding={"code": 0, "data": {"list": []}}))
        res = ad.sign_in()
        self.assertTrue(res.success)
        self.assertEqual(res.status, STATUS_OK)
        self.assertIn("未绑定", res.message)

    def test_binding_auth_failure(self):
        ad = _adapter(_base_routes(binding={"code": 401, "message": "用户未登录"}))
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertEqual(res.status, STATUS_AUTH)

    def test_missing_token_validation(self):
        ad = SkylandAdapter({})
        res = ad.sign_in()
        self.assertFalse(res.success)
        self.assertIn("token", res.message)


# --------------------------------------------------------------------------
# 5. 只读角色检测
# --------------------------------------------------------------------------

class TestDetectBindings(unittest.TestCase):
    def test_detect_returns_bindings_without_signing(self):
        ad = _adapter()
        ok, msg, st, bindings = ad.detect_bindings()
        self.assertTrue(ok)
        self.assertEqual(len(bindings), 2)
        self.assertFalse([c for c in ad.calls if c[1].endswith("attendance")],
                         "角色检测不应触发签到请求")


# --------------------------------------------------------------------------
# 6. 注册表与门闸
# --------------------------------------------------------------------------

class TestRegistry(unittest.TestCase):
    def test_registered(self):
        self.assertIn("skland", engine.REGISTRY)

    def test_status_is_beta_and_implemented(self):
        self.assertEqual(engine.platform_status("skland"), "beta")
        self.assertTrue(engine.is_implemented("skland"))

    def test_yanyun_still_unimplemented(self):
        self.assertFalse(engine.is_implemented("yanyun"))

    def test_service_classify_skland_auth(self):
        from service import classify
        from engine.base import CheckinResult
        res = CheckinResult(platform="skland", success=False, message="用户未登录")
        self.assertEqual(classify(res, "skland"), STATUS_AUTH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
