#!/usr/bin/env python3
"""自动续期 / 未实现平台短路 / 主密钥持久化 回归测试。

完全离线：所有网络调用用假 Session / monkeypatch 替换，账号库用临时目录。
不会联网、不会读写 config/vault.json、不会打印任何真实凭据。

    python tools/test_credential_refresh.py     # 退出码 0 = 全部通过
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import service  # noqa: E402
from engine.base import STATUS_AUTH, STATUS_FAILED  # noqa: E402
from engine.mihoyo import MihoyoAdapter  # noqa: E402
from store import credentials  # noqa: E402
from store.base import Account  # noqa: E402
from store.local_store import resolve_master_key  # noqa: E402
from store.login_browser import PLATFORMS  # noqa: E402
from store import schedule  # noqa: E402
from store.login_mihoyo import MihoyoQRLogin, MihoyoSDKQRLogin  # noqa: E402


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


class _FakeSession:
    """按 URL 返回预设结果，并记录调用，绝不发真实请求。"""

    def __init__(self, router):
        self.router = router
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return _Resp(self.router(url, kw))


class _MemStore:
    def __init__(self):
        self.updated = []

    def update_account(self, user_id, account):
        self.updated.append((user_id, account))
        return account


FAKE_COOKIE = (
    "ltuid_v2=12345678; ltoken_v2=FAKE_LT; cookie_token_v2=OLD_CT; "
    "account_id_v2=12345678; ltmid_v2=FAKE_MID; "
    "stoken=v2_FAKE_STOKEN_FOR_TEST_ONLY_0000000000; stuid=12345678; mid=FAKE_MID"
)


class TestCookieHelpers(unittest.TestCase):
    def test_parse_join_roundtrip(self):
        d = credentials.parse_cookie("a=1; b=two=three; a=9")
        self.assertEqual(d["a"], "9")       # 后值覆盖
        self.assertEqual(d["b"], "two=three")
        self.assertIn("a=9", credentials.join_cookie(d))

    def test_enrich_extracts_renewal_from_cookie(self):
        c = credentials.enrich_mihoyo({"cookie": FAKE_COOKIE})
        self.assertEqual(c["stoken"], "v2_FAKE_STOKEN_FOR_TEST_ONLY_0000000000")
        self.assertEqual(c["stuid"], "12345678")
        self.assertEqual(c["mid"], "FAKE_MID")
        self.assertTrue(c["renewable"])
        self.assertTrue(c["device_id"])
        # 幂等
        self.assertEqual(credentials.enrich_mihoyo(c), c)

    def test_enrich_without_stoken_marks_not_renewable(self):
        c = credentials.enrich_mihoyo({"cookie": "ltuid_v2=12345678; ltoken_v2=x"})
        self.assertFalse(c["renewable"])
        self.assertFalse(credentials.public_status(
            Account(platform="mihoyo", credential=c)
        )["auto_renew"])

    def test_apply_new_cookie_token_replaces_both_aliases(self):
        out = credentials.apply_new_cookie_token(FAKE_COOKIE, "NEW_CT")
        d = credentials.parse_cookie(out)
        self.assertEqual(d["cookie_token_v2"], "NEW_CT")
        self.assertNotIn("OLD_CT", out)
        # 原串无 V1 名时也应补上
        only_v2 = "cookie_token_v2=OLD; account_id_v2=1"
        d2 = credentials.parse_cookie(
            credentials.apply_new_cookie_token(only_v2, "NEW_CT")
        )
        self.assertEqual(d2["cookie_token_v2"], "NEW_CT")

    def test_apply_on_cookie_without_any_token(self):
        d = credentials.parse_cookie(
            credentials.apply_new_cookie_token("ltuid_v2=1; ltoken_v2=x", "NEW_CT")
        )
        self.assertEqual(d["cookie_token"], "NEW_CT")
        self.assertEqual(d["ltuid_v2"], "1")   # 其他字段不丢


class TestAuthFailureSignals(unittest.TestCase):
    def test_mihoyo_signals(self):
        for m in ("未取到游戏角色：Cookie 已失效", "xxx Cookie 失效，需重新登录",
                  "失败 retcode=-100"):
            self.assertTrue(credentials.is_auth_failure("mihoyo", m), m)

    def test_kuro_signals(self):
        for m in ("token 无效/已过期，请重新登录", "社区 code=220 令牌错误"):
            self.assertTrue(credentials.is_auth_failure("kuro", m), m)

    def test_normal_failure_is_not_auth_failure(self):
        self.assertFalse(credentials.is_auth_failure("mihoyo", "触发人机验证(1034)"))
        self.assertFalse(credentials.is_auth_failure("kuro", "今日已签"))


class TestExchange(unittest.TestCase):
    def _cred(self):
        return credentials.enrich_mihoyo({"cookie": FAKE_COOKIE})

    def test_passport_success(self):
        def router(url, kw):
            if "passport-api" in url:
                return {"retcode": 0, "data": {"cookie_token": "CT_FROM_PASSPORT"}}
            raise AssertionError("主接口成功时不应回退")
        sess = _FakeSession(router)
        with mock.patch.object(credentials, "get_session", return_value=sess):
            tok, note = credentials.exchange_cookie_token(self._cred())
        self.assertEqual(tok, "CT_FROM_PASSPORT")
        self.assertIn("passport", note)
        self.assertEqual(len(sess.calls), 1)
        # DS 与 params 都带上
        _, kw = sess.calls[0]
        self.assertEqual(kw["params"]["stoken"],
                         "v2_FAKE_STOKEN_FOR_TEST_ONLY_0000000000")
        self.assertEqual(kw["params"]["mid"], "FAKE_MID")
        self.assertIn("ds", kw["headers"])

    def test_fallback_to_takumi(self):
        def router(url, kw):
            if "passport-api" in url:
                return {"retcode": -1, "message": "denied"}
            return {"retcode": 0, "data": {"cookie_token": "CT_FROM_TAKUMI"}}
        sess = _FakeSession(router)
        with mock.patch.object(credentials, "get_session", return_value=sess):
            tok, note = credentials.exchange_cookie_token(self._cred())
        self.assertEqual(tok, "CT_FROM_TAKUMI")
        self.assertEqual(len(sess.calls), 2)
        _, kw = sess.calls[1]
        self.assertIn("stoken=", kw["headers"]["Cookie"])
        self.assertIn("mid=", kw["headers"]["Cookie"])  # v2_ 需带 mid

    def test_both_fail(self):
        def router(url, kw):
            return {"retcode": -100, "message": "expired"}
        with mock.patch.object(credentials, "get_session",
                               return_value=_FakeSession(router)):
            tok, note = credentials.exchange_cookie_token(self._cred())
        self.assertIsNone(tok)
        self.assertIn("失败", note)

    def test_no_stoken_short_circuits(self):
        with mock.patch.object(credentials, "get_session") as gs:
            tok, _ = credentials.exchange_cookie_token({"cookie": "ltuid_v2=1"})
        self.assertIsNone(tok)
        gs.assert_not_called()


class TestRenew(unittest.TestCase):
    def _mihoyo_account(self, cookie=FAKE_COOKIE):
        return Account(platform="mihoyo", label="测试米游社",
                       credential={"cookie": cookie})

    def test_mihoyo_renew_writes_back_new_cookie(self):
        acc, store = self._mihoyo_account(), _MemStore()
        with mock.patch.object(credentials, "mihoyo_cookie_valid",
                               return_value=False), \
             mock.patch.object(credentials, "exchange_cookie_token",
                               return_value=("FRESH_CT", "ok")):
            ok, note = credentials.renew(acc, store, "local")
        self.assertTrue(ok, note)
        d = credentials.parse_cookie(acc.credential["cookie"])
        self.assertEqual(d["cookie_token_v2"], "FRESH_CT")
        self.assertEqual(acc.credential["stoken"],
                         "v2_FAKE_STOKEN_FOR_TEST_ONLY_0000000000")
        self.assertIn("last_renew", acc.credential)
        self.assertEqual(len(store.updated), 1)   # 必须回写，否则旧 token 作废后彻底失效

    def test_no_stoken_gives_actionable_hint(self):
        acc = self._mihoyo_account("ltuid_v2=12345678; ltoken_v2=x; cookie_token_v2=OLD")
        ok, note = credentials.renew(acc, _MemStore(), "local")
        self.assertFalse(ok)
        self.assertIn("登录获取", note)

    def test_kuro_never_invents_refresh(self):
        acc = Account(platform="kuro", label="测试库街区",
                      credential={"token": "FAKE", "source": "h5"})
        with mock.patch.object(credentials, "exchange_cookie_token") as ex:
            ok, note = credentials.renew(acc, _MemStore(), "local")
        self.assertFalse(ok)
        self.assertIn("没有", note)
        self.assertIn("登录获取", note)
        ex.assert_not_called()
        self.assertEqual(acc.credential["source"], "h5")  # 不破坏 source

    def test_prepare_lazily_enriches_old_account(self):
        acc, store = self._mihoyo_account(), _MemStore()
        note = credentials.prepare(acc, store, "local")
        self.assertIn("自动续期", note)
        self.assertTrue(acc.credential["renewable"])
        self.assertEqual(len(store.updated), 1)
        # 第二次不再回写
        credentials.prepare(acc, store, "local")
        self.assertEqual(len(store.updated), 1)


class TestHealthCheckUsesSign口径(unittest.TestCase):
    """角色接口宽松、luna/info 严格：必须以后者为准。"""

    def _session(self, roles_payload, info_retcode):
        def router(url, kw):
            if "getUserGameRolesByCookie" in url:
                return roles_payload
            if "/luna/info" in url:
                return {"retcode": info_retcode, "data": {"is_sign": False}}
            raise AssertionError(f"非预期请求: {url}")
        return _FakeSession(router)

    def test_luna_minus100_overrides_ok_roles(self):
        roles = {"retcode": 0, "data": {"list": [
            {"game_biz": "hk4e_cn", "region": "cn_gf01", "game_uid": "123"},
        ]}}
        with mock.patch.object(credentials, "get_session",
                               return_value=self._session(roles, -100)):
            self.assertIs(credentials.mihoyo_cookie_valid(
                {"cookie": FAKE_COOKIE}), False)

    def test_luna_ok_means_valid(self):
        roles = {"retcode": 0, "data": {"list": [
            {"game_biz": "hk4e_cn", "region": "cn_gf01", "game_uid": "123"},
        ]}}
        with mock.patch.object(credentials, "get_session",
                               return_value=self._session(roles, 0)):
            self.assertIs(credentials.mihoyo_cookie_valid(
                {"cookie": FAKE_COOKIE}), True)

    def test_roles_minus100_means_invalid(self):
        with mock.patch.object(credentials, "get_session", return_value=(
                self._session({"retcode": -100, "message": "not login"}, 0))):
            self.assertIs(credentials.mihoyo_cookie_valid(
                {"cookie": FAKE_COOKIE}), False)

    def test_no_roles_is_not_auth_problem(self):
        with mock.patch.object(credentials, "get_session", return_value=(
                self._session({"retcode": 0, "data": {"list": []}}, 0))):
            self.assertIs(credentials.mihoyo_cookie_valid(
                {"cookie": FAKE_COOKIE}), True)


class TestQRLoginStokenExtraction(unittest.TestCase):
    """扫码响应的 stoken 形状会变，登录成功但没续期材料是最隐蔽的坑。"""

    def _poll(self, data):
        sess = MihoyoQRLogin()
        with mock.patch("store.login_mihoyo._post", return_value=(
                0, {"retcode": 0, "data": data}, [])):
            return sess.poll("FAKE_TICKET")

    def _base(self, **kw):
        d = {
            "status": "Confirmed",
            "user_info": {"aid": "12345678", "mid": "FAKE_MID"},
            "tokens": [{"name": "ltoken", "token": "FAKE_LT"}],
        }
        d.update(kw)
        return d

    def test_tokens_list_shape(self):
        st = self._poll(self._base(tokens=[
            {"name": "stoken", "token": "v2_FROM_TOKENS"},
            {"name": "ltoken", "token": "FAKE_LT"},
        ]))
        self.assertEqual(st["renewal"]["stoken"], "v2_FROM_TOKENS")
        self.assertIn("stoken=v2_FROM_TOKENS", st["cookie"])

    def test_data_token_as_string(self):
        st = self._poll(self._base(tokens=None, token="v2_FROM_TOKEN_STR"))
        self.assertEqual(st["renewal"]["stoken"], "v2_FROM_TOKEN_STR")

    def test_data_stoken_direct(self):
        st = self._poll(self._base(tokens=None, stoken="v2_DIRECT"))
        self.assertEqual(st["renewal"]["stoken"], "v2_DIRECT")

    def test_missing_stoken_is_reported(self):
        st = self._poll(self._base(tokens=None))
        self.assertNotIn("stoken", st["renewal"])

    def test_ltoken_is_not_mistaken_for_stoken(self):
        st = self._poll(self._base(tokens=[{"name": "ltoken", "token": "LT"}]))
        self.assertNotIn("stoken", st["renewal"])
        self.assertIn("ltoken=LT", st["cookie"])


class TestSDKQRLogin(unittest.TestCase):
    """米游社 App 扫码（bbs_cn）必须在 Confirmed 响应里拿到 stoken。"""

    def test_app_qr_exchange_yields_stoken_and_full_cookie(self):
        sess = MihoyoSDKQRLogin()

        def fake_post(url, body, headers=None):
            if "queryQRLoginStatus" in url:
                return {"retcode": 0, "data": {
                    "status": "Confirmed",
                    "tokens": [{"name": "stoken", "token": "v2_APP_STOKEN"}],
                    "user_info": {"mid": "FAKE_MID", "aid": "12345678"},
                }}
            raise AssertionError(f"非预期请求 {url}")

        with mock.patch("store.login_mihoyo._sdk_post", side_effect=fake_post), \
             mock.patch("store.login_mihoyo._app_get", return_value={
                 "retcode": 0, "data": {"ltoken": "FAKE_LTOKEN"}}), \
             mock.patch("store.credentials.exchange_cookie_token",
                        return_value=("FAKE_CT", "ok")):
            st = sess.poll("FAKE_TICKET")
        self.assertEqual(st["status"], "Confirmed")
        self.assertEqual(st["renewal"]["stoken"], "v2_APP_STOKEN")
        self.assertEqual(st["renewal"]["mid"], "FAKE_MID")
        self.assertIn("stoken=v2_APP_STOKEN", st["cookie"])
        self.assertIn("ltoken=FAKE_LTOKEN", st["cookie"])
        self.assertIn("cookie_token=FAKE_CT", st["cookie"])

    def test_qr_create_uses_bbs_app_channel(self):
        sess = MihoyoSDKQRLogin()
        with mock.patch("store.login_mihoyo._sdk_post", return_value={
                "retcode": 0, "data": {"url": "https://user.mihoyo.com/x",
                                       "ticket": "T"}}) as post:
            qr = sess.create()
        self.assertEqual(qr["ticket"], "T")
        self.assertIn("createQRLogin", post.call_args.args[0])
        headers = post.call_args.args[2]
        self.assertEqual(headers["x-rpc-game_biz"], "bbs_cn")

    def test_waiting_state(self):
        sess = MihoyoSDKQRLogin()
        with mock.patch("store.login_mihoyo._sdk_post", return_value={
                "retcode": 0, "data": {"status": "Init"}}):
            self.assertEqual(sess.poll("T")["status"], "Created")


class TestForceRenew(unittest.TestCase):
    def _acc(self):
        return Account(platform="mihoyo", label="测试",
                       credential=credentials.enrich_mihoyo({"cookie": FAKE_COOKIE}))

    def test_sign_auth_forces_exchange_even_if_healthcheck_says_ok(self):
        acc, store = self._acc(), _MemStore()
        with mock.patch.object(credentials, "mihoyo_cookie_valid",
                               return_value=True) as check, \
             mock.patch.object(credentials, "exchange_cookie_token",
                               return_value=("NEW", "ok")) as ex:
            ok, note = credentials.renew(acc, store, "local", force=True)
        self.assertTrue(ok, note)
        check.assert_not_called()
        ex.assert_called_once()
        self.assertEqual(credentials.parse_cookie(acc.credential["cookie"])[
            "cookie_token_v2"], "NEW")

    def test_manual_renew_does_not_burn_valid_token(self):
        acc = self._acc()
        with mock.patch.object(credentials, "mihoyo_cookie_valid",
                               return_value=True), \
             mock.patch.object(credentials, "exchange_cookie_token") as ex:
            ok, note = credentials.renew(acc, _MemStore(), "local")
        self.assertFalse(ok)
        self.assertIn("无需续期", note)
        ex.assert_not_called()

    def test_no_stoken_hint_explains_root_cause(self):
        acc = Account(platform="mihoyo", credential={"cookie": "ltuid_v2=1"})
        ok, note = credentials.renew(acc, _MemStore(), "local", force=True)
        self.assertFalse(ok)
        self.assertIn("stoken", note)
        self.assertIn("扫码", note)


class TestBrowserLoginCapturesRenewal(unittest.TestCase):
    def test_mihoyo_browser_login_collects_stoken(self):
        names = PLATFORMS["mihoyo"]["cookie_names"]
        for n in ("stoken", "stuid", "mid", "cookie_token", "cookie_token_v2",
                  "account_id", "account_id_v2"):
            self.assertIn(n, names)


class TestRoleFailureClassification(unittest.TestCase):
    def _adapter(self, payload):
        return MihoyoAdapter(payload)

    def test_no_roles_is_not_auth_failure(self):
        class S:
            def get(self, url, **kw):
                return _Resp({"retcode": 0, "data": {"list": []}})
        ad = self._adapter({"cookie": FAKE_COOKIE})
        ad.session = S()
        res = ad.sign_in()
        self.assertEqual(res.status, STATUS_FAILED)
        self.assertIn("没有", res.message)

    def test_roles_minus100_is_auth_failure(self):
        class S:
            def get(self, url, **kw):
                return _Resp({"retcode": -100, "message": "not login"})
        ad = self._adapter({"cookie": FAKE_COOKIE})
        ad.session = S()
        res = ad.sign_in()
        self.assertEqual(res.status, STATUS_AUTH)


class TestServiceWiring(unittest.TestCase):
    def test_unimplemented_platform_short_circuits(self):
        acc = Account(platform="yanyun", label="测试燕云",
                      credential={"token": "FAKE"})
        with mock.patch.object(service, "get_adapter") as ga:
            ok, msg = service._check_one(acc)
        self.assertFalse(ok)
        self.assertIn("未实现", msg)
        ga.assert_not_called()   # 不发网络请求、不假装签到

    def test_mihoyo_adapter_still_registered(self):
        from engine import get_adapter, is_implemented, platform_status
        self.assertTrue(is_implemented("mihoyo"))
        self.assertTrue(is_implemented("kuro"))
        self.assertEqual(platform_status("yanyun"), "unimplemented")
        self.assertEqual(type(get_adapter("mihoyo", {"cookie": "x"})).__name__,
                         "MihoyoAdapter")
        self.assertEqual(type(get_adapter("kuro", {"token": "x"})).__name__,
                         "KuroAdapter")

    def test_failed_sign_triggers_renew_and_retry(self):
        class _FailAdapter:
            def __init__(self, account):
                self.account = account

            def sign_in(self):
                from engine.base import CheckinResult
                return CheckinResult(platform="mihoyo", success=False,
                                     message="未取到游戏角色：Cookie 已失效")

        class _OkAdapter(_FailAdapter):
            def sign_in(self):
                from engine.base import CheckinResult
                return CheckinResult(platform="mihoyo", success=True,
                                     message="原神 签到成功")

        acc = Account(platform="mihoyo", label="测试",
                      credential=credentials.enrich_mihoyo({"cookie": FAKE_COOKIE}))
        calls = {"n": 0}

        def factory(platform, payload):
            calls["n"] += 1
            return _FailAdapter(payload) if calls["n"] == 1 else _OkAdapter(payload)

        with mock.patch.object(service, "get_adapter", side_effect=factory), \
             mock.patch.object(service.credentials, "prepare", return_value=""), \
             mock.patch.object(service.credentials, "renew",
                               return_value=(True, "已自动续期")), \
             mock.patch.object(service.time, "sleep"):
            ok, msg = service._check_one(acc, _MemStore(), "local")
        self.assertTrue(ok, msg)
        self.assertIn("自动续期", msg)
        self.assertEqual(calls["n"], 2)


class TestTodayDetection(unittest.TestCase):
    def test_unsupported_platform_is_explicit(self):
        acc = Account(platform="kuro", label="测试", credential={"token": "x"})
        r = service.check_today(acc)
        self.assertFalse(r["supported"])
        self.assertIn("不提供只读", r["note"])


class TestUnifiedAccountLock(unittest.TestCase):
    def test_same_mihoyo_uid_shares_lock_even_if_account_id_changes(self):
        a = credentials.lock_key("mihoyo", {"stuid": "12345678"}, "old-id")
        b = credentials.lock_key("mihoyo", {"account_id": "12345678"}, "new-id")
        self.assertEqual(a, b)
        self.assertEqual(a, "mihoyo:12345678")

    def test_lock_is_reentrant_for_renew_inside_checkin(self):
        key = credentials.lock_key("mihoyo", {"stuid": "12345678"})
        with credentials.account_lock(key):
            with credentials.account_lock(key):
                pass   # 不阻塞 = RLock 生效

    def test_other_platform_falls_back_to_account_id(self):
        self.assertEqual(
            credentials.lock_key("kuro", {"token": "x"}, "abc"),
            "account:abc")


class TestScheduleSettings(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"CHECKIN_SETTINGS_PATH": os.path.join(td, "settings.json"),
                   "CHECKIN_SCHEDULE_STATE": os.path.join(td, "state.txt")}
            with mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(schedule.load_settings()["schedule_time"], "09:00")
                cfg = schedule.save_settings(
                    {"schedule_time": "08:30", "schedule_enabled": False})
                self.assertEqual(cfg["schedule_time"], "08:30")
                self.assertFalse(cfg["schedule_enabled"])
                again = schedule.load_settings()
                self.assertEqual(again["schedule_time"], "08:30")
                self.assertFalse(again["schedule_enabled"])

    def test_invalid_values_are_normalized(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"CHECKIN_SETTINGS_PATH": os.path.join(td, "settings.json")}
            with mock.patch.dict(os.environ, env, clear=False):
                cfg = schedule.save_settings({
                    "schedule_time": "99:99", "max_runs_per_day": 999,
                    "min_interval_minutes": 1, "schedule_jitter_seconds": -5,
                })
                self.assertEqual(cfg["schedule_time"], "09:00")
                self.assertEqual(cfg["max_runs_per_day"], 24)
                self.assertEqual(cfg["min_interval_minutes"], 5)
                self.assertEqual(cfg["schedule_jitter_seconds"], 0)

    def test_disabled_never_due(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"CHECKIN_SETTINGS_PATH": os.path.join(td, "settings.json"),
                   "CHECKIN_SCHEDULE_STATE": os.path.join(td, "state.txt")}
            with mock.patch.dict(os.environ, env, clear=False):
                schedule.save_settings({"schedule_enabled": False})
                self.assertFalse(schedule.is_due())


class TestMasterKeyPersistence(unittest.TestCase):
    def test_generates_and_reuses_key(self):
        with tempfile.TemporaryDirectory() as td:
            key_file = os.path.join(td, "config", "master.key")
            vault = os.path.join(td, "config", "vault.json")
            env = {
                "CHECKIN_MASTER_KEY_FILE": key_file,
                "CHECKIN_VAULT_PATH": vault,
            }
            with mock.patch.dict(os.environ, env, clear=False), \
                 mock.patch.dict(os.environ, {"CHECKIN_MASTER_KEY": ""}):
                os.environ.pop("CHECKIN_MASTER_KEY", None)
                k1 = resolve_master_key()
                k2 = resolve_master_key()
            self.assertEqual(k1, k2)          # 重启沿用，不用重新登录
            self.assertTrue(os.path.isfile(key_file))
            self.assertGreaterEqual(len(k1), 32)

    def test_env_key_wins(self):
        with mock.patch.dict(os.environ, {"CHECKIN_MASTER_KEY": "EXPLICIT"}):
            self.assertEqual(resolve_master_key(), "EXPLICIT")


if __name__ == "__main__":
    unittest.main(verbosity=2)
