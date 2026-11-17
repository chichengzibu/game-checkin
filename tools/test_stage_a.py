#!/usr/bin/env python3
"""阶段 A 回归：结果分类 / 瞬时重试 / 幂等补跑 / 失效禁用。

完全离线：所有网络与睡眠都 mock，账号库用内存假 store，不碰真实 vault。
    python tools/test_stage_a.py
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import service                                    # noqa: E402
from engine.base import (                          # noqa: E402
    CheckinResult, summarize,
    STATUS_OK, STATUS_PARTIAL, STATUS_ALREADY, STATUS_TRANSIENT,
    STATUS_AUTH, STATUS_CAPTCHA, STATUS_FAILED,
)
from engine.kuro import KuroAdapter                # noqa: E402
from store.base import Account                      # noqa: E402


class _MemStore:
    """只实现 service 会用到的四个方法。"""

    def __init__(self, accounts=None):
        self.accounts = list(accounts or [])
        self.updated = []
        self.saved = []

    def list_accounts(self, user_id):
        return list(self.accounts)

    def update_account(self, user_id, account):
        self.updated.append(account.id)
        return account

    def save_result(self, user_id, account_id, last_run, last_result):
        self.saved.append((account_id, last_result))

    def list_users(self):
        return ["local"]


def res(success, message, status="", platform="mihoyo"):
    return CheckinResult(platform=platform, success=success,
                         message=message, status=status)


class TestSummarize(unittest.TestCase):
    def test_all_success(self):
        items = [{"status": STATUS_OK}, {"status": STATUS_ALREADY}]
        self.assertEqual(summarize(items), (True, STATUS_OK))

    def test_partial_is_not_completion(self):
        items = [{"status": STATUS_OK}, {"status": STATUS_AUTH}]
        self.assertEqual(summarize(items), (True, STATUS_PARTIAL))

    def test_all_failed_uses_dominant(self):
        items = [{"status": STATUS_TRANSIENT}, {"status": STATUS_AUTH}]
        self.assertEqual(summarize(items), (False, STATUS_AUTH))

    def test_empty_is_failed(self):
        self.assertEqual(summarize([]), (False, STATUS_FAILED))

    def test_legacy_result_still_constructs(self):
        r = CheckinResult("mihoyo", False, "旧文案")
        self.assertEqual(r.status, "")
        self.assertEqual(r.items, [])
        self.assertEqual(r.message, "旧文案")


class TestClassify(unittest.TestCase):
    def test_adapter_status_wins(self):
        self.assertEqual(service.classify(res(False, "任意", STATUS_CAPTCHA), "mihoyo"),
                         STATUS_CAPTCHA)

    def test_legacy_auth_message_fallback(self):
        self.assertEqual(service.classify(res(False, "未取到游戏角色：Cookie 已失效"), "mihoyo"),
                         STATUS_AUTH)

    def test_captcha_never_retried(self):
        self.assertEqual(service.classify(res(False, "触发人机验证(1034)"), "mihoyo"),
                         STATUS_CAPTCHA)

    def test_transient_network(self):
        self.assertEqual(service.classify(res(False, "请求失败: timeout"), "kuro"),
                         STATUS_TRANSIENT)

    def test_other_failure(self):
        self.assertEqual(service.classify(res(False, "参数错误"), "mihoyo"),
                         STATUS_FAILED)

    def test_success_defaults_ok(self):
        self.assertEqual(service.classify(res(True, "签到成功"), "mihoyo"), STATUS_OK)


class TestCheckOneEx(unittest.TestCase):
    def _account(self, platform="mihoyo"):
        return Account(platform=platform, label="测试", id="acc1",
                       credential={"cookie": "FAKE"})

    def test_unimplemented_short_circuits(self):
        acc = Account(platform="yanyun", label="燕云", id="yy")
        with mock.patch.object(service, "get_adapter") as ga:
            ok, msg, status = service._check_one_ex(acc)
        self.assertFalse(ok)
        self.assertIn("未实现", msg)
        self.assertEqual(status, STATUS_FAILED)
        ga.assert_not_called()

    def test_transient_retries_then_succeeds(self):
        acc = self._account()
        seq = [res(False, "请求失败: timeout", STATUS_TRANSIENT),
               res(True, "签到成功", STATUS_OK)]

        class _Ad:
            def sign_in(self):
                return seq.pop(0)

        with mock.patch.object(service, "get_adapter", return_value=_Ad()), \
             mock.patch.object(service.credentials, "prepare", return_value=""), \
             mock.patch.object(service.time, "sleep") as sl:
            ok, msg, status = service._check_one_ex(acc)
        self.assertTrue(ok)
        self.assertEqual(status, STATUS_OK)
        self.assertIn("网络重试", msg)
        self.assertEqual(sl.call_count, 1)

    def test_transient_exhausts_at_two_retries(self):
        acc = self._account()

        class _Ad:
            def sign_in(self):
                return res(False, "请求失败: timeout", STATUS_TRANSIENT)

        with mock.patch.object(service, "get_adapter", return_value=_Ad()), \
             mock.patch.object(service.credentials, "prepare", return_value=""), \
             mock.patch.object(service.time, "sleep") as sl:
            ok, msg, status = service._check_one_ex(acc)
        self.assertFalse(ok)
        self.assertEqual(status, STATUS_TRANSIENT)
        self.assertEqual(sl.call_count, service.MAX_TRANSIENT_RETRY)

    def test_captcha_is_never_retried(self):
        acc = self._account()

        class _Ad:
            def __init__(self):
                self.n = 0

            def sign_in(self):
                self.n += 1
                return res(False, "触发人机验证(1034)", STATUS_CAPTCHA)

        ad = _Ad()
        with mock.patch.object(service, "get_adapter", return_value=ad), \
             mock.patch.object(service.credentials, "prepare", return_value=""), \
             mock.patch.object(service.time, "sleep") as sl:
            ok, msg, status = service._check_one_ex(acc)
        self.assertFalse(ok)
        self.assertEqual(status, STATUS_CAPTCHA)
        self.assertEqual(ad.n, 1)
        sl.assert_not_called()

    def test_auth_still_triggers_renew_and_retry(self):
        acc = self._account()
        seq = [res(False, "未取到游戏角色：Cookie 已失效"),
               res(True, "原神 签到成功")]

        class _Ad:
            def sign_in(self):
                return seq.pop(0)

        with mock.patch.object(service, "get_adapter", return_value=_Ad()), \
             mock.patch.object(service.credentials, "prepare", return_value=""), \
             mock.patch.object(service.credentials, "renew",
                               return_value=(True, "已自动续期")), \
             mock.patch.object(service.time, "sleep"):
            ok, msg, status = service._check_one_ex(acc)
        self.assertTrue(ok)
        self.assertIn("自动续期", msg)
        self.assertEqual(status, STATUS_OK)


class TestApplyResult(unittest.TestCase):
    def test_success_marks_today_and_clears_streak(self):
        acc = Account(platform="mihoyo", id="a", fail_streak=3)
        st = _MemStore([acc])
        service.apply_result(acc, True, STATUS_OK, st, "local")
        self.assertEqual(acc.last_ok_date, service._today())
        self.assertEqual(acc.fail_streak, 0)
        self.assertIn("a", st.updated)

    def test_partial_does_not_mark_completion(self):
        acc = Account(platform="mihoyo", id="a")
        service.apply_result(acc, True, STATUS_PARTIAL, _MemStore([acc]))
        self.assertIsNone(acc.last_ok_date)
        self.assertTrue(service.is_pending(acc))

    def test_transient_does_not_accumulate(self):
        acc = Account(platform="mihoyo", id="a")
        service.apply_result(acc, False, STATUS_TRANSIENT, _MemStore([acc]))
        self.assertEqual(acc.fail_streak, 0)
        self.assertTrue(acc.enabled)

    def test_two_deterministic_failures_disable(self):
        acc = Account(platform="kuro", id="a")
        st = _MemStore([acc])
        first = service.apply_result(acc, False, STATUS_AUTH, st, "local")
        self.assertEqual(first, "")
        self.assertTrue(acc.enabled)
        second = service.apply_result(acc, False, STATUS_AUTH, st, "local")
        self.assertIn("自动停用", second)
        self.assertFalse(acc.enabled)

    def test_success_after_one_failure_resets_streak(self):
        acc = Account(platform="kuro", id="a")
        st = _MemStore([acc])
        service.apply_result(acc, False, STATUS_FAILED, st, "local")
        service.apply_result(acc, True, STATUS_OK, st, "local")
        self.assertEqual(acc.fail_streak, 0)
        self.assertTrue(acc.enabled)

    def test_no_store_is_noop(self):
        acc = Account(platform="kuro", id="a")
        self.assertEqual(service.apply_result(acc, True, STATUS_OK, None), "")


class TestPendingAndRunUser(unittest.TestCase):
    def test_done_account_is_not_pending(self):
        acc = Account(platform="mihoyo", id="a", last_ok_date=service._today())
        self.assertFalse(service.is_pending(acc))

    def test_failed_account_is_pending(self):
        acc = Account(platform="mihoyo", id="a")
        self.assertTrue(service.is_pending(acc))

    def test_disabled_account_is_not_pending(self):
        acc = Account(platform="mihoyo", id="a", enabled=False)
        self.assertFalse(service.is_pending(acc))

    def test_only_pending_skips_done_account(self):
        done = Account(platform="mihoyo", id="done", label="已完成",
                       last_ok_date=service._today())
        todo = Account(platform="mihoyo", id="todo", label="待补跑")
        st = _MemStore([done, todo])
        with mock.patch.object(service, "_check_one_ex",
                               return_value=(True, "签到成功", STATUS_OK)) as ex:
            rs = service.run_user("local", st, only_pending=True)
        self.assertEqual(len(rs), 1)
        self.assertEqual(rs[0]["id"], "todo")
        self.assertEqual(ex.call_count, 1)
        self.assertEqual(todo.last_ok_date, service._today())

    def test_manual_run_does_not_skip(self):
        done = Account(platform="mihoyo", id="done",
                       last_ok_date=service._today())
        st = _MemStore([done])
        with mock.patch.object(service, "_check_one_ex",
                               return_value=(True, "签到成功", STATUS_OK)) as ex:
            rs = service.run_user("local", st)
        self.assertEqual(len(rs), 1)
        self.assertEqual(ex.call_count, 1)


class TestKuroJudge(unittest.TestCase):
    def test_already_is_success(self):
        self.assertEqual(KuroAdapter._judge_status({"code": 1511})[2], STATUS_ALREADY)

    def test_auth_token(self):
        self.assertEqual(KuroAdapter._judge_status({"code": 220})[2], STATUS_AUTH)

    def test_network_error_is_transient(self):
        self.assertEqual(
            KuroAdapter._judge_status({"code": -1, "msg": "请求失败: timeout"})[2],
            STATUS_TRANSIENT)

    def test_legacy_judge_returns_pair(self):
        self.assertEqual(len(KuroAdapter._judge({"code": 200})), 2)


class TestLegacyVaultCompat(unittest.TestCase):
    def test_old_account_dict_has_defaults(self):
        a = Account.from_any({"platform": "mihoyo", "credential": {"cookie": "x"},
                              "id": "old"})
        self.assertIsNone(a.last_ok_date)
        self.assertEqual(a.fail_streak, 0)

    def test_new_fields_round_trip(self):
        raw = Account(platform="kuro", id="a", last_ok_date="2026-11-17",
                      fail_streak=2).to_dict()
        b = Account.from_any(raw)
        self.assertEqual(b.last_ok_date, "2026-11-17")
        self.assertEqual(b.fail_streak, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
