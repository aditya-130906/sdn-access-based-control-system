"""Regression tests for whitelist behavior and policy consistency."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from controller.flow_manager import flow_intent_for_source
from controller.whitelist_manager import PolicyEngine, WhitelistManager


class PolicyRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.whitelist_path = os.path.join(self.temp_dir.name, "whitelist.json")
        payload = {
            "authorized_hosts": [
                "00:00:00:00:00:01",
                "00:00:00:00:00:02",
                "00:00:00:00:00:03",
            ]
        }
        with open(self.whitelist_path, "w", encoding="utf-8") as whitelist_file:
            json.dump(payload, whitelist_file)

        self.whitelist_manager = WhitelistManager(self.whitelist_path)
        self.policy_engine = PolicyEngine(self.whitelist_manager)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_authorization(self):
        self.assertEqual(
            self.policy_engine.decide("00:00:00:00:00:01"),
            PolicyEngine.ACTION_ALLOW,
        )
        self.assertEqual(
            self.policy_engine.decide("00:00:00:00:00:04"),
            PolicyEngine.ACTION_DENY,
        )

    def test_add_host_to_whitelist(self):
        self.whitelist_manager.add_host("00:00:00:00:00:04")
        self.assertTrue(self.whitelist_manager.is_authorized("00:00:00:00:00:04"))
        self.assertEqual(
            self.policy_engine.decide("00:00:00:00:00:04"),
            PolicyEngine.ACTION_ALLOW,
        )

    def test_remove_host_from_whitelist(self):
        self.whitelist_manager.remove_host("00:00:00:00:00:02")
        self.assertFalse(self.whitelist_manager.is_authorized("00:00:00:00:00:02"))
        self.assertEqual(
            self.policy_engine.decide("00:00:00:00:00:02"),
            PolicyEngine.ACTION_DENY,
        )

    def test_conflicting_policy_is_rejected(self):
        sources = [
            "00:00:00:00:00:01",
            "00:00:00:00:00:01",
            "00:00:00:00:00:04",
        ]
        self.assertTrue(self.policy_engine.validate_no_conflicts(sources))

        authorized = self.whitelist_manager.get_all()
        decision_1 = flow_intent_for_source(authorized, "00:00:00:00:00:01")
        decision_2 = flow_intent_for_source(authorized, "00:00:00:00:00:04")

        self.assertEqual(decision_1, "ALLOW")
        self.assertEqual(decision_2, "DENY")
        self.assertNotEqual(decision_1, decision_2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
