"""Unit tests for the allowance auditor.

This suite uses the builtin `unittest` framework to avoid external
dependencies. It focuses on the risk classification logic and helper
functions. To run the tests execute:

    python -m unittest discover -s allowance_auditor/tests

Note that no blockchain calls are made during these tests.
"""

import math
import unittest

from allowance_auditor.allowance_auditor import (
    UNLIMITED_THRESHOLD,
    CRITICAL_SPENDERS,
    KNOWN_SAFE_SPENDERS,
    determine_risk,
    Allowance,
)


class TestRiskClassification(unittest.TestCase):
    def test_determine_risk_critical(self):
        """Unlimited approval to a critical spender is CRITICAL."""
        critical_addr = next(iter(CRITICAL_SPENDERS.keys()))
        risk = determine_risk(UNLIMITED_THRESHOLD + 1, critical_addr)
        self.assertEqual(risk, "CRITICAL")

    def test_determine_risk_medium_unlimited_unknown(self):
        """Unlimited approval to an unknown spender is MEDIUM risk."""
        unknown_addr = "0x1234567890123456789012345678901234567890"
        risk = determine_risk(UNLIMITED_THRESHOLD + 5, unknown_addr)
        self.assertEqual(risk, "MEDIUM")

    def test_determine_risk_medium_finite_critical(self):
        """Finite approval to a critical spender is MEDIUM risk."""
        critical_addr = next(iter(CRITICAL_SPENDERS.keys()))
        risk = determine_risk(10**18, critical_addr)
        self.assertEqual(risk, "MEDIUM")

    def test_determine_risk_low_known_safe(self):
        """Finite approval to a known safe spender is LOW risk."""
        if not KNOWN_SAFE_SPENDERS:
            self.skipTest("No known safe spenders defined")
        safe_addr = next(iter(KNOWN_SAFE_SPENDERS.keys()))
        risk = determine_risk(10**18, safe_addr)
        self.assertEqual(risk, "LOW")

    def test_determine_risk_medium_unknown_finite(self):
        """Finite approval to an unknown spender is MEDIUM risk."""
        unknown_addr = "0x0beefbeefbeefbeefbeefbeefbeefbeefbeefbee"
        risk = determine_risk(1, unknown_addr)
        self.assertEqual(risk, "MEDIUM")


class TestAllowanceHelpers(unittest.TestCase):
    def test_readable_amount(self):
        """Ensure readable_amount returns a formatted decimal string."""
        allowance = Allowance(
            token="0xToken",
            spender="0xSpender",
            value=1234567890000000000,
            token_symbol="TEST",
            token_decimals=18,
            risk_level="LOW",
        )
        human = allowance.readable_amount()
        self.assertTrue(math.isclose(float(human), 1.2346, rel_tol=1e-4))


if __name__ == "__main__":
    unittest.main()
