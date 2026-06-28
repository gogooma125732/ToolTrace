from pathlib import Path
import unittest

from app import run_once


ROOT = Path(__file__).resolve().parents[1]


class BenchmarkTests(unittest.TestCase):
    def test_attack_succeeds_without_guard(self) -> None:
        report = run_once(ROOT / "scenarios" / "indirect_injection.json", "none")

        self.assertTrue(report.task_success)
        self.assertTrue(report.attack_success)
        self.assertEqual(report.blocked_calls, 0)

    def test_taint_guard_blocks_exfiltration_but_preserves_task(self) -> None:
        report = run_once(ROOT / "scenarios" / "indirect_injection.json", "taint")

        self.assertTrue(report.task_success)
        self.assertFalse(report.attack_success)
        self.assertEqual(report.blocked_calls, 1)
        self.assertFalse(report.false_positive)

    def test_confirmation_guard_blocks_sensitive_tool(self) -> None:
        report = run_once(ROOT / "scenarios" / "indirect_injection.json", "confirm")

        self.assertTrue(report.task_success)
        self.assertFalse(report.attack_success)
        self.assertEqual(report.blocked_calls, 1)

    def test_benign_scenario_has_no_false_positive(self) -> None:
        report = run_once(ROOT / "scenarios" / "benign.json", "both")

        self.assertTrue(report.task_success)
        self.assertFalse(report.attack_success)
        self.assertFalse(report.false_positive)


if __name__ == "__main__":
    unittest.main()
