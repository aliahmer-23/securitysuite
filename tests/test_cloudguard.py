import copy
import unittest

from cloudguard.cloudguard import (
    generate_demo_environment,
    validate_environment,
    run_assessment,
    calculate_risk,
    remediate_environment,
)


class TestCloudGuard(unittest.TestCase):

    def setUp(self):
        self.environment = generate_demo_environment()


    def test_demo_environment_is_valid(self):
        # Successful validation completes without raising an exception.
        validate_environment(self.environment)


    def test_demo_environment_generates_findings(self):
        findings = run_assessment(self.environment)

        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)


    def test_demo_environment_detects_expected_findings(self):
        findings = run_assessment(self.environment)

        finding_ids = {
            finding.get("id")
            for finding in findings
        }

        self.assertIn("ACCOUNT-001", finding_ids)
        self.assertIn("ACCOUNT-002", finding_ids)
        self.assertIn("S3-001", finding_ids)
        self.assertIn("LOG-001", finding_ids)


    def test_risk_score_is_valid(self):
        findings = run_assessment(self.environment)
        summary = calculate_risk(findings)

        self.assertIsInstance(summary, dict)

        risk_score = summary.get("risk_score")

        self.assertIsInstance(risk_score, int)
        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 100)


    def test_remediation_reduces_findings(self):
        before_environment = copy.deepcopy(self.environment)

        before_findings = run_assessment(before_environment)

        remediated_environment, fixed = remediate_environment(
            before_environment
        )

        after_findings = run_assessment(remediated_environment)

        self.assertGreater(len(before_findings), 0)
        self.assertGreater(len(fixed), 0)
        self.assertLess(
            len(after_findings),
            len(before_findings)
        )


    def test_remediation_reduces_risk(self):
        before_environment = copy.deepcopy(self.environment)

        before_findings = run_assessment(before_environment)
        before_summary = calculate_risk(before_findings)

        remediated_environment, _ = remediate_environment(
            before_environment
        )

        after_findings = run_assessment(remediated_environment)
        after_summary = calculate_risk(after_findings)

        self.assertLess(
            after_summary["risk_score"],
            before_summary["risk_score"]
        )


if __name__ == "__main__":
    unittest.main()
