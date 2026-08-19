import unittest

from securitysuite import (
    active_cloud_findings,
    calculate_combined_risk,
    empty_netscout,
    empty_cloudguard,
)


def make_finding(severity):
    return {
        "severity": severity,
        "title": f"{severity} test finding"
    }


class TestSecuritySuite(unittest.TestCase):

    def test_empty_results_pass(self):
        netscout = empty_netscout()
        cloudguard = empty_cloudguard()

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 0)
        self.assertEqual(summary["overall_risk"], "PASS")
        self.assertEqual(summary["total"], 0)


    def test_network_finding_is_counted(self):
        netscout = {
            "findings": [
                make_finding("HIGH")
            ]
        }

        cloudguard = {
            "findings": []
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 10)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["network_findings"], 1)
        self.assertEqual(summary["cloud_findings"], 0)


    def test_cloud_finding_is_counted(self):
        netscout = {
            "findings": []
        }

        cloudguard = {
            "findings": [
                make_finding("MEDIUM")
            ]
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 5)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["cloud_findings"], 1)


    def test_network_and_cloud_are_combined(self):
        netscout = {
            "findings": [
                make_finding("HIGH"),
                make_finding("LOW")
            ]
        }

        cloudguard = {
            "findings": [
                make_finding("MEDIUM")
            ]
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        # HIGH 10 + LOW 2 + MEDIUM 5 = 17
        self.assertEqual(summary["risk_score"], 17)
        self.assertEqual(summary["raw_score"], 17)

        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 1)

        self.assertEqual(summary["network_findings"], 2)
        self.assertEqual(summary["cloud_findings"], 1)
        self.assertEqual(summary["total"], 3)


    def test_critical_weight(self):
        netscout = {
            "findings": [
                make_finding("CRITICAL")
            ]
        }

        cloudguard = {
            "findings": []
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 25)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["overall_risk"], "MEDIUM")


    def test_risk_score_capped_at_100(self):
        netscout = {
            "findings": [
                make_finding("CRITICAL")
                for _ in range(10)
            ]
        }

        cloudguard = {
            "findings": []
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["raw_score"], 250)
        self.assertEqual(summary["risk_score"], 100)
        self.assertEqual(summary["overall_risk"], "CRITICAL")


    def test_high_threshold(self):
        netscout = {
            "findings": [
                make_finding("HIGH")
                for _ in range(4)
            ]
        }

        cloudguard = {
            "findings": []
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 40)
        self.assertEqual(summary["overall_risk"], "HIGH")


    def test_critical_threshold(self):
        netscout = {
            "findings": [
                make_finding("HIGH")
                for _ in range(7)
            ]
        }

        cloudguard = {
            "findings": []
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 70)
        self.assertEqual(summary["overall_risk"], "CRITICAL")


    def test_remediated_cloud_findings_are_removed(self):
        cloudguard = {
            "findings": [
                make_finding("HIGH"),
                make_finding("MEDIUM")
            ],
            "remediation": {
                "after_findings": 0
            }
        }

        findings = active_cloud_findings(
            cloudguard
        )

        self.assertEqual(findings, [])


    def test_remediation_affects_combined_risk(self):
        netscout = {
            "findings": [
                make_finding("LOW")
            ]
        }

        cloudguard = {
            "findings": [
                make_finding("HIGH"),
                make_finding("MEDIUM")
            ],
            "remediation": {
                "after_findings": 0
            }
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        # Cloud findings have been remediated,
        # so only the network LOW finding remains.
        self.assertEqual(summary["risk_score"], 2)
        self.assertEqual(summary["network_findings"], 1)
        self.assertEqual(summary["cloud_findings"], 0)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["overall_risk"], "LOW")


    def test_info_finding_has_zero_risk(self):
        netscout = {
            "findings": [
                make_finding("INFO")
            ]
        }

        cloudguard = {
            "findings": []
        }

        summary = calculate_combined_risk(
            netscout,
            cloudguard
        )

        self.assertEqual(summary["risk_score"], 0)
        self.assertEqual(summary["info"], 1)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["overall_risk"], "PASS")


if __name__ == "__main__":
    unittest.main()
