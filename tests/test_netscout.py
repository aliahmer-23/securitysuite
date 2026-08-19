import unittest

from netscout.netscout import (
    normalize_target,
    resolve_target,
    validate_authorized_scope,
    build_ports,
    port_risk,
    get_service_guess,
)


class TestNetScout(unittest.TestCase):

    # --------------------------------------------------------
    # Target handling
    # --------------------------------------------------------

    def test_normalize_hostname(self):
        self.assertEqual(
            normalize_target("example.com"),
            "example.com"
        )

    def test_normalize_url(self):
        self.assertEqual(
            normalize_target("https://example.com/test"),
            "example.com"
        )

    def test_empty_target_rejected(self):
        with self.assertRaises(ValueError):
            normalize_target("")

    # --------------------------------------------------------
    # IP resolution
    # Uses literal loopback IP, so no DNS/network lookup needed.
    # --------------------------------------------------------

    def test_literal_ipv4_resolution(self):
        result = resolve_target("127.0.0.1")

        self.assertEqual(result["resolved_ip"], "127.0.0.1")
        self.assertEqual(result["ip_version"], 4)
        self.assertTrue(result["is_ip"])

    # --------------------------------------------------------
    # Scope metadata
    # --------------------------------------------------------

    def test_loopback_scope_detection(self):
        scope = validate_authorized_scope("127.0.0.1")

        self.assertTrue(scope["loopback"])
        self.assertTrue(scope["private"])

    # --------------------------------------------------------
    # Port profiles
    # --------------------------------------------------------

    def test_web_profile(self):
        ports, profile = build_ports("web")

        self.assertEqual(profile, "web")
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(3000, ports)

    def test_quick_profile(self):
        ports, profile = build_ports("quick")

        self.assertEqual(profile, "quick")
        self.assertIn(22, ports)
        self.assertIn(80, ports)
        self.assertIn(443, ports)

    def test_custom_port_range(self):
        ports, profile = build_ports(
            "standard",
            start_port=20,
            end_port=25
        )

        self.assertEqual(
            ports,
            [20, 21, 22, 23, 24, 25]
        )

        self.assertEqual(profile, "custom:20-25")

    def test_invalid_port_range_rejected(self):
        with self.assertRaises(ValueError):
            build_ports(
                "standard",
                start_port=100,
                end_port=50
            )

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            build_ports("does-not-exist")

    # --------------------------------------------------------
    # Port risk classification
    # --------------------------------------------------------

    def test_high_risk_port(self):
        self.assertEqual(
            port_risk(23),
            "HIGH"
        )

    def test_medium_risk_port(self):
        self.assertEqual(
            port_risk(22),
            "MEDIUM"
        )

    def test_low_risk_port(self):
        self.assertEqual(
            port_risk(80),
            "LOW"
        )

    # --------------------------------------------------------
    # Service identification
    # --------------------------------------------------------

    def test_known_service_guess(self):
        service = get_service_guess(80)

        self.assertIsInstance(service, str)
        self.assertNotEqual(service, "")


if __name__ == "__main__":
    unittest.main()
