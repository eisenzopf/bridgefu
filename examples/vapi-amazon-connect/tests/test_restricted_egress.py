import copy
import json
from pathlib import Path
import unittest
from restricted_egress import apply_config, firewall_script, validate


class RestrictedEgress(unittest.TestCase):
    def settings(self):
        return json.loads(Path(__file__).with_name("restricted-egress.example.json").read_text())

    def test_firewall_has_no_direct_media_escape(self):
        settings = validate(self.settings())
        script = firewall_script(settings, "apply")
        self.assertIn("--sport 42000:42031", script)
        self.assertIn("--dport 3478 -j ACCEPT", script)
        self.assertIn("iptables -A BRIDGEFU_CONNECT_TEST -j REJECT", script)
        self.assertIn("ip6tables -A BRIDGEFU_CONNECT_TEST -j REJECT", script)
        self.assertNotIn("ESTABLISHED", script)
        self.assertNotIn("-F OUTPUT", script)

    def test_rejects_unrestricted_allowlist_and_caller_port_overlap(self):
        for changes in ({"relay_cidrs": ["0.0.0.0/0"]}, {"udp_port_start": 40000, "udp_port_end": 40031}, {"relay_port": "3478; true"}):
            settings = self.settings()
            settings.update(changes)
            with self.assertRaises(ValueError):
                validate(settings)

    def test_network_override_preserves_customer_fields(self):
        original = {"aws": {"region": "region-test"}, "context": {"allow_headers": {"X-My-Field": "my_field"}}}
        snapshot = copy.deepcopy(original)
        for source in ("turn_control_url", "join_ack", "auto", "disabled"):
            configured = apply_config(original, self.settings(), source)
            self.assertEqual(configured["context"], original["context"])
            self.assertEqual(configured["generic_bridge"]["webrtc"]["ice_servers"], [])
            self.assertEqual(configured["aws"]["turn"]["relay_only"], source != "disabled")
        self.assertEqual(original, snapshot)
