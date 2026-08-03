from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
SPEC = importlib.util.spec_from_file_location(
    "aws_recipe_live_test_starter_review", SCRIPT
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)


class DisposableStarterReviewTests(unittest.TestCase):
    def fixture(self):
        ledger = {"connect_mode": "disposable", "enable_demo_site": False}
        expected_contract = {
            container: f"{index:064x}"
            for index, container in enumerate(
                sorted(LIVE.DISPOSABLE_STARTER_TEMPLATE_CONTAINERS), 1
            )
        }
        parameters = {
            "PublicHostedZoneId": "none",
            "SipSecurity": "sip_rtp",
            "SipHostname": "unused.bridgefu.invalid",
            "RootVolumeGiB": "12",
            "DataVolumeGiB": "8",
        }
        description = {
            "Parameters": [
                {"ParameterKey": key, "ParameterValue": value}
                for key, value in parameters.items()
            ]
        }
        changes = [
            {
                "path": f"{container}/Resource{index}",
                "resource_type": "AWS::Logs::LogGroup",
                "container_template_sha256": digest,
            }
            for index, (container, digest) in enumerate(
                sorted(expected_contract.items()), 1
            )
        ]
        return ledger, expected_contract, parameters, description, changes

    def test_exact_parameter_builder_includes_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "template.yaml"
            template.write_text(
                """AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Required: {Type: String}
  Count: {Type: Number, Default: 12}
  Enabled: {Type: String, Default: 'false'}
Resources: {}
"""
            )
            values = LIVE.expected_create_parameter_values(
                template, ["ParameterKey=Required,ParameterValue=exact"]
            )
        self.assertEqual(
            values, {"Required": "exact", "Count": "12", "Enabled": "false"}
        )

    def test_exact_ip_only_starter_change_contract_passes(self):
        ledger, contract, _parameters, description, changes = self.fixture()
        LIVE.require_disposable_starter_change_contract(
            ledger, description, changes, contract
        )

    def test_private_control_dns_is_allowed_but_public_ingress_is_rejected(self):
        ledger, contract, _parameters, description, changes = self.fixture()
        starter_hash = contract["root/RecipeApplication/StarterRuntime"]
        changes.extend(
            [
                {
                    "path": (
                        "root/RecipeApplication/StarterRuntime/"
                        "ControlPrivateHostedZone"
                    ),
                    "resource_type": "AWS::Route53::HostedZone",
                    "container_template_sha256": starter_hash,
                },
                {
                    "path": "root/RecipeApplication/StarterRuntime/ControlDnsRecord",
                    "resource_type": "AWS::Route53::RecordSet",
                    "container_template_sha256": starter_hash,
                },
            ]
        )
        LIVE.require_disposable_starter_change_contract(
            ledger, description, changes, contract
        )
        changes[-1]["path"] = "root/RecipeApplication/StarterRuntime/SipDnsRecord"
        with self.assertRaisesRegex(LIVE.LiveTestError, "HA, DNS"):
            LIVE.require_disposable_starter_change_contract(
                ledger, description, changes, contract
            )

    def test_ha_topology_and_certificate_types_are_rejected(self):
        ledger, contract, _parameters, description, changes = self.fixture()
        changes[0]["path"] = "root/RecipeApplication/HighAvailabilityRuntime/Cluster"
        with self.assertRaisesRegex(LIVE.LiveTestError, "topology"):
            LIVE.require_disposable_starter_change_contract(
                ledger, description, changes, contract
            )
        ledger, contract, _parameters, description, changes = self.fixture()
        changes[0]["resource_type"] = "AWS::CertificateManager::Certificate"
        with self.assertRaisesRegex(LIVE.LiveTestError, "HA, DNS"):
            LIVE.require_disposable_starter_change_contract(
                ledger, description, changes, contract
            )

    def test_template_chain_or_ip_posture_drift_is_rejected(self):
        ledger, contract, _parameters, description, changes = self.fixture()
        changes.pop()
        with self.assertRaisesRegex(LIVE.LiveTestError, "topology"):
            LIVE.require_disposable_starter_change_contract(
                ledger, description, changes, contract
            )
        ledger, contract, _parameters, description, changes = self.fixture()
        changes[0]["container_template_sha256"], changes[1][
            "container_template_sha256"
        ] = (
            changes[1]["container_template_sha256"],
            changes[0]["container_template_sha256"],
        )
        with self.assertRaisesRegex(LIVE.LiveTestError, "topology"):
            LIVE.require_disposable_starter_change_contract(
                ledger, description, changes, contract
            )
        ledger, contract, _parameters, description, changes = self.fixture()
        next(
            item
            for item in description["Parameters"]
            if item["ParameterKey"] == "SipSecurity"
        )["ParameterValue"] = "sips_srtp"
        with self.assertRaisesRegex(LIVE.LiveTestError, "IP-only"):
            LIVE.require_disposable_starter_change_contract(
                ledger, description, changes, contract
            )

    def test_browser_safe_public_key_is_not_masked_by_noecho(self):
        for relative in (
            "cloudformation/demo-template.yaml",
            "cloudformation/template.yaml",
            "cloudformation/nested/demo-site.yaml",
        ):
            document = LIVE.cloudformation_document(
                (ROOT / "recipes/vapi-amazon-connect-screen-pop" / relative).read_text()
            )
            self.assertNotIn("NoEcho", document["Parameters"]["VapiPublicKey"])


if __name__ == "__main__":
    unittest.main()
