from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CHECKER_PATH = ROOT / "scripts" / "check-recipe-docs.py"
SPEC = importlib.util.spec_from_file_location("check_recipe_docs", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

RUNBOOK_PATH = (
    ROOT
    / "recipes"
    / "vapi-amazon-connect-screen-pop"
    / "runbooks"
    / "nonproduction-live-qualification.md"
)
README_PATH = ROOT / "recipes" / "vapi-amazon-connect-screen-pop" / "README.md"


class RecipeDocsCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runbook = RUNBOOK_PATH.read_text()
        self.readme = README_PATH.read_text()

    def failures(self, runbook: str | None = None, readme: str | None = None):
        return CHECKER.documentation_portability_failures(
            self.runbook if runbook is None else runbook,
            self.readme if readme is None else readme,
        )

    def test_checked_in_portability_contract_is_valid(self):
        self.assertEqual(self.failures(), [])

    def test_public_document_identifier_guard_accepts_only_synthetic_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.md").write_text(
                "Accounts 000000000000, 111122223333, and 123456789012; "
                "execution bft-20990101a; UUID "
                "00000000-0000-0000-0000-000000000000; fixture IDs "
                "11111111-1111-1111-1111-111111111111 and "
                "22222222-2222-2222-2222-222222222222.\n"
            )
            self.assertEqual(CHECKER.public_document_identifier_failures(root), [])

    def test_public_document_identifier_guard_rejects_live_shaped_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unsafe.md").write_text(
                "Account 210987"
                "654321; organization o-abcdefghij; "
                "role AWSReservedSSO_Admin_0123456789abcdef; "
                "path /Users/operator/private; EIP eipalloc-0123456789abcdef0; "
                "UUID 01234567-89ab-4def-8123-456789abcdef; "
                "execution bft-20260101a.\n"
            )
            failures = CHECKER.public_document_identifier_failures(root)
            self.assertEqual(len(failures), 7)

    def test_fresh_path_b_cannot_reference_old_execution(self):
        path_b = CHECKER.bounded_section(
            self.runbook,
            "### Path B authentication",
            "### Common IP-only initialization",
        )
        assert path_b is not None
        mutated_path_b = path_b.replace("NEW_EXECUTION", "OLD_EXECUTION", 1)
        failures = self.failures(runbook=self.runbook.replace(path_b, mutated_path_b, 1))
        self.assertIn("fresh Path B must not use OLD_EXECUTION", failures)

    def test_canonical_ip_only_init_requires_demo_site_and_rejects_dns_flags(self):
        missing_demo = self.runbook.replace(
            "  --create-connect-demo \\\n  --enable-demo-site\n",
            "  --create-connect-demo\n",
            1,
        )
        self.assertIn(
            "canonical live init must enable the CloudFront demo site",
            self.failures(runbook=missing_demo),
        )
        mutated = self.runbook.replace(
            "  --enable-demo-site\n",
            "  --enable-demo-site \\\n  --hosted-zone-id Z123EXAMPLE\n",
            1,
        )
        self.assertTrue(
            any(
                "canonical IP-only init contains DNS, SIPS, or HA input"
                in failure
                for failure in self.failures(runbook=mutated)
            )
        )

    def test_canonical_ip_only_init_rejects_root_bootstrap_exception(self):
        mutated = self.runbook.replace(
            "  --runtime-profile starter \\\n  --create-connect-demo \\\n",
            "  --runtime-profile starter \\\n"
            "  --allow-root-bootstrap \\\n"
            "  --create-connect-demo \\\n",
            1,
        )
        self.assertIn(
            "canonical IP-only init must use only the exact approved federated "
            "Starter option contract",
            self.failures(runbook=mutated),
        )

    def test_canonical_ip_only_init_rejects_additional_valid_option(self):
        mutated = self.runbook.replace(
            "  --create-connect-demo \\\n  --enable-demo-site\n",
            "  --create-connect-demo \\\n"
            "  --target-flow-arn arn:aws:connect:us-west-2:111122223333:"
            "instance/example/contact-flow/example \\\n"
            "  --enable-demo-site\n",
            1,
        )
        self.assertIn(
            "canonical IP-only init must use only the exact approved federated "
            "Starter option contract",
            self.failures(runbook=mutated),
        )

    def test_refresh_verify_must_precede_application_change_set(self):
        mutated = self.runbook.replace(
            '  bootstrap-refresh-verify --confirm "$NEW_EXECUTION"',
            "  change-set",
            1,
        ).replace(
            '  --execution-id "$NEW_EXECUTION" change-set',
            '  --execution-id "$NEW_EXECUTION" \\\n'
            '  bootstrap-refresh-verify --confirm "$NEW_EXECUTION"',
            1,
        )
        self.assertIn(
            "canonical fresh workflow must uniquely order init, bootstrap, publish, "
            "bootstrap refresh, exact admin execute/update wait, refresh verify, "
            "application change set, execute, verify, smoke, full, lifecycle, "
            "verify, and destroy",
            self.failures(runbook=mutated),
        )

    def test_bootstrap_stack_id_must_use_review_stack_id_field(self):
        mutated = self.runbook.replace('["stack_id"]', '["stack_name"]', 1)
        self.assertIn(
            "FRESH_BOOTSTRAP_STACK_ID must come from review JSON stack_id, "
            "never stack_name",
            self.failures(runbook=mutated),
        )

    def test_bootstrap_change_set_id_must_use_review_change_set_id_field(self):
        mutated = self.runbook.replace(
            '["change_set_id"]', '["change_set_name"]', 1
        )
        self.assertIn(
            "BOOTSTRAP_REFRESH_CHANGE_SET_ID must come from review JSON "
            "change_set_id, never change_set_name",
            self.failures(runbook=mutated),
        )

    def test_id_extractor_must_open_its_review_argument(self):
        mutated = self.runbook.replace(
            'json.load(open(sys.argv[1]))["stack_id"]',
            'json.load(open("/tmp/not-reviewed.json"))["stack_id"]',
            1,
        )
        self.assertIn(
            "FRESH_BOOTSTRAP_STACK_ID extractor must read exactly "
            "$BOOTSTRAP_REFRESH_REVIEW",
            self.failures(runbook=mutated),
        )

    def test_admin_wait_operation_must_be_stack_update_complete(self):
        mutated = self.runbook.replace(
            "aws cloudformation wait stack-update-complete",
            "aws cloudformation wait stack-create-complete",
            1,
        )
        self.assertIn(
            "bootstrap refresh admin wait must use stack-update-complete",
            self.failures(runbook=mutated),
        )

    def test_admin_wait_must_use_admin_profile(self):
        mutated = self.runbook.replace(
            'aws cloudformation wait stack-update-complete \\\n'
            '  --profile "$AWS_ADMIN_PROFILE"',
            'aws cloudformation wait stack-update-complete \\\n'
            '  --profile "$AWS_PROFILE"',
            1,
        )
        self.assertIn(
            "bootstrap refresh execute/wait must use $AWS_ADMIN_PROFILE",
            self.failures(runbook=mutated),
        )

    def test_ip_only_init_region_must_be_us_west_2(self):
        mutated = self.runbook.replace(
            "  init \\\n  --region us-west-2 \\\n",
            "  init \\\n  --region us-east-1 \\\n",
            1,
        )
        self.assertIn(
            "canonical IP-only init must use region us-west-2",
            self.failures(runbook=mutated),
        )

    def test_fresh_workflow_requires_full_headless_run(self):
        full_run = (
            'AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \\\n'
            '  --execution-id "$NEW_EXECUTION" \\\n'
            '  run-headless --suite full --confirm "$NEW_EXECUTION"\n\n'
        )
        mutated = self.runbook.replace(full_run, "", 1)
        self.assertTrue(
            any(
                "canonical fresh workflow must uniquely order" in failure
                for failure in self.failures(runbook=mutated)
            )
        )

    def test_fresh_workflow_requires_smoke_then_full_headless_suites(self):
        mutated = self.runbook.replace(
            'run-headless --suite full --confirm "$NEW_EXECUTION"',
            'run-headless --suite smoke --confirm "$NEW_EXECUTION"',
            1,
        )
        self.assertTrue(
            any(
                "canonical fresh workflow must uniquely order" in failure
                for failure in self.failures(runbook=mutated)
            )
        )

    def test_fresh_workflow_requires_destroy(self):
        destroy = (
            'AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \\\n'
            '  --execution-id "$NEW_EXECUTION" \\\n'
            '  destroy --confirm "$NEW_EXECUTION"\n'
        )
        mutated = self.runbook.replace(destroy, "", 1)
        self.assertTrue(
            any(
                "canonical fresh workflow must uniquely order" in failure
                for failure in self.failures(runbook=mutated)
            )
        )

    def test_application_change_set_must_precede_execute(self):
        mutated = self.runbook.replace(
            '--execution-id "$NEW_EXECUTION" change-set',
            '--execution-id "$NEW_EXECUTION" execute --confirm "$NEW_EXECUTION"',
            1,
        ).replace(
            '  execute --confirm "$NEW_EXECUTION"',
            "  change-set",
            1,
        )
        self.assertTrue(
            any(
                "canonical fresh workflow must uniquely order" in failure
                for failure in self.failures(runbook=mutated)
            )
        )

    def test_no_dns_fresh_workflow_rejects_dns_status(self):
        bootstrap = (
            'AWS_PROFILE="$AWS_PROFILE" python3 scripts/aws-recipe-live-test.py \\\n'
            '  --execution-id "$NEW_EXECUTION" bootstrap\n'
        )
        dns_status = (
            '\nAWS_PROFILE="$AWS_PROFILE" '
            "python3 scripts/aws-recipe-live-test.py \\\n"
            '  --execution-id "$NEW_EXECUTION" dns-status\n'
        )
        mutated = self.runbook.replace(bootstrap, bootstrap + dns_status, 1)
        self.assertIn(
            "canonical no-DNS fresh section must not run dns-status",
            self.failures(runbook=mutated),
        )

    def test_fresh_bootstrap_execution_id_cannot_use_old_execution(self):
        mutated = self.runbook.replace(
            '--execution-id "$NEW_EXECUTION" bootstrap',
            '--execution-id "$OLD_EXECUTION" bootstrap',
            1,
        )
        failures = self.failures(runbook=mutated)
        self.assertIn(
            "common fresh execution section must not use OLD_EXECUTION", failures
        )
        self.assertTrue(
            any(
                "canonical fresh controller command must use "
                "--execution-id $NEW_EXECUTION" in failure
                for failure in failures
            )
        )

    def test_bootstrap_refresh_confirmation_cannot_use_old_execution(self):
        mutated = self.runbook.replace(
            'bootstrap-refresh --confirm "$NEW_EXECUTION"',
            'bootstrap-refresh --confirm "$OLD_EXECUTION"',
            1,
        )
        failures = self.failures(runbook=mutated)
        self.assertIn(
            "common fresh execution section must not use OLD_EXECUTION", failures
        )
        self.assertTrue(
            any(
                "canonical fresh controller confirmation must use $NEW_EXECUTION"
                in failure
                for failure in failures
            )
        )

    def test_application_execute_confirmation_cannot_use_old_execution(self):
        mutated = self.runbook.replace(
            'execute --confirm "$NEW_EXECUTION"',
            'execute --confirm "$OLD_EXECUTION"',
            1,
        )
        failures = self.failures(runbook=mutated)
        self.assertIn(
            "common fresh execution section must not use OLD_EXECUTION", failures
        )
        self.assertTrue(
            any(
                "canonical fresh controller confirmation must use $NEW_EXECUTION"
                in failure
                for failure in failures
            )
        )

    def test_bootstrap_refresh_review_path_cannot_use_old_execution(self):
        mutated = self.runbook.replace(
            'export BOOTSTRAP_REFRESH_REVIEW="$STATE_ROOT/$NEW_EXECUTION/'
            'bootstrap-refresh-change-set-review.json"',
            'export BOOTSTRAP_REFRESH_REVIEW="$STATE_ROOT/$OLD_EXECUTION/'
            'bootstrap-refresh-change-set-review.json"',
            1,
        )
        self.assertIn(
            "BOOTSTRAP_REFRESH_REVIEW must equal "
            "$STATE_ROOT/$NEW_EXECUTION/bootstrap-refresh-change-set-review.json",
            self.failures(runbook=mutated),
        )

    def test_bootstrap_refresh_review_path_cannot_use_application_review(self):
        mutated = self.runbook.replace(
            'export BOOTSTRAP_REFRESH_REVIEW="$STATE_ROOT/$NEW_EXECUTION/'
            'bootstrap-refresh-change-set-review.json"',
            'export BOOTSTRAP_REFRESH_REVIEW="$STATE_ROOT/$NEW_EXECUTION/'
            'change-set-review.json"',
            1,
        )
        self.assertIn(
            "BOOTSTRAP_REFRESH_REVIEW must equal "
            "$STATE_ROOT/$NEW_EXECUTION/bootstrap-refresh-change-set-review.json",
            self.failures(runbook=mutated),
        )

if __name__ == "__main__":
    unittest.main()
