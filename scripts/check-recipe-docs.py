#!/usr/bin/env python3
"""Validate local links and support/runbook claims for recipe documentation."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import shlex
from pathlib import Path


LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
RUNBOOK = re.compile(r"runbooks/([a-z0-9-]+\.md)")
LIVE_COMMAND_PREFIX = "python3 scripts/aws-recipe-live-test.py"
PROFILE_BOUND_LIVE_PREFIX = f'AWS_PROFILE="$AWS_PROFILE" {LIVE_COMMAND_PREFIX}'
PROFILE_NAME_PATTERN = r"AWS(?:_[A-Z0-9]+)*_PROFILE"
IP_ONLY_FORBIDDEN_INIT_OPTIONS = {
    "--delegated-zone-name",
    "--hosted-zone-id",
    "--secure-sips-proof",
    "--sip-hostname",
}
SAFE_EXAMPLE_ACCOUNT_IDS = {"000000000000", "111122223333", "123456789012"}
AWS_ACCOUNT_ID = re.compile(r"(?<![A-Za-z0-9-])([0-9]{12})(?![A-Za-z0-9-])")
AWS_ORGANIZATION_ID = re.compile(r"\b(?:o-[a-z0-9]{10,}|ou-[a-z0-9-]{8,})\b")
AWS_SSO_ROLE = re.compile(r"\bAWSReservedSSO_[A-Za-z0-9+=,.@_-]+_[0-9a-f]{16}\b")
CONCRETE_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
DATED_EXECUTION_ID = re.compile(r"\bbft-20(?!99)[0-9]{6}[a-z]\b")


def public_document_identifier_failures(root: Path) -> list[str]:
    """Reject live-looking operator identifiers from repository Markdown."""
    failures: list[str] = []
    ignored_parts = {".git", "node_modules", "target"}
    for document in sorted(root.rglob("*.md")):
        relative = document.relative_to(root)
        if ignored_parts.intersection(relative.parts):
            continue
        text = document.read_text()
        for account_id in AWS_ACCOUNT_ID.findall(text):
            if account_id not in SAFE_EXAMPLE_ACCOUNT_IDS:
                failures.append(
                    f"{relative}: contains a non-example 12-digit account identifier"
                )
        if AWS_ORGANIZATION_ID.search(text):
            failures.append(f"{relative}: contains a concrete AWS organization/OU ID")
        if AWS_SSO_ROLE.search(text):
            failures.append(f"{relative}: contains a concrete AWS SSO role name")
        if re.search(r"/Users/[^/\s]+/", text):
            failures.append(f"{relative}: contains an operator-local macOS path")
        if re.search(r"\beipalloc-[0-9a-f]{8,}\b", text):
            failures.append(f"{relative}: contains a concrete EIP allocation ID")
        for value in CONCRETE_UUID.findall(text):
            if len(set(value.replace("-", "").lower())) != 1:
                failures.append(f"{relative}: contains a concrete UUID-style identifier")
        if DATED_EXECUTION_ID.search(text):
            failures.append(f"{relative}: contains a dated live-style execution ID")
    return failures


def logical_commands(text: str, prefix: str):
    """Yield shell commands whose physical lines use ordinary backslash joins."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        command_offset = stripped.find(prefix)
        if command_offset < 0:
            index += 1
            continue
        leading = stripped[:command_offset].strip()
        if leading and re.fullmatch(
            r'(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|\'[^\']*\'|\S+)\s*)+',
            leading,
        ) is None:
            index += 1
            continue
        stripped = stripped[command_offset:]
        line_number = index + 1
        parts: list[str] = []
        while stripped.endswith("\\"):
            parts.append(stripped[:-1].rstrip())
            index += 1
            if index >= len(lines):
                break
            stripped = lines[index].strip()
        if stripped:
            parts.append(stripped)
        yield line_number, " ".join(parts)
        index += 1


def option_value(tokens: list[str], option: str) -> str | None:
    if option not in tokens:
        return None
    index = tokens.index(option)
    if index + 1 >= len(tokens):
        return None
    return tokens[index + 1]


def bounded_section(text: str, start_marker: str, end_marker: str) -> str | None:
    """Return one explicitly bounded Markdown section, or None if ambiguous."""
    start = text.find(start_marker)
    if start < 0 or text.find(start_marker, start + len(start_marker)) >= 0:
        return None
    end = text.find(end_marker, start + len(start_marker))
    if end < 0:
        return None
    return text[start:end]


def controller_profile_failures(text: str, label: str) -> list[str]:
    """Require every actionable guarded-controller line to pin AWS_PROFILE."""
    failures: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if LIVE_COMMAND_PREFIX not in line:
            continue
        if not line.strip().startswith(PROFILE_BOUND_LIVE_PREFIX):
            failures.append(
                f"{label} controller command does not pin AWS_PROFILE: "
                f"line {line_number}"
            )
    return failures


def actionable_aws_command(tokens: list[str]) -> bool:
    """Identify live authentication/identity/CloudFormation shell commands."""
    return (
        tokens[:2] == ["aws", "login"]
        or tokens[:3] == ["aws", "sso", "login"]
        or tokens[:3] == ["aws", "sts", "get-caller-identity"]
        or tokens[:3] == ["aws", "cloudformation", "execute-change-set"]
        or tokens[:3] == ["aws", "cloudformation", "wait"]
    )


def exported_profile_lines(text: str) -> dict[str, int]:
    """Index explicitly exported AWS profile variables by first line."""
    exports: dict[str, int] = {}
    pattern = re.compile(rf"^\s*export\s+({PROFILE_NAME_PATTERN})\s*=")
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = pattern.match(line)
        if match is not None:
            exports.setdefault(match.group(1), line_number)
    return exports


def referenced_profile_name(value: str | None) -> str | None:
    """Return the name from $AWS_PROFILE or ${AWS_PROFILE}."""
    if value is None:
        return None
    match = re.fullmatch(
        rf"(?:\$({PROFILE_NAME_PATTERN})|\$\{{({PROFILE_NAME_PATTERN})\}})", value
    )
    if match is None:
        return None
    return match.group(1) or match.group(2)


def raw_aws_profile_failures(text: str, label: str) -> list[str]:
    """Require actionable raw AWS commands to use a prior exported profile."""
    failures: list[str] = []
    exports = exported_profile_lines(text)
    for line_number, command in logical_commands(text, "aws "):
        try:
            tokens = shlex.split(command)
        except ValueError:
            failures.append(f"{label} has an invalid raw AWS command: line {line_number}")
            continue
        if not actionable_aws_command(tokens):
            continue
        profile_name = referenced_profile_name(option_value(tokens, "--profile"))
        if profile_name is None or exports.get(profile_name, line_number + 1) >= line_number:
            failures.append(
                f"{label} actionable AWS command does not use a prior exported "
                f"profile: line {line_number}"
            )
    return failures


def exported_command_substitution(text: str, variable: str) -> str | None:
    """Return one exact multiline export command substitution body."""
    pattern = re.compile(
        rf'^\s*export\s+{re.escape(variable)}="\$\([ \t]*\n'
        r"(?P<body>.*?)"
        r'^\s*\)"\s*$',
        re.MULTILINE | re.DOTALL,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        return None
    return matches[0].group("body")


def json_bracket_lookup(body: str, field: str) -> bool:
    """Return whether a command body indexes one exact JSON field."""
    return (
        re.search(rf"""\[\s*["']{re.escape(field)}["']\s*\]""", body)
        is not None
    )


def quoted_json_field(body: str, field: str) -> bool:
    """Return whether a command body names a JSON field in a string literal."""
    return re.search(rf"""["']{re.escape(field)}["']""", body) is not None


def extraction_reads_exact_review(body: str, field: str) -> bool:
    """Require the canonical JSON extractor to read only the bound review file."""
    try:
        tokens = shlex.split(body.replace("\\\n", " "))
    except ValueError:
        return False
    expected_program = (
        "import json,sys; "
        f'print(json.load(open(sys.argv[1]))["{field}"])'
    )
    return (
        len(tokens) == 4
        and tokens[:2] == ["python3", "-c"]
        and tokens[2] == expected_program
        and tokens[3] == "$BOOTSTRAP_REFRESH_REVIEW"
    )


def controller_operation(tokens: list[str]) -> str | None:
    """Return the guarded controller subcommand from one parsed invocation."""
    try:
        execution_index = tokens.index("--execution-id")
    except ValueError:
        return None
    operation_index = execution_index + 2
    if operation_index >= len(tokens):
        return None
    return tokens[operation_index]


def documentation_portability_failures(
    runbook_text: str, recipe_readme: str
) -> list[str]:
    """Validate portable fresh-path posture and explicit AWS profile authority."""
    failures: list[str] = []
    path_b = bounded_section(
        runbook_text,
        "### Path B authentication",
        "### Common IP-only initialization",
    )
    if path_b is None:
        failures.append("IP-only runbook has no uniquely bounded Path B authentication")
    else:
        if "OLD_EXECUTION" in path_b:
            failures.append("fresh Path B must not use OLD_EXECUTION")
        if "export AWS_PROFILE='<fresh-account-federated-profile>'" not in path_b:
            failures.append("fresh Path B must export its approved federated AWS profile")

    current_execution = bounded_section(
        runbook_text,
        "### Common IP-only initialization",
        "## AWS permissions",
    )
    if current_execution is None:
        failures.append("IP-only runbook has no uniquely bounded fresh execution section")
    else:
        if "OLD_EXECUTION" in current_execution:
            failures.append("common fresh execution section must not use OLD_EXECUTION")
        controller_commands: list[tuple[int, list[str]]] = []
        init_commands: list[tuple[int, list[str]]] = []
        for line_number, command in logical_commands(
            current_execution, LIVE_COMMAND_PREFIX
        ):
            try:
                tokens = shlex.split(command)
            except ValueError:
                failures.append(
                    "canonical IP-only init is not a valid shell command: "
                    f"line {line_number}"
                )
                continue
            controller_commands.append((line_number, tokens))
            if "init" in tokens[2:]:
                init_commands.append((line_number, tokens))
        confirmation_required = {
            "bootstrap-refresh",
            "bootstrap-refresh-verify",
            "destroy",
            "execute",
            "lifecycle-test",
            "run-headless",
        }
        for line_number, tokens in controller_commands:
            operation = controller_operation(tokens)
            if option_value(tokens, "--execution-id") != "$NEW_EXECUTION":
                failures.append(
                    "canonical fresh controller command must use "
                    f"--execution-id $NEW_EXECUTION: line {line_number}"
                )
            if (
                operation in confirmation_required
                and option_value(tokens, "--confirm") != "$NEW_EXECUTION"
            ):
                failures.append(
                    "canonical fresh controller confirmation must use "
                    f"$NEW_EXECUTION: line {line_number}"
                )
        if len(init_commands) != 1:
            failures.append("IP-only runbook must contain one canonical fresh init command")
        else:
            _line_number, init_tokens = init_commands[0]
            expected_init_tokens = [
                "python3",
                "scripts/aws-recipe-live-test.py",
                "--execution-id",
                "$NEW_EXECUTION",
                "init",
                "--region",
                "us-west-2",
                "--max-usd",
                "200",
                "--planned-hours",
                "8",
                "--connect-minutes",
                "30",
                "--runtime-profile",
                "starter",
                "--create-connect-demo",
                "--enable-demo-site",
            ]
            if init_tokens != expected_init_tokens:
                failures.append(
                    "canonical IP-only init must use only the exact approved "
                    "federated Starter option contract"
                )
            if option_value(init_tokens, "--execution-id") != "$NEW_EXECUTION":
                failures.append("canonical IP-only init must use the fresh execution ID")
            if option_value(init_tokens, "--runtime-profile") != "starter":
                failures.append("canonical IP-only init must select the Starter profile")
            if option_value(init_tokens, "--region") != "us-west-2":
                failures.append("canonical IP-only init must use region us-west-2")
            if "--create-connect-demo" not in init_tokens:
                failures.append("canonical IP-only init must create disposable Connect")
            if "--enable-demo-site" not in init_tokens:
                failures.append("canonical live init must enable the CloudFront demo site")
            forbidden = sorted(IP_ONLY_FORBIDDEN_INIT_OPTIONS.intersection(init_tokens))
            if forbidden or "high_availability" in init_tokens:
                failures.append(
                    "canonical IP-only init contains DNS, SIPS, or HA input: "
                    + ", ".join(forbidden or ["high_availability"])
                )

        admin_tokens: dict[str, list[list[str]]] = {
            "execute-change-set": [],
            "wait": [],
        }
        workflow_events = [
            (line_number, controller_operation(tokens) or "invalid-controller")
            for line_number, tokens in controller_commands
        ]
        for line_number, command in logical_commands(
            current_execution, "aws cloudformation"
        ):
            try:
                tokens = shlex.split(command)
            except ValueError:
                failures.append(
                    "canonical bootstrap refresh admin command is invalid: "
                    f"line {line_number}"
                )
                continue
            if len(tokens) >= 3 and tokens[2] in admin_tokens:
                admin_tokens[tokens[2]].append(tokens)
                if tokens[2] == "execute-change-set":
                    workflow_events.append(
                        (line_number, "admin-execute-change-set")
                    )
                else:
                    wait_operation = tokens[3] if len(tokens) >= 4 else "missing"
                    workflow_events.append(
                        (line_number, f"admin-wait-{wait_operation}")
                    )

        workflow: list[str] = []
        for _line_number, operation in sorted(workflow_events):
            if operation == "run-headless":
                matching_tokens = next(
                    tokens
                    for line_number, tokens in controller_commands
                    if line_number == _line_number
                )
                workflow.append(
                    f"run-headless-{option_value(matching_tokens, '--suite')}"
                )
            else:
                workflow.append(operation)
        expected_workflow = [
            "init",
            "bootstrap",
            "publish",
            "bootstrap-refresh",
            "admin-execute-change-set",
            "admin-wait-stack-update-complete",
            "bootstrap-refresh-verify",
            "change-set",
            "execute",
            "verify",
            "run-headless-smoke",
            "run-headless-full",
            "lifecycle-test",
            "verify",
            "destroy",
        ]
        if workflow != expected_workflow:
            failures.append(
                "canonical fresh workflow must uniquely order init, bootstrap, "
                "publish, bootstrap refresh, exact admin execute/update wait, "
                "refresh verify, application change set, execute, verify, smoke, "
                "full, lifecycle, verify, and destroy"
            )
        if "dns-status" in workflow:
            failures.append("canonical no-DNS fresh section must not run dns-status")

        expected_review_assignment = (
            'export BOOTSTRAP_REFRESH_REVIEW="$STATE_ROOT/$NEW_EXECUTION/'
            'bootstrap-refresh-change-set-review.json"'
        )
        review_assignments = [
            line.strip()
            for line in current_execution.splitlines()
            if line.strip().startswith("export BOOTSTRAP_REFRESH_REVIEW=")
        ]
        if review_assignments != [expected_review_assignment]:
            failures.append(
                "BOOTSTRAP_REFRESH_REVIEW must equal "
                "$STATE_ROOT/$NEW_EXECUTION/bootstrap-refresh-change-set-review.json"
            )

        stack_extract = exported_command_substitution(
            current_execution, "FRESH_BOOTSTRAP_STACK_ID"
        )
        if (
            stack_extract is None
            or not json_bracket_lookup(stack_extract, "stack_id")
            or quoted_json_field(stack_extract, "stack_name")
            or '"$BOOTSTRAP_REFRESH_REVIEW"' not in stack_extract
        ):
            failures.append(
                "FRESH_BOOTSTRAP_STACK_ID must come from review JSON stack_id, "
                "never stack_name"
            )
        elif not extraction_reads_exact_review(stack_extract, "stack_id"):
            failures.append(
                "FRESH_BOOTSTRAP_STACK_ID extractor must read exactly "
                "$BOOTSTRAP_REFRESH_REVIEW"
            )
        change_set_extract = exported_command_substitution(
            current_execution, "BOOTSTRAP_REFRESH_CHANGE_SET_ID"
        )
        if (
            change_set_extract is None
            or not json_bracket_lookup(change_set_extract, "change_set_id")
            or quoted_json_field(change_set_extract, "change_set_name")
            or '"$BOOTSTRAP_REFRESH_REVIEW"' not in change_set_extract
        ):
            failures.append(
                "BOOTSTRAP_REFRESH_CHANGE_SET_ID must come from review JSON "
                "change_set_id, never change_set_name"
            )
        elif not extraction_reads_exact_review(change_set_extract, "change_set_id"):
            failures.append(
                "BOOTSTRAP_REFRESH_CHANGE_SET_ID extractor must read exactly "
                "$BOOTSTRAP_REFRESH_REVIEW"
            )

        if (
            len(admin_tokens["execute-change-set"]) == 1
            and len(admin_tokens["wait"]) == 1
        ):
            execute_tokens = admin_tokens["execute-change-set"][0]
            wait_tokens = admin_tokens["wait"][0]
            if len(wait_tokens) < 4 or wait_tokens[3] != "stack-update-complete":
                failures.append(
                    "bootstrap refresh admin wait must use stack-update-complete"
                )
            if (
                option_value(execute_tokens, "--profile") != "$AWS_ADMIN_PROFILE"
                or option_value(wait_tokens, "--profile") != "$AWS_ADMIN_PROFILE"
            ):
                failures.append(
                    "bootstrap refresh execute/wait must use $AWS_ADMIN_PROFILE"
                )
            if (
                option_value(execute_tokens, "--region") != "us-west-2"
                or option_value(wait_tokens, "--region") != "us-west-2"
            ):
                failures.append(
                    "bootstrap refresh execute/wait must use region us-west-2"
                )
            if (
                option_value(execute_tokens, "--stack-name")
                != "$FRESH_BOOTSTRAP_STACK_ID"
                or option_value(wait_tokens, "--stack-name")
                != "$FRESH_BOOTSTRAP_STACK_ID"
            ):
                failures.append(
                    "bootstrap refresh execute/wait must use "
                    "$FRESH_BOOTSTRAP_STACK_ID"
                )
            if (
                option_value(execute_tokens, "--change-set-name")
                != "$BOOTSTRAP_REFRESH_CHANGE_SET_ID"
            ):
                failures.append(
                    "bootstrap refresh execute must use "
                    "$BOOTSTRAP_REFRESH_CHANGE_SET_ID"
                )

    failures.extend(controller_profile_failures(runbook_text, "IP-only runbook"))
    failures.extend(raw_aws_profile_failures(runbook_text, "IP-only runbook"))

    # The canonical customer guide intentionally links to the guarded
    # maintainer runbook instead of duplicating its long, easily stale command
    # sequence. Keep the argument for the mutation-test API and link checks.
    del recipe_readme
    return failures


def local_target(document: Path, raw: str) -> Path | None:
    target = raw.strip().split("#", 1)[0]
    if not target or "://" in target or target.startswith(("mailto:", "#")):
        return None
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    return (document.parent / target).resolve()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    recipe = root / "recipes" / "vapi-amazon-connect-screen-pop"
    live_runbook = recipe / "runbooks" / "nonproduction-live-qualification.md"
    operator_documents = {
        "AWS Starter workplan": root / "BRIDGEFU-AWS-STARTER-WORKPLAN.md",
        "AWS engineering handoff": root / "BRIDGEFU-AWS-ENGINEERING-HANDOFF.md",
        "implementation progress": root / "BRIDGEFU-RECIPE-IMPLEMENTATION-PROGRESS.md",
        "qualification README": recipe / "qualification" / "README.md",
    }
    recipe_readme_path = recipe / "README.md"
    recipe_packages = sorted(
        path.parent for path in (root / "recipes").glob("*/recipe.yaml")
    )
    documents = [
        root / "README.md",
        root / "docs" / "recipes.md",
        root / "docs" / "recipe-authoring.md",
        *operator_documents.values(),
    ]
    for package in recipe_packages:
        documents.extend(sorted(package.glob("*.md")))
        documents.extend(sorted((package / "runbooks").glob("*.md")))
    documents = sorted(set(documents))
    failures: list[str] = []
    failures.extend(public_document_identifier_failures(root))
    for document in documents:
        if not document.exists():
            failures.append(f"missing documentation file: {document.relative_to(root)}")
            continue
        text = document.read_text()
        for raw in LINK.findall(text):
            target = local_target(document, raw)
            if target is not None and not target.exists():
                failures.append(f"{document.relative_to(root)}: missing link target {raw}")

    catalog = (root / "docs" / "recipes.md").read_text()
    for package in recipe_packages:
        manifest = (package / "recipe.yaml").read_text()
        readme = (package / "README.md").read_text()
        expected_tier = "preview"
        if f"support: {expected_tier}" not in manifest:
            failures.append(
                f"{package.name} must declare the expected {expected_tier} tier"
            )
        if expected_tier not in readme.lower():
            failures.append(f"{package.name} README omits the current support tier")
    if "preview" not in catalog.lower() or "supported" not in catalog.lower():
        failures.append("recipe catalog omits current support tiers")

    runbook_names = {path.name for path in (recipe / "runbooks").glob("*.md")}
    templates = [
        recipe / "cloudformation" / "nested" / "observability.yaml",
        recipe / "cloudformation" / "nested" / "runtime-starter.yaml",
    ]
    alarm_text = "\n".join(path.read_text() for path in templates)
    for name in RUNBOOK.findall(alarm_text):
        if name not in runbook_names:
            failures.append(f"CloudWatch alarm references missing runbook {name}")
    descriptions = re.findall(r"AlarmDescription:\s*(?:>-\s*)?([^\n]+)", alarm_text)
    if not descriptions or any("runbooks/" not in description for description in descriptions):
        failures.append("every CloudWatch alarm description must cite a recipe runbook")

    operator_fragments = (
        "${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live",
        "BRIDGEFU_AWS_LIVE_STATE_DIR",
        "permanently retired",
        "bootstrap-only",
        "teardown-only",
        "no application change set was executed",
        "nonproduction-live-qualification.md",
    )
    for label, document in operator_documents.items():
        if not document.exists():
            failures.append(f"missing operator document: {document.relative_to(root)}")
            continue
        text = document.read_text()
        lowered = text.lower()
        normalized_lower = " ".join(lowered.split())
        if "target/aws-live" in text:
            failures.append(
                f"{label} reintroduces the removed repository-local live-state path"
            )
        for fragment in operator_fragments:
            if fragment.lower() not in normalized_lower:
                failures.append(f"{label} omits live-state invariant: {fragment}")
        if "write-only" not in normalized_lower or "not consumed" not in normalized_lower:
            failures.append(f"{label} must say remote capsules are write-only/not consumed")
        if "one operator" not in normalized_lower:
            failures.append(f"{label} must assign recovery to one operator/host")
        if not any(
            phrase in normalized_lower
            for phrase in ("never copy", "never copied", "never be copied")
        ):
            failures.append(f"{label} must prohibit copying host-private state")
        if "not migrated" not in normalized_lower or not any(
            marker in normalized_lower for marker in ("missing", "absent")
        ):
            failures.append(
                f"{label} must mark historical repository-local evidence missing, not migrated"
            )

    runbook_text = ""
    if not live_runbook.exists():
        failures.append(
            "missing IP-only nonproduction runbook: "
            f"{live_runbook.relative_to(root)}"
        )
    else:
        runbook_text = live_runbook.read_text()
        runbook_lower = runbook_text.lower()
        normalized_runbook = " ".join(runbook_lower.split())
        semantic_runbook = normalized_runbook.replace("`", "")
        runbook_fragments = (
            "${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live",
            "BRIDGEFU_AWS_LIVE_STATE_DIR",
            "bft-20990101a",
            "permanently retired",
            "bootstrap-only",
            "teardown-only",
            "no application change set was executed",
            "recover-lost-ledger-review",
            "recover-lost-ledger-execute",
            "destroy-finalize",
            "write-only",
            "not consumed",
            "60 seconds",
            "fresh execution id",
        )
        for fragment in runbook_fragments:
            if fragment.lower() not in normalized_runbook:
                failures.append(f"IP-only runbook omits invariant: {fragment}")
        if re.search(
            r"three.*?identical.*?(?:observations|projections)",
            normalized_runbook,
        ) is None:
            failures.append("IP-only runbook must require three identical observations")
        if not any(
            phrase in normalized_runbook
            for phrase in ("no dns", "does not authorize ha, dns")
        ):
            failures.append("IP-only runbook must explicitly exclude DNS")
        recovery_order = re.compile(
            r"recover-lost-ledger-review.*?independent.*?"
            r"recover-lost-ledger-execute.*?inventory.*?destroy",
            re.IGNORECASE | re.DOTALL,
        )
        if recovery_order.search(runbook_text) is None:
            failures.append(
                "IP-only runbook must order review, independent review, execute, "
                "inventory, and destroy"
            )

        required_actions = {
            "sts:GetCallerIdentity",
            "iam:GetRole",
            "iam:ListRoles",
            "iam:ListPolicies",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListInstanceProfilesForRole",
            "iam:ListRoleTags",
            "iam:ListEntitiesForPolicy",
            "ec2:DescribeRegions",
            "ec2:DescribeAddresses",
            "cloudformation:DescribeStacks",
            "cloudformation:GetTemplate",
            "cloudformation:ListStackResources",
            "cloudformation:ListChangeSets",
            "cloudformation:ListStacks",
            "tag:GetResources",
            "s3:ListAllMyBuckets",
            "s3:ListBucket",
            "s3:GetBucketTagging",
            "s3:GetBucketLocation",
            "s3:GetBucketVersioning",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetEncryptionConfiguration",
            "s3:ListBucketVersions",
            "s3:ListBucketMultipartUploads",
            "ecr:DescribeRepositories",
            "ecr:ListTagsForResource",
            "ecr:DescribeImages",
            "connect:ListInstances",
            "logs:DescribeLogGroups",
            "secretsmanager:ListSecrets",
            "codebuild:BatchGetProjects",
            "route53:ListHostedZones",
            "cloudfront:ListDistributions",
            "cloudfront:ListCachePolicies",
            "cloudfront:ListResponseHeadersPolicies",
            "cloudfront:ListOriginAccessControls",
            "ecr:DeleteRepository",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:DeleteBucket",
            "cloudformation:DeleteStack",
            "iam:DetachRolePolicy",
            "iam:DeleteRolePolicy",
            "iam:DeleteRole",
            "iam:GetPolicy",
            "iam:ListPolicyVersions",
            "iam:DeletePolicyVersion",
            "iam:DeletePolicy",
            "ec2:ReleaseAddress",
            "ec2:DescribeInstances",
            "ec2:DescribeNatGateways",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeSubnets",
            "ec2:DescribeVolumes",
            "connect:DescribeInstance",
            "codebuild:ListBuildsForProject",
            "codebuild:BatchGetBuilds",
            "secretsmanager:DescribeSecret",
        }
        missing_actions = sorted(required_actions - set(re.findall(
            r"[a-z0-9]+:[A-Za-z0-9]+", runbook_text
        )))
        if missing_actions:
            failures.append(
                "IP-only runbook omits controller permissions: "
                + ", ".join(missing_actions)
            )

        runbook_semantics = ("export AWS_PROFILE", "checked_at", "not byte-identical")
        for fragment in runbook_semantics:
            if fragment.lower() not in semantic_runbook:
                failures.append(f"IP-only runbook omits entry/profile/proof rule: {fragment}")
        entry_path_patterns = {
            "eligible lost-ledger recovery entry": (
                r"path a.*?eligible lost-ledger recovery.*?bft-20990101a"
            ),
            "fresh-user/account entry that skips recovery": (
                r"path b.*?fresh user/account.*?skip(?:s)? phases 1.?5"
            ),
        }
        for label, pattern in entry_path_patterns.items():
            if re.search(pattern, semantic_runbook) is None:
                failures.append(f"IP-only runbook omits {label}")
        if (
            "default profile" not in semantic_runbook
            or "aws_profile unchanged" not in semantic_runbook
        ):
            failures.append(
                "IP-only runbook must prevent default-profile fallback and keep "
                "the controller AWS_PROFILE unchanged"
            )
        if re.search(
            r"three.*?stable.*?identical.*?projections|"
            r"three.*?identical.*?stable.*?projections",
            semantic_runbook,
        ) is None:
            failures.append(
                "IP-only runbook must require three stable identical inventory projections"
            )
        if re.search(
            r"(?:exclude|excluding|remove|removing).*?checked_at",
            semantic_runbook,
        ) is None:
            failures.append(
                "IP-only runbook must exclude checked_at before comparing projections"
            )

    recipe_readme = recipe_readme_path.read_text()
    qualification_readme = operator_documents["qualification README"].read_text()
    failures.extend(documentation_portability_failures(runbook_text, recipe_readme))

    invalid_verify = re.compile(r"\bverify\s+(?:\\\s*)?--confirm\b")
    if invalid_verify.search(qualification_readme):
        failures.append("qualification README passes parser-invalid --confirm to verify")

    live_script = root / "scripts" / "aws-recipe-live-test.py"
    specification = importlib.util.spec_from_file_location(
        "bridgefu_aws_recipe_live_test", live_script
    )
    if specification is None or specification.loader is None:
        failures.append("cannot load guarded AWS controller parser")
    else:
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        live_parser = module.parser()
        parser_substitutions = {
            "$EXPECT_DEMO_SITE": "false",
            "$RUNTIME_PROFILE": "starter",
            "$SUITE": "smoke",
        }
        for document in documents:
            if not document.exists():
                continue
            for line_number, command in logical_commands(
                document.read_text(), LIVE_COMMAND_PREFIX
            ):
                try:
                    tokens = shlex.split(command)
                except ValueError as error:
                    failures.append(
                        f"{document.relative_to(root)}:{line_number}: "
                        f"invalid shell command: {error}"
                    )
                    continue
                arguments = [
                    parser_substitutions.get(token, token) for token in tokens[2:]
                ]
                parser_error = io.StringIO()
                try:
                    with contextlib.redirect_stderr(parser_error):
                        live_parser.parse_args(arguments)
                except SystemExit:
                    detail = parser_error.getvalue().strip().splitlines()
                    failures.append(
                        f"{document.relative_to(root)}:{line_number}: "
                        "parser-invalid controller command"
                        + (f": {detail[-1]}" if detail else "")
                    )

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"validated {len(documents)} recipe documentation files and alarm runbooks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
