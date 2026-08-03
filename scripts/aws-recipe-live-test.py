#!/usr/bin/env python3
"""Guarded AWS lifecycle for the flagship Bridgefu recipe qualification.

AWS mutations require durable private authority under
${XDG_STATE_HOME:-$HOME/.local/state}/bridgefu/aws-live (or the absolute
BRIDGEFU_AWS_LIVE_STATE_DIR override). The normal flow is init -> bootstrap ->
publish -> bootstrap-refresh review -> authorized admin execution ->
bootstrap-refresh-verify -> change-set -> execute -> verify -> lifecycle-test ->
verify -> destroy.

The narrow lost-ledger exception is a two-command, recent bootstrap-only,
teardown-only recovery. Its review and execute phases perform AWS reads only;
execute installs local authority, while destroy remains a separate explicit AWS
mutation. Remote recovery capsules are currently write-only evidence and are not
consumed. A retained three-observation zero proof is required before a fresh ID
can initialize another run.
"""

from __future__ import annotations

import argparse
import base64
import copy
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


PROJECT = "bridgefu-recipe"
MANAGED_BY = "bridgefu-test"
RECIPE = "vapi-amazon-connect-screen-pop@1"
EXECUTION_PATTERN = re.compile(r"^bft-[a-z0-9-]{4,20}$")
AWS_UUID_PATTERN_TEXT = (
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-" r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
SECRET_ENV = "VAPI_PRIVATE_KEY"
PUBLIC_KEY_ENV = "VAPI_PUBLIC_KEY"
LIVE_STATE_OVERRIDE_ENV = "BRIDGEFU_AWS_LIVE_STATE_DIR"
LIVE_STATE_DIRECTORY_PARTS = ("bridgefu", "aws-live")
LEGACY_LIVE_STATE_PARTS = ("target", "aws-live")
MAX_LEGACY_STATE_FILES = 4_096
MAX_LEGACY_STATE_BYTES = 512 * 1024 * 1024
MAX_LEGACY_STATE_DEPTH = 16
LIVE_LOCK_TOKEN_ENV = "BRIDGEFU_AWS_LIVE_LOCK_TOKEN"
MAX_STATE_JSON_BYTES = 16 * 1024 * 1024
MAX_RECOVERY_REVIEW_FILES = 16
RECOVERY_REVIEW_TTL_SECONDS = 15 * 60
RECOVERY_STACK_HISTORY_MAX_AGE = dt.timedelta(days=89)
MAX_RECOVERY_INVENTORY_ITEMS = 100_000
RECOVERY_BOOTSTRAP_RESOURCE_TYPES = {
    "DeploymentRole": "AWS::IAM::Role",
    "CloudFormationExecutionRole": "AWS::IAM::Role",
    "QualificationRole": "AWS::IAM::Role",
    "QualificationRunnerRole": "AWS::IAM::Role",
    "DeploymentControlPolicy": "AWS::IAM::ManagedPolicy",
    "DeploymentArtifactPolicy": "AWS::IAM::ManagedPolicy",
    "DeploymentApplicationPolicy": "AWS::IAM::ManagedPolicy",
    "DeploymentComputePolicy": "AWS::IAM::ManagedPolicy",
    "DeploymentDataPolicy": "AWS::IAM::ManagedPolicy",
    "DeploymentDemoPolicy": "AWS::IAM::ManagedPolicy",
    "DeploymentQualificationRunnerPolicy": "AWS::IAM::ManagedPolicy",
    "QualificationSourceEip": "AWS::EC2::EIP",
}
MAX_ABSOLUTE_USD = 200.0
MAX_INLINE_TEMPLATE_BYTES = 51_200
ROLE_CHAIN_SESSION_SECONDS = 3_600
MAX_RELEASE_OBJECTS = 1_010
MAX_RELEASE_BYTES = 101 * 1024 * 1024
MAX_HEADLESS_EVIDENCE_FILES = 513
MAX_HEADLESS_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_HEADLESS_ARCHIVE_BYTES = 65 * 1024 * 1024
HEADLESS_BUILD_TIMEOUT_MINUTES = 180
HEADLESS_BUILD_TIMEOUT_SECONDS = HEADLESS_BUILD_TIMEOUT_MINUTES * 60
HEADLESS_STOP_TIMEOUT_SECONDS = 10 * 60
HEADLESS_POLL_SECONDS = 15
HEADLESS_CREDENTIAL_REFRESH_SECONDS = 45 * 60
CODEBUILD_TERMINAL_STATUSES = frozenset(
    {"SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"}
)
CODEBUILD_STATUSES = CODEBUILD_TERMINAL_STATUSES | {"IN_PROGRESS"}
HEADLESS_RUN_PHASES = (
    "prepared",
    "input_published",
    "build_started",
    "terminal",
    "verified",
)
MAX_HEADLESS_RUN_HISTORY = 4
MAX_VAPI_RESPONSE_BYTES = 1024 * 1024
VAPI_LIST_LIMIT = 1000
VAPI_RESOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
VAPI_ABSENCE_ATTEMPTS = 24
VAPI_ABSENCE_INTERVAL_SECONDS = 5
MIN_CAPACITY_RESERVE = 1
VPC_QUOTA_CODE = "L-F678F1CE"
EIP_QUOTA_CODE = "L-0263D0A3"
CONNECT_INSTANCE_QUOTA_CODE = "L-AA17A6B9"
NAT_GATEWAY_QUOTA_CODE = "L-FE5A380F"
ACCESS_ANALYZER_CATALOG_LAG_WAIVERS = {
    "The action apigateway:TagResource does not exist.": (
        "deployer-application",
        (
            "Required by the live AWS::ApiGatewayV2::Stage handler and declared "
            "in its regional CloudFormation resource schema; IAM Access "
            "Analyzer's action catalog is lagging."
        ),
    ),
    "The action apigateway:UntagResource does not exist.": (
        "deployer-application",
        (
            "Required by the live AWS::ApiGatewayV2::Stage handler and declared "
            "in its regional CloudFormation resource schema; IAM Access "
            "Analyzer's action catalog is lagging."
        ),
    ),
    "The action connect:ListChildHoursOfOperations does not exist.": (
        "deployer-demo",
        (
            "Required by the live AWS::Connect::HoursOfOperation read handler "
            "and declared in its regional CloudFormation resource schema; IAM "
            "accepts the exact action while Access Analyzer's action catalog is "
            "lagging."
        ),
    ),
    "The action connect:AssociateHoursOfOperations does not exist.": (
        "deployer-demo",
        (
            "Required by the live AWS::Connect::HoursOfOperation update handler "
            "and declared in its regional CloudFormation resource schema; IAM "
            "Access Analyzer's action catalog is lagging."
        ),
    ),
    "The action connect:DisassociateHoursOfOperations does not exist.": (
        "deployer-demo",
        (
            "Required by the live AWS::Connect::HoursOfOperation update handler "
            "and declared in its regional CloudFormation resource schema; IAM "
            "Access Analyzer's action catalog is lagging."
        ),
    ),
    "The action connect:UpdateUserConfig does not exist.": (
        "deployer-demo",
        (
            "Required by the live AWS::Connect::User update handler and declared "
            "in its regional CloudFormation resource schema; IAM Access "
            "Analyzer's action catalog is lagging."
        ),
    ),
}
MUTABLE_SOURCE_DIGEST_PATHS = frozenset({"BRIDGEFU-RECIPE-IMPLEMENTATION-PROGRESS.md"})
ALLOWED_STACK_RESOURCE_TYPES = {
    "AWS::ApiGatewayV2::Api",
    "AWS::ApiGatewayV2::Integration",
    "AWS::ApiGatewayV2::Route",
    "AWS::ApiGatewayV2::Stage",
    "AWS::Backup::BackupPlan",
    "AWS::Backup::BackupSelection",
    "AWS::Backup::BackupVault",
    "AWS::CertificateManager::Certificate",
    "AWS::CloudFormation::Stack",
    "AWS::CloudFront::CachePolicy",
    "AWS::CloudFront::Distribution",
    "AWS::CloudFront::OriginAccessControl",
    "AWS::CloudFront::ResponseHeadersPolicy",
    "AWS::CodeBuild::Project",
    "AWS::CloudWatch::Alarm",
    "AWS::CloudWatch::Dashboard",
    "AWS::Connect::ContactFlow",
    "AWS::Connect::HoursOfOperation",
    "AWS::Connect::Instance",
    "AWS::Connect::IntegrationAssociation",
    "AWS::Connect::Queue",
    "AWS::Connect::RoutingProfile",
    "AWS::Connect::SecurityProfile",
    "AWS::Connect::User",
    "AWS::DynamoDB::Table",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::AutoScaling::LifecycleHook",
    "AWS::EC2::EIP",
    "AWS::EC2::EIPAssociation",
    "AWS::EC2::Instance",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::LaunchTemplate",
    "AWS::EC2::NatGateway",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::Route",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::SecurityGroupEgress",
    "AWS::EC2::SecurityGroupIngress",
    "AWS::EC2::Subnet",
    "AWS::EC2::SubnetRouteTableAssociation",
    "AWS::EC2::VPC",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::VPCGatewayAttachment",
    "AWS::EC2::Volume",
    "AWS::EC2::VolumeAttachment",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::ECS::TaskDefinition",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::ElastiCache::SubnetGroup",
    "AWS::ElastiCache::User",
    "AWS::ElastiCache::UserGroup",
    "AWS::ElasticLoadBalancingV2::Listener",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::Logs::LogGroup",
    "AWS::Logs::MetricFilter",
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBParameterGroup",
    "AWS::RDS::DBSubnetGroup",
    "AWS::Route53::HostedZone",
    "AWS::Route53::RecordSet",
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::SecretsManager::Secret",
    "AWS::SNS::Subscription",
    "AWS::SNS::Topic",
    "Custom::BridgefuDemoSite",
    "Custom::BridgefuVapiResources",
}
TEARDOWN_INVENTORY_KEYS = frozenset(
    {
        "checked_at",
        "tagged_resource_arns",
        "active_stack_names",
        "review_stack_ids",
        "connect_log_group_names",
        "iam_role_names",
        "iam_policy_arns",
        "demo_site_bucket_names",
        "artifact_bucket_names",
        "ecr_repository_names",
        "cloudfront_distribution_ids",
        "cloudfront_cache_policy_ids",
        "cloudfront_response_headers_policy_ids",
        "cloudfront_origin_access_control_ids",
        "private_tls_secret_arns",
        "temporary_secret_arns",
        "connect_instance_arns",
        "elastic_ip_allocation_ids",
        "active_codebuild_build_ids",
        "vapi_resource_ids",
    }
)
BOOTSTRAP_REFRESH_ALLOWED_CHANGES = {
    "root/DeploymentControlPolicy": "AWS::IAM::ManagedPolicy",
    "root/DeploymentArtifactPolicy": "AWS::IAM::ManagedPolicy",
    "root/DeploymentComputePolicy": "AWS::IAM::ManagedPolicy",
    "root/DeploymentDataPolicy": "AWS::IAM::ManagedPolicy",
    "root/QualificationRole": "AWS::IAM::Role",
    "root/DeploymentDemoPolicy": "AWS::IAM::ManagedPolicy",
    "root/DeploymentQualificationRunnerPolicy": "AWS::IAM::ManagedPolicy",
    "root/QualificationRunnerRole": "AWS::IAM::Role",
    "root/QualificationSourceEip": "AWS::EC2::EIP",
}


class LiveTestError(RuntimeError):
    pass


class CloudFormationLoader(yaml.SafeLoader):
    """Load CloudFormation YAML while preserving short-form intrinsics."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise LiveTestError(f"CloudFormation template has duplicate key: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def construct_cloudformation_tag(
    loader: CloudFormationLoader, suffix: str, node: yaml.Node
) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:  # pragma: no cover - PyYAML currently exposes only these node types.
        raise LiveTestError("CloudFormation template has an unsupported YAML node")
    key = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    if suffix == "GetAtt" and isinstance(value, str):
        resource, separator, attribute = value.partition(".")
        if not separator or not resource or not attribute:
            raise LiveTestError("CloudFormation !GetAtt must name resource.attribute")
        value = [resource, attribute]
    return {key: value}


CloudFormationLoader.add_multi_constructor("!", construct_cloudformation_tag)


def cloudformation_document(source: Path | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, Path):
        raw: str | dict[str, Any] = source.read_text()
    else:
        raw = source
    if isinstance(raw, dict):
        document = raw
    else:
        if not isinstance(raw, str):
            raise LiveTestError("CloudFormation template body is unavailable")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            try:
                decoded = yaml.load(raw, Loader=CloudFormationLoader)
            except yaml.YAMLError as error:
                raise LiveTestError(
                    "unable to parse CloudFormation template"
                ) from error
        document = decoded
    if not isinstance(document, dict) or not isinstance(
        document.get("Resources"), dict
    ):
        raise LiveTestError("CloudFormation template has no resource map")
    return document


def canonical_template_sha256(source: Path | str | dict[str, Any]) -> str:
    document = cloudformation_document(source)
    canonical = json.dumps(document, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def template_body_argument(template: Path) -> str:
    """Return an AWS CLI template-body value within the inline API limit."""

    source = template.read_bytes()
    if len(source) <= MAX_INLINE_TEMPLATE_BYTES:
        return f"file://{template}"
    try:
        document = cloudformation_document(source.decode())
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise LiveTestError(
            f"unable to compact oversized CloudFormation template: {template}"
        ) from error
    compact = json.dumps(document, separators=(",", ":"), sort_keys=True)
    if len(compact.encode()) > MAX_INLINE_TEMPLATE_BYTES:
        raise LiveTestError(
            f"CloudFormation template still exceeds the inline limit: {template}"
        )
    return compact


def certificate_evidence_checks(sip_security: str) -> dict[str, bool]:
    if sip_security == "sip_rtp":
        return {"certificate_not_required_for_ip_only": True}
    if sip_security == "sips_srtp":
        return {"exportable_certificate_issued": True}
    raise LiveTestError(f"unsupported SIP security mode: {sip_security}")


def bound_vapi_public_key(ledger: dict[str, Any], *, allow_bind: bool = False) -> str:
    required = (
        bool(ledger.get("enable_demo_site"))
        or ledger.get("connect_mode") == "disposable"
    )
    if not required:
        return ""
    public_key = os.environ.get(PUBLIC_KEY_ENV, "")
    if not re.fullmatch(r"[A-Za-z0-9._~:/+=-]{8,256}", public_key):
        raise LiveTestError(f"{PUBLIC_KEY_ENV} is missing or invalid")
    digest = hashlib.sha256(public_key.encode()).hexdigest()
    expected = ledger.get("vapi_public_key_sha256")
    if expected is None and allow_bind:
        ledger["vapi_public_key_sha256"] = digest
    elif expected != digest:
        raise LiveTestError(
            "Vapi public key differs from the exact key bound at preflight"
        )
    return public_key


def bound_vapi_private_key(ledger: dict[str, Any], *, allow_bind: bool = False) -> str:
    private_key = os.environ.get(SECRET_ENV, "")
    if len(private_key) < 24:
        raise LiveTestError(f"{SECRET_ENV} is missing or too short")
    digest = hashlib.sha256(private_key.encode()).hexdigest()
    expected = ledger.get("vapi_private_key_sha256")
    if expected is None and allow_bind:
        ledger["vapi_private_key_sha256"] = digest
    elif expected != digest:
        raise LiveTestError(
            "Vapi private key differs from the exact key bound at preflight"
        )
    return private_key


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def root_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_live_state_root(candidate: Path) -> Path:
    if not candidate.is_absolute():
        raise LiveTestError("live-state directory must be an absolute path")
    normalized = Path(os.path.abspath(os.fspath(candidate)))
    resolved = normalized.resolve(strict=False)
    if normalized != resolved:
        raise LiveTestError("live-state directory cannot contain symlinks")
    if tuple(resolved.parts[-2:]) != LIVE_STATE_DIRECTORY_PARTS:
        raise LiveTestError("live-state directory must end with bridgefu/aws-live")
    if "target" in resolved.parts:
        raise LiveTestError("live-state directory cannot use any target directory")
    repository = root_dir().resolve()
    if path_is_within(resolved, repository):
        raise LiveTestError("live-state directory must stay outside the repository")
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target:
        cargo_path = Path(cargo_target)
        if not cargo_path.is_absolute():
            cargo_path = repository / cargo_path
        if path_is_within(resolved, cargo_path.resolve(strict=False)):
            raise LiveTestError("live-state directory cannot use CARGO_TARGET_DIR")
    current = resolved
    while not current.exists():
        if current.parent == current:
            raise LiveTestError("live-state directory has no existing owned ancestor")
        current = current.parent
    details = current.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise LiveTestError("live-state ancestor must be a real directory")
    if details.st_uid != os.getuid():
        raise LiveTestError("live-state directory must have a user-owned ancestor")
    if resolved.exists():
        details = resolved.lstat()
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o077
        ):
            raise LiveTestError(
                "existing live-state directory must be user-owned mode 0700"
            )
    return resolved


def live_state_root() -> Path:
    override = os.environ.get(LIVE_STATE_OVERRIDE_ENV)
    if override is not None:
        if not override or "\x00" in override:
            raise LiveTestError("live-state override is invalid")
        return validate_live_state_root(Path(override))
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg is not None:
        if not xdg or not Path(xdg).is_absolute():
            raise LiveTestError("XDG_STATE_HOME must be an absolute path")
        base = Path(xdg)
    else:
        base = Path.home() / ".local" / "state"
    return validate_live_state_root(base.joinpath(*LIVE_STATE_DIRECTORY_PARTS))


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    details = path.lstat()
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
    ):
        raise LiveTestError("live-state path is not a user-owned directory")
    os.chmod(path, 0o700)


def ensure_live_state_root() -> Path:
    state_root = live_state_root()
    ensure_private_directory(state_root.parent)
    ensure_private_directory(state_root)
    return state_root


def open_private_directory(path: Path) -> int:
    """Open a private directory without following a final-component symlink."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LiveTestError(
            f"unable to open private state directory: {path}"
        ) from error
    details = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        os.close(descriptor)
        raise LiveTestError("live-state directory must be user-owned mode 0700")
    return descriptor


def require_private_regular_file(details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_nlink != 1
        or details.st_mode & 0o077
    ):
        raise LiveTestError(f"{label} must be a private user-owned regular file")


def private_file_bytes(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    directory = open_private_directory(path.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        details = os.fstat(descriptor)
        require_private_regular_file(details, label)
        if details.st_size > maximum_bytes:
            raise LiveTestError(f"{label} exceeds its byte boundary")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise LiveTestError(f"{label} exceeds its byte boundary")
        after = os.fstat(descriptor)
        if (details.st_dev, details.st_ino, details.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise LiveTestError(f"{label} changed while it was read")
        return payload
    except FileNotFoundError as error:
        raise LiveTestError(f"{label} does not exist: {path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


@contextlib.contextmanager
def exclusive_state_lock(
    lock_name: str, *, record: dict[str, Any] | None = None
) -> Iterator[int]:
    if re.fullmatch(r"(?:root|bft-[a-z0-9-]{4,20})\.lock", lock_name) is None:
        raise LiveTestError("live-state lock name is invalid")
    state_root = ensure_live_state_root()
    lock_directory = state_root / ".locks"
    ensure_private_directory(lock_directory)
    directory = open_private_directory(lock_directory)
    descriptor = -1
    try:
        descriptor = os.open(
            lock_name,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        require_private_regular_file(os.fstat(descriptor), "live-state lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise LiveTestError(
                "another controller process holds the execution state lock"
            ) from error
        if record is not None:
            encoded = (json.dumps(record, sort_keys=True) + "\n").encode("ascii")
            if len(encoded) > 4_096:
                raise LiveTestError("live-state lock record is too large")
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise LiveTestError("live-state lock record made no progress")
                offset += written
            os.fsync(descriptor)
            os.fsync(directory)
        yield descriptor
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        os.close(directory)


def inherited_execution_lock_is_held(
    execution_id: str, token_value: str, descriptor: int
) -> bool:
    lock_path = live_state_root() / ".locks" / f"{execution_id}.lock"
    try:
        directory = open_private_directory(lock_path.parent)
    except LiveTestError:
        return False
    try:
        details = os.fstat(descriptor)
        require_private_regular_file(details, "live-state lock")
        path_details = os.stat(lock_path.name, dir_fd=directory, follow_symlinks=False)
        if (details.st_dev, details.st_ino) != (
            path_details.st_dev,
            path_details.st_ino,
        ):
            return False
        if details.st_size > 4_096:
            return False
        raw = os.pread(descriptor, 4_097, 0)
        try:
            record = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        holder_pid = record.get("holder_pid") if isinstance(record, dict) else None
        if (
            record.get("execution_id") != execution_id
            or record.get("token") != token_value
            or not isinstance(holder_pid, int)
            or isinstance(holder_pid, bool)
            or holder_pid < 1
        ):
            return False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    except (LiveTestError, OSError):
        return False
    finally:
        os.close(directory)


def live_lock_pass_fds() -> tuple[int, ...]:
    inherited = os.environ.get(LIVE_LOCK_TOKEN_ENV, "")
    match = re.fullmatch(r"bft-[a-z0-9-]{4,20}:[0-9a-f]{64}:([0-9]+)", inherited)
    if match is None:
        return ()
    descriptor = int(match.group(1))
    try:
        os.fstat(descriptor)
    except OSError as error:
        raise LiveTestError("inherited live-state lock descriptor is closed") from error
    return (descriptor,)


@contextlib.contextmanager
def execution_lock(execution_id: str, *, root_scope: bool = False) -> Iterator[None]:
    if EXECUTION_PATTERN.fullmatch(execution_id) is None:
        raise LiveTestError("execution ID cannot address a state lock")
    inherited = os.environ.get(LIVE_LOCK_TOKEN_ENV, "")
    inherited_match = re.fullmatch(
        rf"{re.escape(execution_id)}:([0-9a-f]{{64}}):([0-9]+)", inherited
    )
    if inherited_match is not None:
        if not inherited_execution_lock_is_held(
            execution_id,
            inherited_match.group(1),
            int(inherited_match.group(2)),
        ):
            raise LiveTestError("inherited live-state lock token is not held")
        yield
        return
    if inherited:
        raise LiveTestError("inherited live-state lock token is invalid")
    previous = os.environ.get(LIVE_LOCK_TOKEN_ENV)
    token_value = secrets.token_hex(32)
    with contextlib.ExitStack() as locks:
        if root_scope:
            locks.enter_context(exclusive_state_lock("root.lock"))
        lock_descriptor = locks.enter_context(
            exclusive_state_lock(
                f"{execution_id}.lock",
                record={
                    "schema_version": 1,
                    "execution_id": execution_id,
                    "holder_pid": os.getpid(),
                    "token": token_value,
                },
            )
        )
        os.set_inheritable(lock_descriptor, True)
        token = f"{execution_id}:{token_value}:{lock_descriptor}"
        os.environ[LIVE_LOCK_TOKEN_ENV] = token
        try:
            yield
        finally:
            os.set_inheritable(lock_descriptor, False)
            if previous is None:
                os.environ.pop(LIVE_LOCK_TOKEN_ENV, None)
            else:
                os.environ[LIVE_LOCK_TOKEN_ENV] = previous


def ledger_path(execution_id: str) -> Path:
    if EXECUTION_PATTERN.fullmatch(execution_id) is None:
        raise LiveTestError("execution ID cannot address live state")
    return live_state_root() / execution_id / "ledger.json"


def legacy_ledger_path(execution_id: str) -> Path:
    if EXECUTION_PATTERN.fullmatch(execution_id) is None:
        raise LiveTestError("execution ID cannot address legacy live state")
    return root_dir().joinpath(*LEGACY_LIVE_STATE_PARTS, execution_id, "ledger.json")


def bounded_legacy_state_files(directory: Path) -> list[Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise LiveTestError("legacy live-state execution is not a real directory")
    files: list[Path] = []
    total_bytes = 0
    entries = 0
    pending: list[tuple[Path, int]] = [(directory, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_LEGACY_STATE_DEPTH:
            raise LiveTestError("legacy live state exceeds its directory-depth limit")
        with os.scandir(current) as children:
            for child in children:
                entries += 1
                if entries > MAX_LEGACY_STATE_FILES * 2:
                    raise LiveTestError("legacy live state exceeds its entry limit")
                item = Path(child.path)
                details = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(details.st_mode):
                    raise LiveTestError("legacy live state contains a symlink")
                if stat.S_ISDIR(details.st_mode):
                    pending.append((item, depth + 1))
                    continue
                if not stat.S_ISREG(details.st_mode):
                    raise LiveTestError("legacy live state contains a special file")
                if details.st_uid != os.getuid() or details.st_nlink != 1:
                    raise LiveTestError("legacy live state contains an unsafe file")
                files.append(item)
                total_bytes += details.st_size
                if (
                    len(files) > MAX_LEGACY_STATE_FILES
                    or total_bytes > MAX_LEGACY_STATE_BYTES
                ):
                    raise LiveTestError("legacy live state exceeds migration limits")
    return sorted(files)


def bounded_legacy_file_bytes(path: Path, maximum_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise LiveTestError("legacy live-state file is unsafe or oversized")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) > maximum_bytes or (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size):
            raise LiveTestError("legacy live-state file changed while read")
        return payload
    finally:
        os.close(descriptor)


def legacy_state_manifest(directory: Path, files: list[Path]) -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    total = 0
    for path in files:
        relative = path.relative_to(directory).as_posix()
        raw = bounded_legacy_file_bytes(path, MAX_LEGACY_STATE_BYTES - total)
        total += len(raw)
        manifest.append(
            {
                "path": relative,
                "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "executable": bool(
                    path.stat(follow_symlinks=False).st_mode & stat.S_IXUSR
                ),
            }
        )
    return manifest


def ledger_partition(ledger: dict[str, Any]) -> str:
    value = ledger.get("partition")
    if isinstance(value, str) and re.fullmatch(r"aws(?:-[a-z0-9]+)*", value):
        return value
    for field in (
        "trusted_principal_arn",
        "initial_caller_session_arn",
        "connect_instance_arn",
    ):
        candidate = ledger.get(field)
        if isinstance(candidate, str):
            match = re.match(r"arn:(aws(?:-[a-z0-9]+)*):", candidate)
            if match:
                return match.group(1)
    raise LiveTestError("legacy qualification ledger has no AWS partition binding")


def retire_legacy_ledger(legacy: Path, source_digest: str) -> None:
    tombstone = legacy.with_name(f"ledger.migrated-{source_digest}.json")
    if tombstone.exists():
        if (
            legacy.exists()
            or hashlib.sha256(
                bounded_legacy_file_bytes(tombstone, 4 * 1024 * 1024)
            ).hexdigest()
            != source_digest
        ):
            raise LiveTestError("legacy live-state tombstone is ambiguous")
        return
    observed = hashlib.sha256(
        bounded_legacy_file_bytes(legacy, 4 * 1024 * 1024)
    ).hexdigest()
    if observed != source_digest:
        raise LiveTestError("legacy authority changed before retirement")
    staging = legacy.with_name(f".ledger-retiring-{secrets.token_hex(8)}")
    os.rename(legacy, staging)
    directory = os.open(legacy.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
        staged_digest = hashlib.sha256(
            bounded_legacy_file_bytes(staging, 4 * 1024 * 1024)
        ).hexdigest()
        if staged_digest != source_digest or legacy.exists():
            if not legacy.exists():
                os.rename(staging, legacy)
                os.fsync(directory)
            raise LiveTestError("legacy authority changed during retirement")
        os.rename(staging, tombstone)
        os.fsync(directory)
        final_invalid = (
            legacy.exists()
            or hashlib.sha256(
                bounded_legacy_file_bytes(tombstone, 4 * 1024 * 1024)
            ).hexdigest()
            != source_digest
        )
        if final_invalid:
            if not legacy.exists() and tombstone.exists():
                os.rename(tombstone, legacy)
                os.fsync(directory)
            raise LiveTestError("legacy authority retirement did not converge")
    finally:
        os.close(directory)


def migrate_legacy_execution_if_needed(execution_id: str) -> Path:
    destination = ledger_path(execution_id)
    legacy = legacy_ledger_path(execution_id)
    if destination.exists():
        if legacy.exists():
            try:
                evidence = json.loads(
                    private_file_bytes(
                        destination.parent / "state-migration-evidence.json",
                        maximum_bytes=256 * 1024,
                        label="state migration evidence",
                    ).decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise LiveTestError(
                    "dual live-state authorities are ambiguous"
                ) from error
            legacy_digest = hashlib.sha256(
                bounded_legacy_file_bytes(legacy, 4 * 1024 * 1024)
            ).hexdigest()
            if (
                not isinstance(evidence, dict)
                or evidence.get("execution_id") != execution_id
                or evidence.get("source_ledger_sha256") != legacy_digest
            ):
                raise LiveTestError(
                    "legacy and durable live-state authorities diverged"
                )
            retire_legacy_ledger(legacy, legacy_digest)
        return destination
    if not legacy.exists():
        return destination
    if destination.parent.exists():
        raise LiveTestError("durable execution directory exists without its ledger")
    files = bounded_legacy_state_files(legacy.parent)
    source_manifest = legacy_state_manifest(legacy.parent, files)
    source_ledger = next(
        (item for item in source_manifest if item["path"] == "ledger.json"), None
    )
    if source_ledger is None or source_ledger["size_bytes"] > 4 * 1024 * 1024:
        raise LiveTestError("legacy qualification ledger is missing or oversized")
    legacy_raw = bounded_legacy_file_bytes(legacy, 4 * 1024 * 1024)
    try:
        legacy_payload = json.loads(legacy_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveTestError("legacy qualification ledger is unreadable") from error
    if (
        not isinstance(legacy_payload, dict)
        or legacy_payload.get("execution_id") != execution_id
    ):
        raise LiveTestError("legacy qualification ledger identity mismatch")
    state_root = ensure_live_state_root()
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{execution_id}-migration-", dir=state_root)
    )
    try:
        shutil.copytree(
            legacy.parent,
            temporary,
            dirs_exist_ok=True,
            symlinks=False,
            copy_function=shutil.copy2,
        )
        copied_files = bounded_legacy_state_files(temporary)
        copied_manifest = legacy_state_manifest(temporary, copied_files)
        source_after = legacy_state_manifest(
            legacy.parent, bounded_legacy_state_files(legacy.parent)
        )
        if source_after != source_manifest or copied_manifest != source_manifest:
            raise LiveTestError("legacy live state changed during migration")
        for item in [temporary, *temporary.rglob("*")]:
            details = item.lstat()
            if stat.S_ISDIR(details.st_mode):
                os.chmod(item, 0o700)
            elif stat.S_ISREG(details.st_mode):
                os.chmod(item, 0o700 if details.st_mode & stat.S_IXUSR else 0o600)
        migrated_ledger = json.loads((temporary / "ledger.json").read_text())
        migrated_ledger["partition"] = ledger_partition(migrated_ledger)
        old_revision = migrated_ledger.get("state_revision", 0)
        if (
            not isinstance(old_revision, int)
            or isinstance(old_revision, bool)
            or old_revision < 0
        ):
            raise LiveTestError("legacy qualification ledger revision is invalid")
        migrated_ledger["state_revision"] = old_revision + 1
        migrated_ledger["previous_ledger_sha256"] = source_ledger["sha256"]
        authority = initial_recovery_authority(
            migrated_ledger, authority_kind="legacy_state_migration"
        )
        immutable_private_json(temporary / "recovery-authority.json", authority)
        migrated_ledger["recovery_authority_sha256"] = canonical_json_sha256(authority)
        atomic_json(temporary / "ledger.json", migrated_ledger)
        destination_digest = hashlib.sha256(
            private_file_bytes(
                temporary / "ledger.json",
                maximum_bytes=4 * 1024 * 1024,
                label="migrated qualification ledger",
            )
        ).hexdigest()
        atomic_json(
            temporary / "state-migration-evidence.json",
            {
                "schema_version": 1,
                "execution_id": execution_id,
                "migrated_at": utc_now(),
                "source": os.fspath(legacy.parent),
                "destination": os.fspath(destination.parent),
                "file_count": len(files),
                "source_manifest_sha256": canonical_json_sha256(source_manifest),
                "source_ledger_sha256": source_ledger["sha256"],
                "destination_ledger_sha256": destination_digest,
            },
        )
        temporary.rename(destination.parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    installed_digest = hashlib.sha256(
        private_file_bytes(
            destination,
            maximum_bytes=4 * 1024 * 1024,
            label="migrated qualification ledger",
        )
    ).hexdigest()
    if installed_digest != destination_digest:
        quarantine = destination.parent.with_name(
            f".{execution_id}-migration-quarantine-{secrets.token_hex(8)}"
        )
        destination.parent.rename(quarantine)
        raise LiveTestError("migrated qualification ledger digest changed")
    try:
        retire_legacy_ledger(legacy, source_ledger["sha256"])
    except Exception:
        quarantine = destination.parent.with_name(
            f".{execution_id}-migration-quarantine-{secrets.token_hex(8)}"
        )
        if destination.parent.exists():
            destination.parent.rename(quarantine)
        raise
    return destination


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_STATE_JSON_BYTES:
        raise LiveTestError("state document exceeds its byte boundary")
    ensure_private_directory(path.parent)
    directory = open_private_directory(path.parent)
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            require_private_regular_file(existing, "existing state document")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        temporary_details = os.fstat(descriptor)
        require_private_regular_file(temporary_details, "temporary state document")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise LiveTestError("state document write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(
            temporary_name,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def immutable_private_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_STATE_JSON_BYTES:
        raise LiveTestError("immutable state document exceeds its byte boundary")
    ensure_private_directory(path.parent)
    directory = open_private_directory(path.parent)
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        require_private_regular_file(os.fstat(descriptor), "immutable state document")
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise LiveTestError("immutable state write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(directory)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created_identity is not None:
            try:
                current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if (
                current is not None
                and (current.st_dev, current.st_ino) == created_identity
            ):
                os.unlink(path.name, dir_fd=directory)
                os.fsync(directory)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


RECOVERY_SNAPSHOT_FIELDS = (
    "schema_version",
    "execution_id",
    "project",
    "managed_by",
    "recipe",
    "created_at",
    "status",
    "region",
    "partition",
    "account_id",
    "connect_mode",
    "connect_instance_arn",
    "artifact_bucket",
    "ecr_repository",
    "stack_name",
    "stack_id",
    "review_stack_id",
    "qualification_stack_name",
    "qualification_stack_id",
    "qualification_review_stack_id",
    "qualification_project_name",
    "bootstrap_stack_name",
    "bootstrap_stack_id",
    "recovery_authority_sha256",
    "state_revision",
    "previous_ledger_sha256",
    "qualification_deadline_at",
    "max_usd",
    "cost_ceiling_type",
    "deployment_role_arn",
    "cloudformation_execution_role_arn",
    "qualification_role_arn",
    "qualification_runner_role_arn",
    "qualification_source_eip_allocation_id",
    "qualification_source_cidr",
    "change_set_arn",
    "change_set_name",
    "qualification_change_set_arn",
    "qualification_change_set_name",
    "release_id",
    "publication_source_tree_sha256",
    "release_manifest_sha256",
    "application_stack_name",
    "vapi_stack_id",
    "vapi_assistant_id",
    "vapi_prepare_tool_id",
    "vapi_webhook_credential_id",
    "vapi_prepare_url",
    "vapi_teardown_mode",
    "vapi_not_created_reason",
    "vapi_api_key_secret_arn",
    "vapi_public_key_secret_arn",
    "agent_credential_secret_arn",
    "private_tls_secret_arn",
    "dns_mode",
    "public_hosted_zone_id",
    "public_hosted_zone_name",
    "demo_site_bucket",
    "created_resources",
)


def sanitized_created_resources(ledger: dict[str, Any]) -> list[dict[str, str]]:
    value = ledger.get("created_resources", [])
    allowed_types = {
        "ecr_repository",
        "route53_hosted_zone",
        "s3_bucket",
        "secret",
    }
    if (
        not isinstance(value, list)
        or len(value) > 32
        or len(value)
        != len(
            {
                (item.get("type"), item.get("id"))
                for item in value
                if isinstance(item, dict)
            }
        )
    ):
        raise LiveTestError("created-resource recovery inventory is invalid")
    sanitized: list[dict[str, str]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"type", "id"}
            or item.get("type") not in allowed_types
            or not isinstance(item.get("id"), str)
            or not 1 <= len(item["id"]) <= 512
            or "\x00" in item["id"]
            or item["id"].startswith("/")
            or ".." in PurePosixPath(item["id"]).parts
        ):
            raise LiveTestError("created-resource recovery entry is invalid")
        sanitized.append({"type": item["type"], "id": item["id"]})
    return sanitized


def sanitized_recovery_snapshot(ledger: dict[str, Any]) -> dict[str, Any]:
    events = ledger.get("events", [])
    if not isinstance(events, list):
        raise LiveTestError("qualification event ledger is invalid")
    last_record = events[-1] if events and isinstance(events[-1], dict) else {}
    last_event = last_record.get("event")
    snapshot_at = last_record.get("at", ledger.get("created_at"))
    if not isinstance(snapshot_at, str):
        raise LiveTestError("qualification snapshot has no durable timestamp")
    authority = {
        field: ledger[field]
        for field in RECOVERY_SNAPSHOT_FIELDS
        if field in ledger and field != "created_resources"
    }
    authority["created_resources"] = sanitized_created_resources(ledger)
    for field in (
        "vapi_assistant_id",
        "vapi_prepare_tool_id",
        "vapi_webhook_credential_id",
    ):
        value = authority.get(field)
        if value is not None and (
            not isinstance(value, str)
            or VAPI_RESOURCE_ID_PATTERN.fullmatch(value) is None
        ):
            raise LiveTestError("Vapi recovery resource binding is invalid")
    prepare_url = authority.get("vapi_prepare_url")
    if prepare_url is not None and (
        not isinstance(prepare_url, str)
        or len(prepare_url) > 2_048
        or not prepare_url.startswith("https://")
        or any(character.isspace() for character in prepare_url)
    ):
        raise LiveTestError("Vapi recovery prepare URL is invalid")
    mode = authority.get("vapi_teardown_mode")
    if mode is not None and mode not in {"bound_ids", "not_created", "owner_scan"}:
        raise LiveTestError("Vapi recovery teardown mode is invalid")
    for field in (
        "vapi_api_key_secret_arn",
        "vapi_public_key_secret_arn",
        "agent_credential_secret_arn",
        "private_tls_secret_arn",
    ):
        value = authority.get(field)
        if value is not None and (
            not isinstance(value, str)
            or len(value) > 2_048
            or re.fullmatch(
                r"arn:aws(?:-[a-z0-9]+)*:secretsmanager:[^:]+:[0-9]{12}:secret:.+",
                value,
            )
            is None
        ):
            raise LiveTestError("recovery secret ARN binding is invalid")
    teardown_binding = {
        field: authority[field]
        for field in (
            "application_stack_name",
            "vapi_stack_id",
            "vapi_assistant_id",
            "vapi_prepare_tool_id",
            "vapi_webhook_credential_id",
            "vapi_prepare_url",
            "vapi_teardown_mode",
            "vapi_api_key_secret_arn",
        )
        if field in authority
    }
    authority["vapi_teardown_authority_sha256"] = canonical_json_sha256(
        teardown_binding
    )
    execution_id = ledger.get("execution_id")
    deterministic_names = (
        {
            "vapi_api_key_secret": f"bridgefu-{execution_id}-vapi-api-key",
            "vapi_public_key_secret": f"bridgefu-{execution_id}-vapi-public-key",
            "connect_log_group": f"/aws/connect/{execution_id}-connect",
        }
        if isinstance(execution_id, str)
        and EXECUTION_PATTERN.fullmatch(execution_id) is not None
        else {}
    )
    return {
        "schema_version": 1,
        "snapshot_at": snapshot_at,
        "scope": "active_run_accidental_loss_recovery_only",
        "final_teardown_authority": False,
        "authority": authority,
        "event_count": len(events),
        "last_event": last_event,
        "deterministic_names": deterministic_names,
    }


def write_local_recovery_snapshot(path: Path, ledger: dict[str, Any]) -> Path:
    snapshot_path = path.parent / "recovery-snapshot.json"
    atomic_json(snapshot_path, sanitized_recovery_snapshot(ledger))
    return snapshot_path


RECOVERY_AUTHORITY_FIXED_FIELDS = (
    "schema_version",
    "execution_id",
    "created_at",
    "account_id",
    "partition",
    "region",
    "project",
    "managed_by",
    "recipe",
    "stack_name",
    "qualification_stack_name",
    "bootstrap_stack_name",
    "artifact_bucket",
    "ecr_repository",
    "connect_mode",
    "qualification_deadline_at",
    "max_usd",
)
LOST_LEDGER_RUNTIME_STATUSES = {
    "recovery_teardown_only",
    "destroying",
    "destroying_base_finalize",
    "teardown_incomplete",
    "destroyed",
}


def initial_recovery_authority(
    ledger: dict[str, Any], *, authority_kind: str = "initialized_execution"
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "authority_kind": authority_kind,
        "execution_id": ledger["execution_id"],
        "created_at": ledger["created_at"],
        "account_id": ledger["account_id"],
        "partition": ledger["partition"],
        "region": ledger["region"],
        "project": ledger["project"],
        "managed_by": ledger["managed_by"],
        "recipe": ledger["recipe"],
        "stack_name": ledger["stack_name"],
        "qualification_stack_name": ledger["qualification_stack_name"],
        "bootstrap_stack_name": ledger["bootstrap_stack_name"],
        "artifact_bucket": ledger["artifact_bucket"],
        "ecr_repository": ledger["ecr_repository"],
        "connect_mode": ledger["connect_mode"],
        "qualification_deadline_at": ledger["qualification_deadline_at"],
        "max_usd": ledger["max_usd"],
    }


def lost_ledger_recovery_authority(ledger: dict[str, Any]) -> dict[str, Any]:
    authority = initial_recovery_authority(
        ledger, authority_kind="lost_ledger_teardown_only"
    )
    authority["teardown_binding"] = {
        "recovery_mode": ledger["recovery_mode"],
        "recovery_adoption_status": ledger["recovery_adoption_status"],
        "recovery_review_sha256": ledger["recovery_review_sha256"],
        "deployed_teardown_authority_sha256": ledger[
            "deployed_teardown_authority_sha256"
        ],
        "deployed_teardown_authority": ledger["deployed_teardown_authority"],
        "bootstrap_stack_id": ledger["bootstrap_stack_id"],
        "bootstrap_status_at_adoption": ledger["bootstrap_status_at_adoption"],
        "bootstrap_deployed_template_sha256": ledger[
            "bootstrap_deployed_template_sha256"
        ],
        "bootstrap_resource_authority": ledger["bootstrap_resource_authority"],
        "bootstrap_managed_policy_arns": ledger["bootstrap_managed_policy_arns"],
        "deployment_role_arn": ledger["deployment_role_arn"],
        "cloudformation_execution_role_arn": ledger[
            "cloudformation_execution_role_arn"
        ],
        "qualification_role_arn": ledger["qualification_role_arn"],
        "qualification_runner_role_arn": ledger["qualification_runner_role_arn"],
        "qualification_source_eip_allocation_id": ledger[
            "qualification_source_eip_allocation_id"
        ],
        "qualification_source_cidr": ledger["qualification_source_cidr"],
        "artifact_bucket_authority": ledger["artifact_bucket_authority"],
        "ecr_repository_authority": ledger["ecr_repository_authority"],
        "created_resources": sanitized_created_resources(ledger),
        "original_trusted_principal_arn": ledger["original_trusted_principal_arn"],
        "recovery_authorizer_principal_arn": ledger[
            "recovery_authorizer_principal_arn"
        ],
        "vapi_teardown_mode": ledger["vapi_teardown_mode"],
        "vapi_not_created_reason": ledger["vapi_not_created_reason"],
        "application_stack_name": ledger["application_stack_name"],
        "demo_site_bucket": ledger["demo_site_bucket"],
        "public_hosted_zone_id": ledger["public_hosted_zone_id"],
    }
    return authority


def write_initial_recovery_authority(path: Path, ledger: dict[str, Any]) -> None:
    authority = initial_recovery_authority(ledger)
    authority_path = path.parent / "recovery-authority.json"
    immutable_private_json(authority_path, authority)
    ledger["recovery_authority_sha256"] = canonical_json_sha256(authority)


def validate_recovery_authority(path: Path, ledger: dict[str, Any]) -> None:
    authority_path = path.parent / "recovery-authority.json"
    try:
        authority = json.loads(
            private_file_bytes(
                authority_path,
                maximum_bytes=256 * 1024,
                label="recovery authority",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveTestError("recovery authority is unreadable") from error
    digest = ledger.get("recovery_authority_sha256")
    if (
        not isinstance(authority, dict)
        or authority.get("schema_version") != 1
        or authority.get("authority_kind")
        not in {
            "initialized_execution",
            "legacy_state_migration",
            "lost_ledger_teardown_only",
        }
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or canonical_json_sha256(authority) != digest
    ):
        raise LiveTestError("recovery authority digest or shape changed")
    if any(
        authority.get(field) != ledger.get(field)
        for field in RECOVERY_AUTHORITY_FIXED_FIELDS
    ):
        raise LiveTestError("qualification ledger differs from its recovery authority")
    if authority.get("authority_kind") == "lost_ledger_teardown_only":
        try:
            expected_authority = lost_ledger_recovery_authority(ledger)
        except (KeyError, TypeError) as error:
            raise LiveTestError(
                "lost-ledger teardown authority is incomplete"
            ) from error
        if authority != expected_authority:
            raise LiveTestError(
                "lost-ledger teardown binding differs from its immutable authority"
            )
        if (
            ledger.get("recovery_mode") != "teardown_only"
            or ledger.get("recovery_adoption_status") != "recovery_teardown_only"
            or ledger.get("status") not in LOST_LEDGER_RUNTIME_STATUSES
            or ledger.get("vapi_teardown_mode") != "not_created"
        ):
            raise LiveTestError(
                "lost-ledger runtime state is outside teardown authority"
            )


def validate_durable_ledger(path: Path, execution_id: str) -> dict[str, Any]:
    try:
        raw = private_file_bytes(
            path,
            maximum_bytes=4 * 1024 * 1024,
            label="qualification ledger",
        )
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveTestError("qualification ledger is unreadable") from error
    if not isinstance(payload, dict) or payload.get("execution_id") != execution_id:
        raise LiveTestError("qualification ledger identity mismatch")
    revision = payload.get("state_revision")
    previous = payload.get("previous_ledger_sha256")
    if (
        payload.get("schema_version") != 1
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
        or previous is not None
        and (
            not isinstance(previous, str)
            or re.fullmatch(r"[0-9a-f]{64}", previous) is None
        )
    ):
        raise LiveTestError("qualification ledger revision is invalid")
    validate_recovery_authority(path, payload)
    return payload


def load_ledger(execution_id: str) -> tuple[Path, dict[str, Any]]:
    path = migrate_legacy_execution_if_needed(execution_id)
    payload = validate_durable_ledger(path, execution_id)
    return path, payload


def persist_ledger(path: Path, ledger: dict[str, Any]) -> None:
    current_revision = 0
    previous_digest: str | None = None
    if path.exists():
        raw = private_file_bytes(
            path,
            maximum_bytes=4 * 1024 * 1024,
            label="qualification ledger",
        )
        try:
            current = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LiveTestError("qualification ledger is unreadable") from error
        if not isinstance(current, dict) or current.get("execution_id") != ledger.get(
            "execution_id"
        ):
            raise LiveTestError("qualification ledger changed identity")
        current_revision = current.get("state_revision", 0)
        memory_revision = ledger.get("state_revision", 0)
        if (
            not isinstance(current_revision, int)
            or isinstance(current_revision, bool)
            or current_revision < 0
            or memory_revision != current_revision
        ):
            raise LiveTestError("qualification ledger revision changed concurrently")
        previous_digest = hashlib.sha256(raw).hexdigest()
    elif ledger.get("state_revision") not in (None, 0):
        raise LiveTestError("qualification ledger revision has no predecessor")
    ledger["state_revision"] = current_revision + 1
    ledger["previous_ledger_sha256"] = previous_digest
    atomic_json(path, ledger)


def record(path: Path, ledger: dict[str, Any], event: str, **fields: Any) -> None:
    ledger.setdefault("events", []).append({"at": utc_now(), "event": event, **fields})
    persist_ledger(path, ledger)
    write_local_recovery_snapshot(path, ledger)


def mirror_recovery_snapshot(
    path: Path, ledger: dict[str, Any], environment: dict[str, str]
) -> None:
    snapshot_path = write_local_recovery_snapshot(path, ledger)
    snapshot = json.loads(
        private_file_bytes(
            snapshot_path,
            maximum_bytes=MAX_STATE_JSON_BYTES,
            label="recovery capsule",
        ).decode("utf-8")
    )
    sequence = ledger.get("state_revision")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise LiveTestError("recovery capsule has no valid state sequence")
    previous = ledger.get("recovery_snapshot_mirror", {})
    previous_digest = previous.get("sha256") if isinstance(previous, dict) else None
    if previous_digest is not None and (
        not isinstance(previous_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", previous_digest) is None
    ):
        raise LiveTestError("recovery capsule predecessor digest is invalid")
    snapshot["capsule_sequence"] = sequence
    snapshot["previous_capsule_sha256"] = previous_digest
    atomic_json(snapshot_path, snapshot)
    raw = private_file_bytes(
        snapshot_path,
        maximum_bytes=MAX_STATE_JSON_BYTES,
        label="recovery capsule",
    )
    digest = hashlib.sha256(raw).hexdigest()
    capsule_directory = path.parent / "recovery-capsules"
    capsule_path = capsule_directory / f"{sequence:08d}-{digest}.json"
    if capsule_path.exists():
        if (
            hashlib.sha256(
                private_file_bytes(
                    capsule_path,
                    maximum_bytes=MAX_STATE_JSON_BYTES,
                    label="local recovery capsule",
                )
            ).hexdigest()
            != digest
        ):
            raise LiveTestError("local recovery capsule changed")
    else:
        immutable_private_json(capsule_path, snapshot)
    key = (
        f"qualification/{ledger['execution_id']}/recovery/snapshots/"
        f"{sequence:08d}-{digest}.json"
    )
    checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
    exists = exact_probe_exists(
        [
            "s3api",
            "head-object",
            "--region",
            ledger["region"],
            "--bucket",
            ledger["artifact_bucket"],
            "--key",
            key,
        ],
        absent_markers=("404", "Not Found", "NoSuchKey"),
        label="active-run recovery capsule",
        environment=environment,
    )
    if exists:
        result = aws_json(
            [
                "s3api",
                "head-object",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--key",
                key,
                "--checksum-mode",
                "ENABLED",
            ],
            env=environment,
        )
    else:
        result = aws_json(
            [
                "s3api",
                "put-object",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--key",
                key,
                "--body",
                os.fspath(capsule_path),
                "--if-none-match",
                "*",
                "--server-side-encryption",
                "AES256",
                "--checksum-sha256",
                checksum,
                "--metadata",
                f"sha256={digest},execution-id={ledger['execution_id']},sequence={sequence}",
                "--tagging",
                f"Project={PROJECT}&ManagedBy={MANAGED_BY}&BridgefuExecutionId={ledger['execution_id']}",
            ],
            env=environment,
        )
    version_id = result.get("VersionId") if isinstance(result, dict) else None
    if not isinstance(version_id, str) or not version_id:
        raise LiveTestError("recovery snapshot mirror has no immutable S3 version")
    head = aws_json(
        [
            "s3api",
            "head-object",
            "--region",
            ledger["region"],
            "--bucket",
            ledger["artifact_bucket"],
            "--key",
            key,
            "--version-id",
            version_id,
            "--checksum-mode",
            "ENABLED",
        ],
        env=environment,
    )
    metadata = head.get("Metadata") if isinstance(head, dict) else None
    if (
        not isinstance(metadata, dict)
        or metadata.get("sha256") != digest
        or metadata.get("execution-id") != ledger["execution_id"]
        or metadata.get("sequence") != str(sequence)
        or head.get("VersionId") != version_id
        or head.get("ServerSideEncryption") != "AES256"
        or head.get("ContentLength") != len(raw)
        or head.get("ChecksumSHA256") != checksum
    ):
        raise LiveTestError("recovery snapshot mirror readback changed")
    ledger["recovery_snapshot_mirror"] = {
        "bucket": ledger["artifact_bucket"],
        "key": key,
        "version_id": version_id,
        "sha256": digest,
        "sequence": sequence,
        "scope": "active_run_accidental_loss_recovery_only",
        "mirrored_at": utc_now(),
    }
    record(path, ledger, "recovery_snapshot_mirrored", version_id=version_id)


def command(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = True,
    capture: bool = True,
    cwd: Path | None = None,
    inherit_live_lock: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        env=env,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        cwd=cwd,
        pass_fds=live_lock_pass_fds() if inherit_live_lock else (),
    )
    if check and result.returncode != 0:
        detail = (result.stderr or "command failed").strip()[-2000:]
        raise LiveTestError(f"{args[0]} command failed: {detail}")
    return result


@contextlib.contextmanager
def isolated_docker_environment(parent: Path) -> Iterator[dict[str, str]]:
    """Keep temporary registry credentials out of the user's Docker config."""
    config = Path(tempfile.mkdtemp(prefix=".docker-config-", dir=parent))
    os.chmod(config, 0o700)
    try:
        environment = os.environ.copy()
        source_config = Path(
            environment.get("DOCKER_CONFIG", os.fspath(Path.home() / ".docker"))
        ).expanduser()
        plugin_directories: list[str] = []
        local_plugins = source_config / "cli-plugins"
        if local_plugins.is_dir():
            plugin_directories.append(os.fspath(local_plugins.resolve()))
        source_settings = source_config / "config.json"
        if source_settings.is_file():
            if source_settings.stat().st_size > 1024 * 1024:
                raise LiveTestError("Docker configuration is unexpectedly large")
            try:
                settings = json.loads(source_settings.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise LiveTestError("Docker configuration is invalid") from error
            extra_plugins = settings.get("cliPluginsExtraDirs", [])
            if not isinstance(extra_plugins, list) or not all(
                isinstance(item, str) for item in extra_plugins
            ):
                raise LiveTestError("Docker CLI plugin configuration is invalid")
            for item in extra_plugins:
                plugin_path = Path(item).expanduser()
                if not plugin_path.is_absolute():
                    plugin_path = source_config / plugin_path
                if plugin_path.is_dir():
                    plugin_directories.append(os.fspath(plugin_path.resolve()))
        plugin_directories = list(dict.fromkeys(plugin_directories))
        if plugin_directories:
            (config / "config.json").write_text(
                json.dumps({"cliPluginsExtraDirs": plugin_directories}),
                encoding="utf-8",
            )
            os.chmod(config / "config.json", 0o600)
        active_context = command(
            ["docker", "context", "show"], env=environment
        ).stdout.strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}", active_context) is None:
            raise LiveTestError("Docker returned an invalid active context")
        isolated_environment = environment.copy()
        isolated_environment["DOCKER_CONFIG"] = os.fspath(config)
        if active_context != "default":
            archive = config / "active.dockercontext"
            imported_name = "bridgefu-publication"
            try:
                command(
                    [
                        "docker",
                        "context",
                        "export",
                        active_context,
                        os.fspath(archive),
                    ],
                    env=environment,
                )
                if not archive.is_file() or archive.is_symlink():
                    raise LiveTestError("Docker context export produced no archive")
                os.chmod(archive, 0o600)
                import_environment = isolated_environment.copy()
                for name in (
                    "DOCKER_CONTEXT",
                    "DOCKER_HOST",
                    "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH",
                ):
                    import_environment.pop(name, None)
                command(
                    [
                        "docker",
                        "context",
                        "import",
                        imported_name,
                        os.fspath(archive),
                    ],
                    env=import_environment,
                )
            finally:
                archive.unlink(missing_ok=True)
            for name in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
                isolated_environment.pop(name, None)
            isolated_environment["DOCKER_CONTEXT"] = imported_name
        yield isolated_environment
    finally:
        shutil.rmtree(config)


def aws_json(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> Any:
    result = command(
        ["aws", *args, "--output", "json", "--no-cli-pager"],
        env=env,
        input_text=input_text,
        check=check,
    )
    if result.returncode != 0 or not (result.stdout or "").strip():
        return None
    return json.loads(result.stdout)


def aws_wait(args: list[str], *, env: dict[str, str] | None = None) -> None:
    command(["aws", *args, "--no-cli-pager"], env=env)


def identity(env: dict[str, str] | None = None) -> dict[str, str]:
    value = aws_json(["sts", "get-caller-identity"], env=env)
    if not isinstance(value, dict):
        raise LiveTestError("unable to resolve AWS caller identity")
    return value


def durable_trusted_principal(caller: dict[str, str]) -> str:
    """Return the durable IAM principal behind a human AWS session."""
    arn = caller.get("Arn", "")
    account = caller.get("Account", "")
    if re.fullmatch(
        rf"arn:aws[-a-z0-9]*:iam::{re.escape(account)}:"
        r"(?:root|user/[A-Za-z0-9+=,.@_/-]+|role/[A-Za-z0-9+=,.@_/-]+)",
        arn,
    ):
        return arn
    match = re.fullmatch(
        rf"arn:(aws[-a-z0-9]*):sts::{re.escape(account)}:"
        r"assumed-role/([^/]+)/[^/]+",
        arn,
    )
    if not match:
        raise LiveTestError(
            "the active AWS identity is not an IAM user, IAM role, account root, "
            "or assumed-role session"
        )
    role_name = match.group(2)
    role = aws_json(["iam", "get-role", "--role-name", role_name])["Role"]
    role_arn = role.get("Arn", "")
    if not re.fullmatch(
        rf"arn:{re.escape(match.group(1))}:iam::{re.escape(account)}:"
        rf"role/(?:[A-Za-z0-9+=,.@_-]+/)*{re.escape(role_name)}",
        role_arn,
    ):
        raise LiveTestError("unable to bind the assumed session to its IAM role")
    return role_arn


def assume_env(ledger: dict[str, Any], role: str) -> dict[str, str]:
    if role not in {"deployment", "qualification"}:
        raise LiveTestError("invalid temporary role type")
    arn = ledger[f"{role}_role_arn"]
    session_name = (
        f"bridgefu-{ledger['execution_id']}"
        if role == "deployment"
        else f"bridgefu-{ledger['execution_id']}-qualification"
    )
    role_name = (
        f"bridgefu-{ledger['execution_id']}-deployer"
        if role == "deployment"
        else f"bridgefu-{ledger['execution_id']}-qualifier"
    )
    expected_role_arn = (
        f"arn:{ledger['partition']}:iam::{ledger['account_id']}:role/{role_name}"
    )
    if arn != expected_role_arn:
        raise LiveTestError(
            f"temporary {role} role ARN differs from its ledger binding"
        )
    response = aws_json(
        [
            "sts",
            "assume-role",
            "--role-arn",
            arn,
            "--role-session-name",
            session_name,
            "--duration-seconds",
            str(ROLE_CHAIN_SESSION_SECONDS),
        ]
    )
    credentials = response.get("Credentials") if isinstance(response, dict) else None
    assumed = response.get("AssumedRoleUser") if isinstance(response, dict) else None
    expected_session_arn = (
        f"arn:{ledger['partition']}:sts::{ledger['account_id']}:"
        f"assumed-role/{role_name}/{session_name}"
    )
    if (
        not isinstance(credentials, dict)
        or not isinstance(assumed, dict)
        or assumed.get("Arn") != expected_session_arn
        or any(
            not isinstance(credentials.get(field), str) or not credentials[field]
            for field in ("AccessKeyId", "SecretAccessKey", "SessionToken")
        )
    ):
        raise LiveTestError(f"temporary {role} role response is not exact")
    environment = os.environ.copy()
    environment.update(
        {
            "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
            "AWS_SESSION_TOKEN": credentials["SessionToken"],
            "AWS_REGION": ledger["region"],
            "AWS_DEFAULT_REGION": ledger["region"],
        }
    )
    environment.pop("AWS_PROFILE", None)
    observed = identity(environment)
    if (
        observed.get("Account") != ledger["account_id"]
        or observed.get("Arn") != expected_session_arn
    ):
        raise LiveTestError(f"failed to assume the temporary {role} role")
    return environment


class RefreshableRoleEnvironment:
    """Refresh a temporary AWS role session before its one-hour expiry."""

    def __init__(
        self,
        ledger: dict[str, Any],
        role: str,
        *,
        refresh_after_seconds: int = HEADLESS_CREDENTIAL_REFRESH_SECONDS,
    ) -> None:
        if (
            refresh_after_seconds <= 0
            or refresh_after_seconds >= ROLE_CHAIN_SESSION_SECONDS
        ):
            raise LiveTestError("temporary-role refresh interval is invalid")
        self.ledger = ledger
        self.role = role
        self.refresh_after_seconds = refresh_after_seconds
        self.environment: dict[str, str] | None = None
        self.assumed_at: float | None = None

    def get(self) -> dict[str, str]:
        now = time.monotonic()
        if (
            self.environment is None
            or self.assumed_at is None
            or now - self.assumed_at >= self.refresh_after_seconds
        ):
            self.environment = assume_env(self.ledger, self.role)
            self.assumed_at = now
        return self.environment


def cost_estimate(
    hours: float,
    connect_minutes: int,
    enable_demo_site: bool = False,
    runtime_profile: str = "starter",
    disposable_connect: bool = False,
) -> dict[str, Any]:
    if (
        not isinstance(hours, (int, float))
        or isinstance(hours, bool)
        or not math.isfinite(hours)
        or hours <= 0
        or hours > 48
    ):
        raise LiveTestError(
            "planned duration must be greater than 0 and no more than 48 hours"
        )
    if (
        not isinstance(connect_minutes, int)
        or isinstance(connect_minutes, bool)
        or connect_minutes < 0
        or connect_minutes > 240
    ):
        raise LiveTestError(
            "planned Amazon Connect use must be between 0 and 240 minutes"
        )
    if runtime_profile not in {"starter", "high_availability"}:
        raise LiveTestError("runtime profile must be starter or high_availability")
    # Deliberately conservative planning values. AWS billing data is delayed, so
    # this is not a real-time spend cap. The absolute qualification deadline is
    # a fail-closed controller guard for starting or resuming paid test phases;
    # it does not stop abandoned AWS resources or perform automatic teardown.
    breakdown = {
        "exportable_acm_certificate": 20.0,
        "ec2_and_detailed_monitoring": round(hours * 0.35, 2),
        "vpc_interface_endpoints": round(hours * 0.15, 2),
        "elastic_ip": round(hours * 0.02, 2),
        "encrypted_ebs": round(hours * 0.02, 2),
        "amazon_connect": round(connect_minutes * 0.08, 2),
        "optional_demo_site_cloudfront_s3": 2.0 if enable_demo_site else 0.0,
        "disposable_connect_nat_and_codebuild": (
            round(hours * 0.40 + 12.0, 2) if disposable_connect else 0.0
        ),
        "lambda_api_dynamodb_logs_s3_ecr_dns": 10.0,
        # Four EC2 slots, two NAT gateways, three NLBs, Multi-AZ RDS, and
        # two Valkey nodes. The allowance intentionally exceeds current
        # us-west-2 on-demand rates so the live gate remains useful if pricing
        # or data-processing volume moves between releases.
        "ha_nat_nlb_rds_redis_and_compute": (
            round(hours * 3.5, 2) if runtime_profile == "high_availability" else 0.0
        ),
        "unexpected_usage_contingency": (
            50.0 if runtime_profile == "high_availability" else 30.0
        ),
    }
    return {
        "currency": "USD",
        "limit_kind": "planning_estimate_not_realtime_spend_cap",
        "runtime_profile": runtime_profile,
        "planned_hours": hours,
        "planned_connect_minutes": connect_minutes,
        "breakdown": breakdown,
        "conservative_total": round(sum(breakdown.values()), 2),
    }


def require_cost_estimate_within_ceiling(
    max_usd: float, conservative_total: float
) -> None:
    if (
        not isinstance(max_usd, (int, float))
        or isinstance(max_usd, bool)
        or not math.isfinite(max_usd)
        or max_usd <= 0
        or max_usd > MAX_ABSOLUTE_USD
    ):
        raise LiveTestError(
            "--max-usd estimate ceiling must be finite, positive, and no more than 200"
        )
    if (
        not isinstance(conservative_total, (int, float))
        or isinstance(conservative_total, bool)
        or not math.isfinite(conservative_total)
        or conservative_total < 0
    ):
        raise LiveTestError("conservative cost estimate is invalid")
    if conservative_total > max_usd:
        raise LiveTestError(
            "conservative planning estimate exceeds the authorized estimate ceiling"
        )


def qualification_deadline_for(created_at: str, planned_hours: float) -> str:
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise LiveTestError("qualification creation time is invalid")
    if (
        not isinstance(planned_hours, (int, float))
        or isinstance(planned_hours, bool)
        or not math.isfinite(planned_hours)
        or planned_hours <= 0
        or planned_hours > 48
    ):
        raise LiveTestError("qualification planned duration is invalid")
    try:
        created = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise LiveTestError("qualification creation time is invalid") from error
    if created.tzinfo is None:
        raise LiveTestError("qualification creation time has no timezone")
    deadline = created.astimezone(dt.timezone.utc) + dt.timedelta(hours=planned_hours)
    return deadline.isoformat().replace("+00:00", "Z")


def require_qualification_deadline(
    path: Path,
    ledger: dict[str, Any],
    operation: str,
    *,
    now: dt.datetime | None = None,
) -> int:
    """Return whole seconds left, binding old ledgers to their original clock."""
    estimate = ledger.get("cost_estimate")
    if not isinstance(estimate, dict):
        raise LiveTestError("qualification cost estimate is invalid")
    require_cost_estimate_within_ceiling(
        ledger.get("max_usd"), estimate.get("conservative_total")
    )
    planned_hours = estimate.get("planned_hours")
    expected = qualification_deadline_for(ledger.get("created_at"), planned_hours)
    recorded = ledger.get("qualification_deadline_at")
    if recorded is None:
        ledger["qualification_deadline_at"] = expected
        ledger["cost_ceiling_type"] = "estimate_with_absolute_deadline"
        record(path, ledger, "qualification_deadline_bound", deadline_at=expected)
    elif recorded != expected:
        raise LiveTestError(
            "qualification deadline differs from its original authorization"
        )
    try:
        deadline = dt.datetime.fromisoformat(expected.replace("Z", "+00:00"))
    except (
        ValueError
    ) as error:  # pragma: no cover - qualification_deadline_for validates it.
        raise LiveTestError("qualification deadline is invalid") from error
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise LiveTestError("qualification deadline check has no timezone")
    remaining = math.floor(
        (deadline - current.astimezone(dt.timezone.utc)).total_seconds()
    )
    if remaining <= 0:
        raise LiveTestError(
            f"{operation} is blocked because the absolute qualification deadline "
            "expired; this guard does not stop existing AWS resources, so use "
            "inventory and teardown/cleanup to end their charges"
        )
    return remaining


def normalize_zone_id(value: str) -> str:
    return value.rsplit("/", 1)[-1]


def tag_arguments(execution_id: str) -> list[str]:
    return [
        f"Key=Project,Value={PROJECT}",
        f"Key=ManagedBy,Value={MANAGED_BY}",
        f"Key=BridgefuExecutionId,Value={execution_id}",
        f"Key=BridgefuRecipe,Value={RECIPE}",
    ]


def bootstrap_stack_parameters(
    ledger: dict[str, Any], trusted_principal_arn: str
) -> dict[str, str]:
    return {
        "ExecutionId": ledger["execution_id"],
        "TrustedPrincipalArn": trusted_principal_arn,
        "GitHubOidcProviderArn": "none",
        "GitHubRepository": "eisenzopf/bridgefu",
        "GitHubEnvironment": "none",
        "ConnectInstanceArn": ledger["connect_instance_arn"],
        "ConnectMode": (
            "Disposable" if ledger.get("connect_mode") == "disposable" else "Existing"
        ),
        "EnableQualificationRunner": "false",
        "ArtifactBucketName": ledger["artifact_bucket"],
        "EcrRepositoryName": ledger["ecr_repository"],
        "ArtifactAccessMode": "EphemeralManage",
        "PublicHostedZoneId": ledger["public_hosted_zone_id"],
        "EnableDemoSite": "true" if ledger.get("enable_demo_site") else "false",
    }


def exact_bootstrap_stack_identity(ledger: dict[str, Any]) -> tuple[str, str]:
    """Return the immutable bootstrap identity already bound in the ledger."""
    stack_name = ledger.get("bootstrap_stack_name")
    stack_id = ledger.get("bootstrap_stack_id")
    partition = ledger.get("partition")
    region = ledger.get("region")
    account_id = ledger.get("account_id")
    if not all(
        isinstance(value, str) and value
        for value in (stack_name, stack_id, partition, region, account_id)
    ):
        raise LiveTestError("bootstrap stack has no exact ledger-bound identity")
    expected = re.compile(
        rf"arn:{re.escape(partition)}:cloudformation:{re.escape(region)}:"
        rf"{re.escape(account_id)}:stack/{re.escape(stack_name)}/"
        rf"{AWS_UUID_PATTERN_TEXT}"
    )
    if expected.fullmatch(stack_id) is None:
        raise LiveTestError("bootstrap stack ID is outside the ledger authority")
    return stack_name, stack_id


def created_resource(
    ledger: dict[str, Any], resource_type: str, resource_id: str
) -> bool:
    return {"type": resource_type, "id": resource_id} in ledger.get(
        "created_resources", []
    )


def record_created_resource(
    ledger: dict[str, Any], resource_type: str, resource_id: str
) -> None:
    resource = {"type": resource_type, "id": resource_id}
    if resource not in ledger.setdefault("created_resources", []):
        ledger["created_resources"].append(resource)


def require_ownership_tags(tags: list[dict[str, str]], execution_id: str) -> None:
    observed = {tag["Key"]: tag["Value"] for tag in tags}
    expected = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": execution_id,
    }
    if any(observed.get(key) != value for key, value in expected.items()):
        raise LiveTestError(
            "recorded publication resource has unexpected ownership tags"
        )


def stack_status_if_exists(
    name: str, region: str, environment: dict[str, str] | None = None
) -> str | None:
    identifier = name
    expected_stack_id = identifier if identifier.startswith("arn:") else None
    expected_name = (
        identifier.split(":stack/", 1)[1].split("/", 1)[0]
        if expected_stack_id is not None and ":stack/" in identifier
        else identifier
    )
    result = command(
        [
            "aws",
            "cloudformation",
            "describe-stacks",
            "--region",
            region,
            "--stack-name",
            name,
            "--no-cli-pager",
        ],
        env=environment,
        check=False,
    )
    if result.returncode == 0:
        try:
            document = json.loads(result.stdout or "")
        except json.JSONDecodeError as error:
            raise LiveTestError(f"stack status is invalid JSON: {name}") from error
        stacks = document.get("Stacks") if isinstance(document, dict) else None
        if (
            not isinstance(stacks, list)
            or len(stacks) != 1
            or stacks[0].get("StackName") != expected_name
            or (
                expected_stack_id is not None
                and stacks[0].get("StackId") != expected_stack_id
            )
            or not isinstance(stacks[0].get("StackStatus"), str)
        ):
            raise LiveTestError(
                f"stack status violated the exact-identifier contract: {identifier}"
            )
        return stacks[0]["StackStatus"]
    detail = result.stderr or ""
    if "ValidationError" not in detail or "does not exist" not in detail:
        raise LiveTestError(f"unable to verify that stack is absent: {name}")
    return None


def stack_exists(
    name: str, region: str, environment: dict[str, str] | None = None
) -> bool:
    return stack_status_if_exists(name, region, environment) is not None


def assert_absent_stack(name: str, region: str) -> None:
    if stack_exists(name, region):
        raise LiveTestError(f"refusing to reuse existing stack: {name}")


def describe_change_set_if_exists(
    ledger: dict[str, Any],
    environment: dict[str, str],
    stack_name: str,
    change_set_name: str,
    *,
    expected_stack_id: str | None = None,
) -> dict[str, Any] | None:
    stack_identifier = expected_stack_id or stack_name
    result = command(
        [
            "aws",
            "cloudformation",
            "describe-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            stack_identifier,
            "--change-set-name",
            change_set_name,
            "--include-property-values",
            "--output",
            "json",
            "--no-cli-pager",
        ],
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr or ""
        if any(
            marker in detail
            for marker in (
                "ChangeSetNotFound",
                "does not exist",
                "does not exist in Stack",
            )
        ):
            return None
        raise LiveTestError("unable to reconcile the exact change-set request")
    try:
        description = json.loads(result.stdout or "")
    except json.JSONDecodeError as error:
        raise LiveTestError("reconciled change set returned invalid JSON") from error
    if (
        not isinstance(description, dict)
        or description.get("StackName") != stack_name
        or (
            expected_stack_id is not None
            and description.get("StackId") != expected_stack_id
        )
        or description.get("ChangeSetName") != change_set_name
        or not isinstance(description.get("ChangeSetId"), str)
    ):
        raise LiveTestError("reconciled change set violates its exact identity")
    require_change_set_id_authority(
        ledger,
        description["ChangeSetId"],
        "reconciled change set",
        expected_name=change_set_name,
    )
    return description


def validate_bootstrap_refresh_review(
    description: dict[str, Any], changes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    # DescribeChangeSet does not return the request-only ChangeSetType field.
    # bootstrap_refresh fixes the create request to UPDATE and separately binds
    # the response to the exact stack, name, and change-set ID it requested.
    if (
        description.get("Status") != "CREATE_COMPLETE"
        or description.get("ExecutionStatus") != "AVAILABLE"
        or not changes
        or len({item.get("path") for item in changes}) != len(changes)
        or any(
            BOOTSTRAP_REFRESH_ALLOWED_CHANGES.get(item["path"]) != item["resource_type"]
            for item in changes
        )
        or any(item.get("action") != "Modify" for item in changes)
        or any(item.get("replacement") not in {None, "False"} for item in changes)
    ):
        raise LiveTestError(
            "bootstrap refresh contains changes outside the scoped bootstrap resources"
        )
    return sorted(changes, key=lambda item: item["path"])


def bootstrap_refresh_changes(description: dict[str, Any]) -> list[dict[str, Any]]:
    raw_changes = description.get("Changes")
    if not isinstance(raw_changes, list):
        raise LiveTestError("bootstrap refresh returned an invalid change list")
    changes: list[dict[str, Any]] = []
    for change in raw_changes:
        resource = change.get("ResourceChange", {})
        logical_id = resource.get("LogicalResourceId")
        if not isinstance(logical_id, str) or not logical_id:
            raise LiveTestError("bootstrap refresh change is missing a logical ID")
        if resource.get("ChangeSetId"):
            raise LiveTestError("bootstrap refresh cannot contain a nested change set")
        changes.append(
            {
                "path": f"root/{logical_id}",
                "action": resource.get("Action"),
                "resource_type": resource.get("ResourceType"),
                "replacement": resource.get("Replacement"),
            }
        )
    return validate_bootstrap_refresh_review(description, changes)


def bootstrap_zone_transition(
    ledger: dict[str, Any],
    observed_parameters: dict[str, str],
    expected_parameters: dict[str, str],
) -> bool:
    if observed_parameters == expected_parameters:
        return False
    observed_without_zone = dict(observed_parameters)
    expected_without_zone = dict(expected_parameters)
    observed_zone = observed_without_zone.pop("PublicHostedZoneId", None)
    expected_zone = expected_without_zone.pop("PublicHostedZoneId", None)
    allowed = (
        observed_without_zone == expected_without_zone
        and ledger.get("dns_mode") == "temporary_delegated_zone"
        and observed_zone == "none"
        and expected_zone == ledger.get("public_hosted_zone_id")
        and isinstance(expected_zone, str)
        and expected_zone != "none"
        and created_resource(ledger, "route53_hosted_zone", expected_zone)
    )
    if not allowed:
        raise LiveTestError("bootstrap refresh parameters changed outside the ledger")
    return True


def verify_owned_bootstrap_zone(
    ledger: dict[str, Any], deployment_environment: dict[str, str]
) -> None:
    zone_id = str(ledger["public_hosted_zone_id"])
    hosted_zone = aws_json(
        ["route53", "get-hosted-zone", "--id", zone_id],
        env=deployment_environment,
    )
    if hosted_zone["HostedZone"]["Name"].rstrip(".") != ledger[
        "public_hosted_zone_name"
    ] or hosted_zone["HostedZone"]["Config"].get("PrivateZone"):
        raise LiveTestError("bootstrap refresh hosted zone does not match the ledger")
    tags = aws_json(
        [
            "route53",
            "list-tags-for-resource",
            "--resource-type",
            "hostedzone",
            "--resource-id",
            zone_id,
        ],
        env=deployment_environment,
    )
    require_ownership_tags(tags["ResourceTagSet"]["Tags"], ledger["execution_id"])


def init(args: argparse.Namespace) -> None:
    execution_id = args.execution_id
    if not EXECUTION_PATTERN.fullmatch(execution_id):
        raise LiveTestError("execution ID must match bft-[a-z0-9-]{4,20}")
    assert_no_unresolved_local_live_state_for_init(execution_id)
    if read_retired_execution_marker(execution_id) is not None:
        raise LiveTestError("execution ID is permanently retired and cannot be reused")
    path = migrate_legacy_execution_if_needed(execution_id)
    if path.exists():
        raise LiveTestError(f"refusing to overwrite existing ledger: {path}")
    if path.parent.exists():
        raise LiveTestError(
            "refusing to initialize inside a pre-existing durable execution directory"
        )
    estimate = cost_estimate(
        args.planned_hours,
        args.connect_minutes,
        args.enable_demo_site,
        args.runtime_profile,
        args.create_connect_demo,
    )
    require_cost_estimate_within_ceiling(args.max_usd, estimate["conservative_total"])
    caller = identity()
    account = caller["Account"]
    arn_parts = caller.get("Arn", "").split(":", 2)
    if len(arn_parts) != 3 or not re.fullmatch(r"aws(?:-[a-z0-9]+)*", arn_parts[1]):
        raise LiveTestError("AWS caller identity has an invalid partition")
    partition = arn_parts[1]
    trusted_principal = durable_trusted_principal(caller)
    root_bootstrap_exception = caller["Arn"] == f"arn:aws:iam::{account}:root"
    if root_bootstrap_exception and not args.allow_root_bootstrap:
        raise LiveTestError(
            "AWS account root is not accepted by default; use an IAM Identity "
            "Center or assumed-role session, or explicitly acknowledge the "
            "one-time bootstrap exception with --allow-root-bootstrap"
        )
    assert_no_account_live_state_for_init(
        args.execution_id, account, partition, args.region
    )
    connect_mode = "disposable" if args.create_connect_demo else "existing"
    if args.create_connect_demo:
        if args.runtime_profile != "starter":
            raise LiveTestError("the disposable qualification uses the Starter profile")
        connect_instance_arn = (
            f"arn:aws:connect:{args.region}:{account}:instance/unused"
        )
        target_flow_arn = connect_instance_arn + "/contact-flow/unused"
    else:
        connect_instance_arn = args.connect_instance_arn
        target_flow_arn = args.target_flow_arn
        if not target_flow_arn:
            raise LiveTestError(
                "--target-flow-arn is required with --connect-instance-arn"
            )
        if f":{account}:instance/" not in connect_instance_arn:
            raise LiveTestError("Connect instance is outside the active AWS account")
        if not target_flow_arn.startswith(connect_instance_arn + "/contact-flow/"):
            raise LiveTestError(
                "target flow does not belong to the supplied Connect instance"
            )
        instance_id = connect_instance_arn.rsplit("/", 1)[-1]
        flow_id = target_flow_arn.rsplit("/", 1)[-1]
        aws_json(
            [
                "connect",
                "describe-instance",
                "--region",
                args.region,
                "--instance-id",
                instance_id,
            ]
        )
        aws_json(
            [
                "connect",
                "describe-contact-flow",
                "--region",
                args.region,
                "--instance-id",
                instance_id,
                "--contact-flow-id",
                flow_id,
            ]
        )
    sip_security = (
        "sips_srtp"
        if not args.create_connect_demo or args.secure_sips_proof
        else "sip_rtp"
    )
    if sip_security == "sips_srtp" and bool(args.hosted_zone_id) == bool(
        args.delegated_zone_name
    ):
        raise LiveTestError(
            "SIPS proof requires exactly one hosted zone ID or delegated zone name"
        )
    if sip_security == "sip_rtp" and (args.hosted_zone_id or args.delegated_zone_name):
        raise LiveTestError("the IP-only SIP proof does not accept DNS parameters")
    if args.hosted_zone_id:
        zone_id = normalize_zone_id(args.hosted_zone_id)
        zone = aws_json(["route53", "get-hosted-zone", "--id", zone_id])
        zone_name = zone["HostedZone"]["Name"].rstrip(".")
        if zone["HostedZone"]["Config"].get("PrivateZone"):
            raise LiveTestError(
                "the SIP hostname requires a public Route 53 hosted zone"
            )
        dns_mode = "existing_route53_zone"
    elif args.delegated_zone_name:
        zone_id = "none"
        zone_name = args.delegated_zone_name.rstrip(".")
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])",
            zone_name,
        ):
            raise LiveTestError("delegated zone name is not a valid public DNS name")
        dns_mode = "temporary_delegated_zone"
    else:
        zone_id = "none"
        zone_name = "none"
        dns_mode = "ip_only"
    sip_hostname = args.sip_hostname or "unused.bridgefu.invalid"
    if dns_mode != "ip_only" and (
        not sip_hostname.endswith("." + zone_name) and sip_hostname != zone_name
    ):
        raise LiveTestError("SIP hostname is not inside the supplied hosted zone")
    api_key = os.environ.get(SECRET_ENV, "")
    if len(api_key) < 24:
        raise LiveTestError(f"{SECRET_ENV} is missing or too short")
    public_key = os.environ.get(PUBLIC_KEY_ENV, "")
    if (args.enable_demo_site or args.create_connect_demo) and not re.fullmatch(
        r"[A-Za-z0-9._~:/+=-]{8,256}", public_key
    ):
        raise LiveTestError(
            f"{PUBLIC_KEY_ENV} must contain the browser-safe Vapi public key "
            "for a browser or disposable Connect qualification"
        )
    stack_name = f"bridgefu-{execution_id}"
    qualification_stack = f"{stack_name}-qualification"
    bootstrap_stack = f"{stack_name}-bootstrap"
    assert_absent_stack(stack_name, args.region)
    assert_absent_stack(qualification_stack, args.region)
    assert_absent_stack(bootstrap_stack, args.region)
    owned = aws_json(
        [
            "resourcegroupstaggingapi",
            "get-resources",
            "--region",
            args.region,
            "--tag-filters",
            f"Key=BridgefuExecutionId,Values={execution_id}",
        ]
    )
    if owned.get("ResourceTagMappingList"):
        raise LiveTestError("AWS already contains resources with this execution ID")
    bucket = f"bridgefu-recipe-{account}-{args.region}-{execution_id}"
    repository = f"bridgefu-test/{execution_id}"
    if exact_probe_exists(
        [
            "s3api",
            "head-bucket",
            "--region",
            args.region,
            "--bucket",
            bucket,
        ],
        absent_markers=("(404)", "Not Found", "NoSuchBucket"),
        label="preflight artifact bucket",
    ):
        raise LiveTestError("the exact artifact bucket name already exists")
    if exact_probe_exists(
        [
            "ecr",
            "describe-repositories",
            "--region",
            args.region,
            "--repository-names",
            repository,
        ],
        absent_markers=("RepositoryNotFoundException",),
        label="preflight ECR repository",
    ):
        raise LiveTestError("the exact ECR repository name already exists")
    connect_logs = aws_json(
        [
            "logs",
            "describe-log-groups",
            "--region",
            args.region,
            "--log-group-name-prefix",
            f"/aws/connect/{execution_id}-connect",
        ]
    )
    if any(
        group.get("logGroupName") == f"/aws/connect/{execution_id}-connect"
        for group in connect_logs.get("logGroups", [])
    ):
        raise LiveTestError("the exact disposable Connect log group already exists")
    created_at = utc_now()
    ledger = {
        "schema_version": 1,
        "execution_id": execution_id,
        "project": PROJECT,
        "managed_by": MANAGED_BY,
        "recipe": RECIPE,
        "created_at": created_at,
        "qualification_deadline_at": qualification_deadline_for(
            created_at, args.planned_hours
        ),
        "cost_ceiling_type": "estimate_with_absolute_deadline",
        "status": "initialized",
        "region": args.region,
        "partition": partition,
        "account_id": account,
        "trusted_principal_arn": trusted_principal,
        "initial_caller_session_arn": caller["Arn"],
        "root_bootstrap_exception": root_bootstrap_exception,
        "connect_instance_arn": connect_instance_arn,
        "target_flow_arn": target_flow_arn,
        "connect_mode": connect_mode,
        "public_hosted_zone_id": zone_id,
        "public_hosted_zone_name": zone_name,
        "dns_mode": dns_mode,
        "sip_hostname": sip_hostname,
        "sip_security": sip_security,
        "runtime_profile": args.runtime_profile,
        "enable_demo_site": bool(args.enable_demo_site),
        "demo_site_bucket": f"bfu-{account}-{args.region}-{execution_id}-site",
        "demo_site_public_key_sha256": (
            hashlib.sha256(public_key.encode()).hexdigest()
            if args.enable_demo_site
            else None
        ),
        "vapi_public_key_sha256": (
            hashlib.sha256(public_key.encode()).hexdigest()
            if args.enable_demo_site or args.create_connect_demo
            else None
        ),
        "vapi_private_key_sha256": hashlib.sha256(api_key.encode()).hexdigest(),
        "max_usd": args.max_usd,
        "cost_estimate": estimate,
        "artifact_bucket": bucket,
        "ecr_repository": repository,
        "stack_name": stack_name,
        "qualification_stack_name": qualification_stack,
        "bootstrap_stack_name": bootstrap_stack,
        "created_resources": [],
        "events": [],
    }
    ensure_live_state_root()
    ensure_private_directory(path.parent)
    write_initial_recovery_authority(path, ledger)
    record(
        path,
        ledger,
        "preflight_passed",
        caller_kind=caller["Arn"].split(":")[-1],
        trusted_principal_arn=trusted_principal,
        root_bootstrap_exception=root_bootstrap_exception,
    )
    print(path)
    print(
        f"conservative AWS planning estimate (not a real-time spend cap): "
        f"${estimate['conservative_total']:.2f} of ${args.max_usd:.2f}; "
        f"absolute deadline {ledger['qualification_deadline_at']}"
    )


def access_analyzer_waiver_reason(
    finding: dict[str, Any], execution_id: str
) -> str | None:
    """Return evidence text only for an exact, independently verified catalog lag."""
    if finding.get("findingType") != "ERROR":
        return None
    if finding.get("issueCode") != "INVALID_ACTION":
        return None
    details = finding.get("findingDetails")
    if not isinstance(details, str):
        return None
    rule = ACCESS_ANALYZER_CATALOG_LAG_WAIVERS.get(details)
    if rule is None:
        return None
    policy_suffix, reason = rule
    if finding.get("policy") != f"bridgefu-{execution_id}-{policy_suffix}":
        return None
    return reason


def partition_access_analyzer_errors(
    raw_errors: list[dict[str, Any]], execution_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Separate exact catalog-lag waivers from errors that must remain fatal."""
    errors: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []
    for finding in raw_errors:
        reason = access_analyzer_waiver_reason(finding, execution_id)
        if reason is None:
            errors.append(finding)
        else:
            waivers.append({**finding, "reason": reason})
    return errors, waivers


def validate_deployment_role_policies(
    path: Path, ledger: dict[str, Any], environment: dict[str, str]
) -> Path:
    """Fail closed when IAM Access Analyzer finds an invalid bootstrap policy."""
    prefix = f"bridgefu-{ledger['execution_id']}-deployer-"
    role_contract = {
        f"bridgefu-{ledger['execution_id']}-deployer": {
            f"{prefix}artifacts",
            f"{prefix}control",
        },
        f"bridgefu-{ledger['execution_id']}-cloudformation": {
            f"{prefix}artifacts",
            f"{prefix}control",
            f"{prefix}application",
            f"{prefix}compute",
            f"{prefix}data",
            *(
                {f"{prefix}demo"}
                if ledger.get("connect_mode") == "disposable"
                else set()
            ),
            *(
                {f"{prefix}runner"}
                if ledger.get("connect_mode") == "disposable"
                else set()
            ),
        },
        f"bridgefu-{ledger['execution_id']}-qualifier": set(),
        **(
            {f"bridgefu-{ledger['execution_id']}-runner": set()}
            if ledger.get("connect_mode") == "disposable"
            else {}
        ),
    }
    inline_contract = {
        f"bridgefu-{ledger['execution_id']}-deployer": set(),
        f"bridgefu-{ledger['execution_id']}-cloudformation": set(),
        f"bridgefu-{ledger['execution_id']}-qualifier": {"BridgefuRecipeQualification"},
        **(
            {
                f"bridgefu-{ledger['execution_id']}-runner": {
                    "BridgefuQualificationRunner"
                }
            }
            if ledger.get("connect_mode") == "disposable"
            else {}
        ),
    }
    expected_policy_prefix = (
        f"arn:aws:iam::{ledger['account_id']}:policy/"
        f"bridgefu-{ledger['execution_id']}-deployer-"
    )
    managed: dict[str, dict[str, Any]] = {}
    inline_documents: list[tuple[str, str, dict[str, Any]]] = []
    for role_name, expected_names in role_contract.items():
        attached = aws_json(
            ["iam", "list-attached-role-policies", "--role-name", role_name],
            env=environment,
        ).get("AttachedPolicies", [])
        observed_names = {item["PolicyName"] for item in attached}
        if observed_names != expected_names:
            raise LiveTestError(
                "bootstrap role policy attachments violate the least-privilege contract"
            )
        for item in attached:
            arn = item["PolicyArn"]
            if not arn.startswith(expected_policy_prefix):
                raise LiveTestError("bootstrap role has an unexpected attached policy")
            managed[arn] = item
        inline_response = aws_json(
            ["iam", "list-role-policies", "--role-name", role_name],
            env=environment,
        )
        inline_names = (
            inline_response.get("PolicyNames")
            if isinstance(inline_response, dict)
            else None
        )
        if (
            not isinstance(inline_names, list)
            or set(inline_names) != inline_contract[role_name]
        ):
            raise LiveTestError(
                "bootstrap role inline policies violate the least-privilege contract"
            )
        for name in sorted(inline_names):
            document = aws_json(
                [
                    "iam",
                    "get-role-policy",
                    "--role-name",
                    role_name,
                    "--policy-name",
                    name,
                ],
                env=environment,
            )["PolicyDocument"]
            inline_documents.append((role_name, name, document))
    policies: list[dict[str, Any]] = []
    for arn, item in sorted(managed.items()):
        policy = aws_json(["iam", "get-policy", "--policy-arn", arn], env=environment)[
            "Policy"
        ]
        version = aws_json(
            [
                "iam",
                "get-policy-version",
                "--policy-arn",
                arn,
                "--version-id",
                policy["DefaultVersionId"],
            ],
            env=environment,
        )["PolicyVersion"]
        validation = aws_json(
            [
                "accessanalyzer",
                "validate-policy",
                "--policy-type",
                "IDENTITY_POLICY",
                "--policy-document",
                json.dumps(version["Document"], separators=(",", ":")),
            ],
            env=environment,
        )
        policies.append(
            {
                "name": item["PolicyName"],
                "arn": arn,
                "findings": validation.get("findings", []),
            }
        )
    for role_name, name, document in inline_documents:
        validation = aws_json(
            [
                "accessanalyzer",
                "validate-policy",
                "--policy-type",
                "IDENTITY_POLICY",
                "--policy-document",
                json.dumps(document, separators=(",", ":")),
            ],
            env=environment,
        )
        policies.append(
            {
                "name": f"inline:{role_name}:{name}",
                "arn": f"arn:aws:iam::{ledger['account_id']}:role/{role_name}/inline/{name}",
                "findings": validation.get("findings", []),
            }
        )
    raw_errors = [
        {"policy": policy["name"], **finding}
        for policy in policies
        for finding in policy["findings"]
        if finding.get("findingType") == "ERROR"
    ]
    errors, waivers = partition_access_analyzer_errors(
        raw_errors, ledger["execution_id"]
    )
    evidence = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "role_arns": [
            ledger["deployment_role_arn"],
            ledger["cloudformation_execution_role_arn"],
            ledger["qualification_role_arn"],
            *(
                [ledger["qualification_runner_role_arn"]]
                if ledger.get("connect_mode") == "disposable"
                else []
            ),
        ],
        "validated_at": utc_now(),
        "policy_count": len(policies),
        "raw_error_count": len(raw_errors),
        "waived_error_count": len(waivers),
        "error_count": len(errors),
        "waivers": waivers,
        "policies": policies,
    }
    evidence_path = path.parent / "bootstrap-policy-validation.json"
    atomic_json(evidence_path, evidence)
    ledger["bootstrap_policy_validation_path"] = os.fspath(evidence_path)
    ledger["bootstrap_policy_validation_error_count"] = len(errors)
    record(
        path,
        ledger,
        "bootstrap_policies_validated",
        policy_count=len(policies),
        error_count=len(errors),
    )
    if errors:
        raise LiveTestError(
            "IAM Access Analyzer found invalid deployment-role policy entries"
        )
    return evidence_path


def bootstrap(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if ledger["status"] != "initialized":
        raise LiveTestError("bootstrap requires an initialized ledger")
    caller = identity()
    if durable_trusted_principal(caller) != ledger["trusted_principal_arn"]:
        raise LiveTestError("bootstrap caller differs from the preflight principal")
    template = (
        root_dir()
        / "recipes"
        / "vapi-amazon-connect-screen-pop"
        / "cloudformation"
        / "test-deployment-role.yaml"
    )
    expected_parameters = bootstrap_stack_parameters(
        ledger, ledger["trusted_principal_arn"]
    )
    parameters = [
        f"ParameterKey={key},ParameterValue={value}"
        for key, value in expected_parameters.items()
    ]
    recorded_bootstrap_stack_id = ledger.get("bootstrap_stack_id")
    bootstrap_lookup = ledger["bootstrap_stack_name"]
    if recorded_bootstrap_stack_id is not None:
        _bootstrap_name, bootstrap_lookup = exact_bootstrap_stack_identity(ledger)
    existing = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_lookup,
        ],
        check=False,
    )
    if existing:
        if not args.adopt_existing:
            raise LiveTestError(
                "bootstrap stack already exists; use --adopt-existing only after "
                "an authorized identity created the exact reviewed template"
            )
        stacks = existing.get("Stacks") if isinstance(existing, dict) else None
        if (
            not isinstance(stacks, list)
            or len(stacks) != 1
            or stacks[0].get("StackName") != ledger["bootstrap_stack_name"]
        ):
            raise LiveTestError("adopted bootstrap stack identity is invalid")
        stack = stacks[0]
        if (
            recorded_bootstrap_stack_id is not None
            and stack.get("StackId") != recorded_bootstrap_stack_id
        ):
            raise LiveTestError("adopted bootstrap stack replaced its bound identity")
        ledger["bootstrap_stack_id"] = stack.get("StackId")
        _bootstrap_name, bootstrap_stack_id = exact_bootstrap_stack_identity(ledger)
        if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
            raise LiveTestError("adopted bootstrap stack is not stably complete")
        observed_parameters = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in stack.get("Parameters", [])
        }
        if observed_parameters != expected_parameters:
            raise LiveTestError(
                "adopted bootstrap stack parameters do not match the ledger"
            )
        active_template = aws_json(
            [
                "cloudformation",
                "get-template",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
                "--template-stage",
                "Original",
            ]
        ).get("TemplateBody")
        if canonical_template_sha256(active_template) != canonical_template_sha256(
            template
        ):
            raise LiveTestError("adopted bootstrap stack template does not match")
        observed_tags = {item["Key"]: item["Value"] for item in stack.get("Tags", [])}
        expected_tags = {
            "Project": PROJECT,
            "ManagedBy": MANAGED_BY,
            "BridgefuExecutionId": ledger["execution_id"],
            "BridgefuRecipe": RECIPE,
        }
        if any(observed_tags.get(key) != value for key, value in expected_tags.items()):
            raise LiveTestError("adopted bootstrap stack ownership tags do not match")
        record(path, ledger, "bootstrap_stack_adopted")
    else:
        if recorded_bootstrap_stack_id is not None:
            raise LiveTestError("the exact ledger-bound bootstrap stack is unavailable")
        if args.adopt_existing:
            raise LiveTestError("--adopt-existing requires the exact bootstrap stack")
        require_qualification_deadline(path, ledger, "bootstrap creation")
        created = aws_json(
            [
                "cloudformation",
                "create-stack",
                "--region",
                ledger["region"],
                "--stack-name",
                ledger["bootstrap_stack_name"],
                "--template-body",
                template_body_argument(template),
                "--parameters",
                *parameters,
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "--on-failure",
                "DO_NOTHING",
                "--tags",
                *tag_arguments(ledger["execution_id"]),
            ]
        )
        if not isinstance(created, dict):
            raise LiveTestError("bootstrap creation returned no exact stack ID")
        ledger["bootstrap_stack_id"] = created.get("StackId")
        _bootstrap_name, bootstrap_stack_id = exact_bootstrap_stack_identity(ledger)
        record(
            path,
            ledger,
            "bootstrap_stack_created",
            resource=ledger["bootstrap_stack_name"],
        )
        aws_wait(
            [
                "cloudformation",
                "wait",
                "stack-create-complete",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
            ]
        )
        stack = aws_json(
            [
                "cloudformation",
                "describe-stacks",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
            ]
        )["Stacks"][0]
    if stack.get("StackId") != ledger.get("bootstrap_stack_id") or stack.get(
        "StackName"
    ) != ledger.get("bootstrap_stack_name"):
        raise LiveTestError("bootstrap stack response changed its exact identity")
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}
    expected_roles = {
        "DeploymentRoleArn": (
            f"arn:aws:iam::{ledger['account_id']}:role/"
            f"bridgefu-{ledger['execution_id']}-deployer"
        ),
        "CloudFormationExecutionRoleArn": (
            f"arn:aws:iam::{ledger['account_id']}:role/"
            f"bridgefu-{ledger['execution_id']}-cloudformation"
        ),
        "QualificationRoleArn": (
            f"arn:aws:iam::{ledger['account_id']}:role/"
            f"bridgefu-{ledger['execution_id']}-qualifier"
        ),
    }
    if any(outputs.get(key) != value for key, value in expected_roles.items()):
        raise LiveTestError("bootstrap stack returned unexpected role ARNs")
    ledger["deployment_role_arn"] = expected_roles["DeploymentRoleArn"]
    ledger["cloudformation_execution_role_arn"] = expected_roles[
        "CloudFormationExecutionRoleArn"
    ]
    ledger["qualification_role_arn"] = expected_roles["QualificationRoleArn"]
    if ledger.get("connect_mode") == "disposable":
        expected_runner = (
            f"arn:aws:iam::{ledger['account_id']}:role/"
            f"bridgefu-{ledger['execution_id']}-runner"
        )
        if outputs.get("QualificationRunnerRoleArn") != expected_runner:
            raise LiveTestError("bootstrap returned an unexpected runner role")
        public_ip = outputs.get("QualificationSourceEipPublicIp", "")
        allocation_id = outputs.get("QualificationSourceEipAllocationId", "")
        try:
            source_network = ipaddress.ip_network(f"{public_ip}/32", strict=True)
        except ValueError as error:
            raise LiveTestError("bootstrap returned an invalid runner EIP") from error
        if not source_network.network_address.is_global or not re.fullmatch(
            r"eipalloc-[0-9a-f]+", allocation_id
        ):
            raise LiveTestError("bootstrap runner EIP outputs violate the contract")
        ledger["qualification_runner_role_arn"] = expected_runner
        ledger["qualification_source_eip_allocation_id"] = allocation_id
        ledger["qualification_source_cidr"] = str(source_network)
    deployment_environment = assume_env(ledger, "deployment")
    deploy_identity = identity(deployment_environment)["Arn"]
    validate_deployment_role_policies(path, ledger, deployment_environment)
    ledger["status"] = "bootstrap_complete"
    record(path, ledger, "temporary_roles_ready")
    print(f"temporary deployment role ready: {deploy_identity}")


def authorize_caller(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if ledger.get("status") != "initialized":
        raise LiveTestError("caller authorization is allowed only before publication")
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    caller = identity()
    expected_root = f"arn:aws:iam::{ledger['account_id']}:root"
    if (
        caller["Arn"] != expected_root
        or ledger.get("trusted_principal_arn") != expected_root
    ):
        raise LiveTestError("caller authorization requires the recorded account root")
    match = re.fullmatch(
        rf"arn:aws:iam::{ledger['account_id']}:user/([A-Za-z0-9+=,.@_/-]+)",
        args.principal_arn,
    )
    if not match:
        raise LiveTestError(
            "the replacement principal must be an IAM user in this account"
        )
    user = aws_json(["iam", "get-user", "--user-name", match.group(1)])["User"]
    if user.get("Arn") != args.principal_arn:
        raise LiveTestError("the replacement IAM user identity did not match")
    template = (
        root_dir()
        / "recipes"
        / "vapi-amazon-connect-screen-pop"
        / "cloudformation"
        / "test-deployment-role.yaml"
    )
    _bootstrap_name, bootstrap_stack_id = exact_bootstrap_stack_identity(ledger)
    parameters = bootstrap_stack_parameters(ledger, args.principal_arn)
    update = aws_json(
        [
            "cloudformation",
            "update-stack",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--template-body",
            template_body_argument(template),
            "--parameters",
            *[parameter(key, value) for key, value in sorted(parameters.items())],
            "--capabilities",
            "CAPABILITY_NAMED_IAM",
            "--tags",
            *tag_arguments(ledger["execution_id"]),
        ]
    )
    if not isinstance(update, dict) or update.get("StackId") != bootstrap_stack_id:
        raise LiveTestError("bootstrap caller update changed its exact stack identity")
    aws_wait(
        [
            "cloudformation",
            "wait",
            "stack-update-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
        ]
    )
    ledger["trusted_principal_arn"] = args.principal_arn
    record(path, ledger, "temporary_non_root_caller_authorized")
    print(args.principal_arn)


def bootstrap_refresh(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("bootstrap refresh requires the exact execution ID")
    bootstrap_stack_name, bootstrap_stack_id = exact_bootstrap_stack_identity(ledger)
    evidence_path = path.parent / "bootstrap-refresh-change-set-review.json"
    if ledger.get("bootstrap_refresh_complete"):
        if ledger.get("bootstrap_refresh_release_id") != ledger.get("release_id"):
            raise LiveTestError(
                "bootstrap refresh completion belongs to another candidate"
            )
        try:
            completed_evidence = json.loads(evidence_path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise LiveTestError("bootstrap refresh evidence is unavailable") from error
        if (
            not isinstance(completed_evidence, dict)
            or completed_evidence.get("stack_name") != bootstrap_stack_name
            or completed_evidence.get("stack_id") != bootstrap_stack_id
        ):
            raise LiveTestError(
                "bootstrap refresh evidence is not bound to the exact stack ID"
            )
        validate_candidate_release(path, ledger, assume_env(ledger, "deployment"))
        print(evidence_path)
        return
    if (
        ledger.get("status") != "published"
        or ledger.get("change_set_arn")
        or ledger.get("publication_source_tree_sha256")
        != working_tree_digest(root_dir())
    ):
        raise LiveTestError(
            "bootstrap refresh requires the exact published candidate before app review"
        )
    caller = identity()
    durable_caller = durable_trusted_principal(caller)
    if durable_caller != ledger.get("trusted_principal_arn"):
        raise LiveTestError(
            "bootstrap refresh caller differs from the authorized principal"
        )
    if ledger.get("bootstrap_refresh_change_set_arn"):
        expected_change_set_name = f"bootstrap-refresh-{ledger['release_id']}"
        if ledger.get("bootstrap_refresh_change_set_name") != expected_change_set_name:
            raise LiveTestError(
                "bootstrap refresh review belongs to a superseded candidate"
            )
        require_change_set_id_authority(
            ledger,
            ledger.get("bootstrap_refresh_change_set_arn"),
            "bootstrap refresh review",
            expected_name=expected_change_set_name,
        )
        if evidence_path.is_file():
            try:
                existing_evidence = json.loads(evidence_path.read_text())
            except (OSError, json.JSONDecodeError) as error:
                raise LiveTestError("bootstrap refresh evidence is invalid") from error
            if (
                not isinstance(existing_evidence, dict)
                or existing_evidence.get("change_set_id")
                != ledger.get("bootstrap_refresh_change_set_arn")
                or existing_evidence.get("change_set_name")
                != ledger.get("bootstrap_refresh_change_set_name")
                or existing_evidence.get("stack_name") != bootstrap_stack_name
                or existing_evidence.get("stack_id") != bootstrap_stack_id
            ):
                raise LiveTestError(
                    "bootstrap refresh evidence is not bound to the exact stack ID"
                )
            print(evidence_path)
            print(
                "authorized administrator execution is required before "
                "bootstrap-refresh-verify"
            )
            return
    application = command(
        [
            "aws",
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            ledger["stack_name"],
            "--output",
            "json",
            "--no-cli-pager",
        ],
        check=False,
    )
    if application.returncode == 0:
        raise LiveTestError("bootstrap permissions cannot refresh after app deployment")
    application_error = application.stderr or ""
    if (
        "ValidationError" not in application_error
        or "does not exist" not in application_error
    ):
        raise LiveTestError("unable to verify that the application stack is absent")
    deployment_environment = assume_env(ledger, "deployment")
    bootstrap_response = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
        ]
    )
    bootstrap_stacks = (
        bootstrap_response.get("Stacks")
        if isinstance(bootstrap_response, dict)
        else None
    )
    if (
        not isinstance(bootstrap_stacks, list)
        or len(bootstrap_stacks) != 1
        or bootstrap_stacks[0].get("StackName") != bootstrap_stack_name
        or bootstrap_stacks[0].get("StackId") != bootstrap_stack_id
    ):
        raise LiveTestError("bootstrap refresh target changed its exact stack identity")
    bootstrap_stack = bootstrap_stacks[0]
    if bootstrap_stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise LiveTestError(
            "bootstrap refresh requires a stable CREATE_COMPLETE or UPDATE_COMPLETE stack"
        )
    expected_parameters = bootstrap_stack_parameters(ledger, durable_caller)
    observed_parameters = {
        item["ParameterKey"]: item.get("ParameterValue", "")
        for item in bootstrap_stack.get("Parameters", [])
    }
    if bootstrap_zone_transition(ledger, observed_parameters, expected_parameters):
        verify_owned_bootstrap_zone(ledger, deployment_environment)
    observed_tags = {
        item["Key"]: item["Value"] for item in bootstrap_stack.get("Tags", [])
    }
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": ledger["execution_id"],
        "BridgefuRecipe": RECIPE,
    }
    if any(observed_tags.get(key) != value for key, value in expected_tags.items()):
        raise LiveTestError("bootstrap refresh ownership tags changed")

    template = (
        path.parent
        / "release"
        / "recipe"
        / "cloudformation"
        / "test-deployment-role.yaml"
    )
    manifest = json.loads((path.parent / "release" / "manifest.json").read_text())
    relative = "recipe/cloudformation/test-deployment-role.yaml"
    matches = [
        item for item in manifest.get("artifacts", []) if item.get("path") == relative
    ]
    if (
        len(matches) != 1
        or matches[0].get("sha256") != hashlib.sha256(template.read_bytes()).hexdigest()
    ):
        raise LiveTestError("bootstrap refresh template is not the published artifact")
    active_template = aws_json(
        [
            "cloudformation",
            "get-template",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--template-stage",
            "Original",
        ],
        env=deployment_environment,
    ).get("TemplateBody")
    if (
        canonical_template_sha256(active_template)
        == canonical_template_sha256(template)
        and observed_parameters == expected_parameters
    ):
        outputs = {
            item["OutputKey"]: item["OutputValue"]
            for item in bootstrap_stack.get("Outputs", [])
        }
        if outputs.get("DeploymentRoleArn") != ledger.get(
            "deployment_role_arn"
        ) or outputs.get("QualificationRoleArn") != ledger.get(
            "qualification_role_arn"
        ):
            raise LiveTestError(
                "no-op bootstrap refresh changed the temporary role identities"
            )
        if ledger.get("connect_mode") == "disposable":
            required_outputs = {
                "QualificationRunnerRoleArn",
                "QualificationSourceEipAllocationId",
                "QualificationSourceEipPublicIp",
            }
            if not required_outputs.issubset(outputs):
                raise LiveTestError(
                    "no-op bootstrap refresh is missing qualification runner outputs"
                )
            ledger["qualification_runner_role_arn"] = outputs[
                "QualificationRunnerRoleArn"
            ]
            ledger["qualification_source_eip_allocation_id"] = outputs[
                "QualificationSourceEipAllocationId"
            ]
            ledger["qualification_source_cidr"] = (
                outputs["QualificationSourceEipPublicIp"] + "/32"
            )
        refreshed_deployment_environment = assume_env(ledger, "deployment")
        identity(refreshed_deployment_environment)
        identity(assume_env(ledger, "qualification"))
        validate_deployment_role_policies(
            path, ledger, refreshed_deployment_environment
        )
        evidence = {
            "change_set_id": None,
            "change_set_name": None,
            "stack_name": bootstrap_stack_name,
            "stack_id": bootstrap_stack_id,
            "status": "NO_CHANGES",
            "execution_status": "NOT_REQUIRED",
            "change_set_type": "UPDATE",
            "template_sha256": matches[0]["sha256"],
            "release_id": ledger["release_id"],
            "publication_source_tree_sha256": ledger["publication_source_tree_sha256"],
            "changes": [],
            "reviewed_at": utc_now(),
        }
        atomic_json(evidence_path, evidence)
        ledger["bootstrap_refresh_template_sha256"] = matches[0]["sha256"]
        ledger["bootstrap_refresh_complete"] = True
        ledger["bootstrap_refresh_release_id"] = ledger["release_id"]
        record(path, ledger, "bootstrap_refresh_no_changes")
        print(evidence_path)
        return
    change_set_name = f"bootstrap-refresh-{ledger['release_id']}"
    recovered = describe_change_set_if_exists(
        ledger,
        deployment_environment,
        bootstrap_stack_name,
        change_set_name,
        expected_stack_id=bootstrap_stack_id,
    )
    if recovered is not None:
        result = {
            "Id": recovered["ChangeSetId"],
            "StackId": recovered["StackId"],
        }
        event = "bootstrap_refresh_change_set_request_reconciled"
    else:
        require_qualification_deadline(path, ledger, "bootstrap refresh review")
        result = aws_json(
            [
                "cloudformation",
                "create-change-set",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
                "--change-set-name",
                change_set_name,
                "--change-set-type",
                "UPDATE",
                "--description",
                f"Bridgefu bounded test-role refresh {ledger['execution_id']}",
                "--template-body",
                template_body_argument(template),
                "--parameters",
                *[
                    parameter(key, value)
                    for key, value in sorted(expected_parameters.items())
                ],
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "--client-token",
                f"bootstrap-refresh-{ledger['release_id']}",
                "--tags",
                *tag_arguments(ledger["execution_id"]),
            ],
            env=deployment_environment,
        )
        event = "bootstrap_refresh_change_set_requested"
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("Id"), str)
        or not result["Id"].startswith("arn:")
        or result.get("StackId") != bootstrap_stack_id
    ):
        raise LiveTestError(
            "bootstrap refresh request is not bound to the exact stack ID"
        )
    require_change_set_id_authority(
        ledger,
        result["Id"],
        "bootstrap refresh review",
        expected_name=change_set_name,
    )
    ledger["bootstrap_refresh_change_set_arn"] = result["Id"]
    ledger["bootstrap_refresh_change_set_name"] = change_set_name
    record(path, ledger, event)
    aws_wait(
        [
            "cloudformation",
            "wait",
            "change-set-create-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--change-set-name",
            result["Id"],
        ],
        env=deployment_environment,
    )
    try:
        description = aws_json(
            [
                "cloudformation",
                "describe-change-set",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
                "--change-set-name",
                result["Id"],
                "--include-property-values",
            ],
            env=deployment_environment,
        )
        if (
            description.get("StackName") != bootstrap_stack_name
            or description.get("StackId") != bootstrap_stack_id
            or description.get("ChangeSetName") != change_set_name
            or description.get("ChangeSetId") != result["Id"]
        ):
            raise LiveTestError(
                "bootstrap refresh response differs from the requested change set"
            )
        changes = bootstrap_refresh_changes(description)
    except Exception:
        aws_json(
            [
                "cloudformation",
                "delete-change-set",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
                "--change-set-name",
                result["Id"],
            ],
            env=deployment_environment,
            check=False,
        )
        raise
    evidence = {
        "change_set_id": description["ChangeSetId"],
        "change_set_name": change_set_name,
        "stack_name": bootstrap_stack_name,
        "stack_id": bootstrap_stack_id,
        "status": description["Status"],
        "execution_status": description["ExecutionStatus"],
        "change_set_type": "UPDATE",
        "template_sha256": matches[0]["sha256"],
        "release_id": ledger["release_id"],
        "publication_source_tree_sha256": ledger["publication_source_tree_sha256"],
        "changes": changes,
        "reviewed_at": utc_now(),
    }
    atomic_json(evidence_path, evidence)
    ledger["bootstrap_refresh_change_set_arn"] = description["ChangeSetId"]
    ledger["bootstrap_refresh_change_set_name"] = change_set_name
    ledger["bootstrap_refresh_template_sha256"] = matches[0]["sha256"]
    record(
        path,
        ledger,
        "bootstrap_refresh_change_set_reviewed",
        change_count=len(changes),
    )
    print(evidence_path)
    print(
        "authorized administrator execution is required before bootstrap-refresh-verify"
    )


def bootstrap_refresh_verify(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError(
            "bootstrap refresh verification requires the exact execution ID"
        )
    bootstrap_stack_name, bootstrap_stack_id = exact_bootstrap_stack_identity(ledger)
    evidence_path = path.parent / "bootstrap-refresh-change-set-review.json"
    if ledger.get("bootstrap_refresh_complete"):
        try:
            completed_evidence = json.loads(evidence_path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise LiveTestError("bootstrap refresh evidence is unavailable") from error
        if (
            not isinstance(completed_evidence, dict)
            or completed_evidence.get("stack_name") != bootstrap_stack_name
            or completed_evidence.get("stack_id") != bootstrap_stack_id
        ):
            raise LiveTestError(
                "bootstrap refresh evidence is not bound to the exact stack ID"
            )
        print(evidence_path)
        return
    if (
        ledger.get("status") != "published"
        or ledger.get("publication_source_tree_sha256")
        != working_tree_digest(root_dir())
        or not ledger.get("bootstrap_refresh_change_set_arn")
        or ledger.get("bootstrap_refresh_change_set_name")
        != f"bootstrap-refresh-{ledger.get('release_id')}"
    ):
        raise LiveTestError(
            "bootstrap refresh verification has no exact reviewed candidate"
        )
    change_set_id = require_change_set_id_authority(
        ledger,
        ledger.get("bootstrap_refresh_change_set_arn"),
        "bootstrap refresh execution",
        expected_name=ledger.get("bootstrap_refresh_change_set_name"),
    )
    caller = identity()
    durable_caller = durable_trusted_principal(caller)
    if durable_caller != ledger.get("trusted_principal_arn"):
        raise LiveTestError(
            "bootstrap refresh verifier differs from the authorized principal"
        )
    evidence = json.loads(evidence_path.read_text())
    if (
        evidence.get("change_set_id") != ledger.get("bootstrap_refresh_change_set_arn")
        or evidence.get("change_set_name")
        != ledger.get("bootstrap_refresh_change_set_name")
        or evidence.get("stack_name") != bootstrap_stack_name
        or evidence.get("stack_id") != bootstrap_stack_id
        or evidence.get("change_set_type") != "UPDATE"
        or evidence.get("template_sha256")
        != ledger.get("bootstrap_refresh_template_sha256")
        or evidence.get("release_id") != ledger.get("release_id")
        or evidence.get("publication_source_tree_sha256")
        != ledger.get("publication_source_tree_sha256")
    ):
        raise LiveTestError("bootstrap refresh evidence no longer matches the ledger")
    deployment_environment = assume_env(ledger, "deployment")
    description = aws_json(
        [
            "cloudformation",
            "describe-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--change-set-name",
            change_set_id,
            "--include-property-values",
        ],
        env=deployment_environment,
    )
    if (
        description.get("ChangeSetId") != ledger["bootstrap_refresh_change_set_arn"]
        or description.get("ChangeSetName")
        != ledger["bootstrap_refresh_change_set_name"]
        or description.get("StackName") != bootstrap_stack_name
        or description.get("StackId") != bootstrap_stack_id
        or description.get("ExecutionStatus") != "EXECUTE_COMPLETE"
        or description.get("Status") not in {"CREATE_COMPLETE", "DELETE_COMPLETE"}
    ):
        raise LiveTestError("reviewed bootstrap refresh has not completed execution")
    refreshed_response = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
        ],
        env=deployment_environment,
    )
    refreshed_stacks = (
        refreshed_response.get("Stacks")
        if isinstance(refreshed_response, dict)
        else None
    )
    if (
        not isinstance(refreshed_stacks, list)
        or len(refreshed_stacks) != 1
        or refreshed_stacks[0].get("StackName") != bootstrap_stack_name
        or refreshed_stacks[0].get("StackId") != bootstrap_stack_id
    ):
        raise LiveTestError("bootstrap refresh result changed its exact stack identity")
    refreshed = refreshed_stacks[0]
    if refreshed.get("StackStatus") != "UPDATE_COMPLETE":
        raise LiveTestError("bootstrap refresh did not reach UPDATE_COMPLETE")
    active_template = aws_json(
        [
            "cloudformation",
            "get-template",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--template-stage",
            "Original",
        ],
        env=deployment_environment,
    ).get("TemplateBody")
    template = (
        path.parent
        / "release"
        / "recipe"
        / "cloudformation"
        / "test-deployment-role.yaml"
    )
    if canonical_template_sha256(active_template) != canonical_template_sha256(
        template
    ):
        raise LiveTestError("bootstrap stack is not using the reviewed template")
    outputs = {
        item["OutputKey"]: item["OutputValue"] for item in refreshed.get("Outputs", [])
    }
    if outputs.get("DeploymentRoleArn") != ledger.get(
        "deployment_role_arn"
    ) or outputs.get("QualificationRoleArn") != ledger.get("qualification_role_arn"):
        raise LiveTestError("bootstrap refresh changed the temporary role identities")
    if ledger.get("connect_mode") == "disposable":
        ledger["qualification_runner_role_arn"] = outputs["QualificationRunnerRoleArn"]
        ledger["qualification_source_eip_allocation_id"] = outputs[
            "QualificationSourceEipAllocationId"
        ]
        ledger["qualification_source_cidr"] = (
            outputs["QualificationSourceEipPublicIp"] + "/32"
        )
    expected_parameters = bootstrap_stack_parameters(ledger, durable_caller)
    observed_parameters = {
        item["ParameterKey"]: item.get("ParameterValue", "")
        for item in refreshed.get("Parameters", [])
    }
    if observed_parameters != expected_parameters:
        raise LiveTestError("bootstrap refresh did not install the exact parameters")
    observed_tags = {item["Key"]: item["Value"] for item in refreshed.get("Tags", [])}
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": ledger["execution_id"],
        "BridgefuRecipe": RECIPE,
    }
    if any(observed_tags.get(key) != value for key, value in expected_tags.items()):
        raise LiveTestError("bootstrap refresh changed ownership tags")
    refreshed_deployment_environment = assume_env(ledger, "deployment")
    identity(refreshed_deployment_environment)
    identity(assume_env(ledger, "qualification"))
    validate_deployment_role_policies(path, ledger, refreshed_deployment_environment)
    ledger["bootstrap_refresh_complete"] = True
    ledger["bootstrap_refresh_release_id"] = ledger["release_id"]
    record(path, ledger, "bootstrap_refresh_complete")
    print(evidence_path)


def create_bucket(ledger: dict[str, Any], env: dict[str, str]) -> None:
    args = [
        "s3api",
        "create-bucket",
        "--region",
        ledger["region"],
        "--bucket",
        ledger["artifact_bucket"],
    ]
    if ledger["region"] != "us-east-1":
        args.extend(
            [
                "--create-bucket-configuration",
                f"LocationConstraint={ledger['region']}",
            ]
        )
    aws_json(args, env=env)
    aws_json(
        [
            "s3api",
            "put-public-access-block",
            "--bucket",
            ledger["artifact_bucket"],
            "--public-access-block-configuration",
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ],
        env=env,
    )
    aws_json(
        [
            "s3api",
            "put-bucket-encryption",
            "--bucket",
            ledger["artifact_bucket"],
            "--server-side-encryption-configuration",
            '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true,"BlockedEncryptionTypes":{"EncryptionType":["SSE-C"]}}]}',
        ],
        env=env,
    )
    aws_json(
        [
            "s3api",
            "put-bucket-versioning",
            "--bucket",
            ledger["artifact_bucket"],
            "--versioning-configuration",
            "Status=Enabled",
        ],
        env=env,
    )
    aws_json(
        [
            "s3api",
            "put-bucket-tagging",
            "--bucket",
            ledger["artifact_bucket"],
            "--tagging",
            json.dumps(
                {
                    "TagSet": [
                        {"Key": "Project", "Value": PROJECT},
                        {"Key": "ManagedBy", "Value": MANAGED_BY},
                        {
                            "Key": "BridgefuExecutionId",
                            "Value": ledger["execution_id"],
                        },
                        {"Key": "BridgefuRecipe", "Value": RECIPE},
                    ]
                }
            ),
        ],
        env=env,
    )


def create_vapi_secret(ledger: dict[str, Any], env: dict[str, str]) -> str:
    secret = bound_vapi_private_key(ledger)
    directory = ledger_path(ledger["execution_id"]).parent
    with tempfile.NamedTemporaryFile(
        mode="w", dir=directory, prefix=".vapi-key-", delete=False
    ) as handle:
        handle.write(secret)
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    try:
        result = aws_json(
            [
                "secretsmanager",
                "create-secret",
                "--region",
                ledger["region"],
                "--name",
                f"bridgefu-{ledger['execution_id']}-vapi-api-key",
                "--description",
                "Temporary Vapi API key for an approved Bridgefu qualification run",
                "--secret-string",
                f"file://{temporary}",
                "--tags",
                *tag_arguments(ledger["execution_id"]),
            ],
            env=env,
        )
    finally:
        temporary.unlink(missing_ok=True)
    return result["ARN"]


def validate_vapi_private_key_secret(
    ledger: dict[str, Any], env: dict[str, str], secret_arn: str
) -> None:
    response = aws_json(
        [
            "secretsmanager",
            "get-secret-value",
            "--region",
            ledger["region"],
            "--secret-id",
            secret_arn,
        ],
        env=env,
    )
    secret = response.get("SecretString") if isinstance(response, dict) else None
    if not isinstance(secret, str) or hashlib.sha256(
        secret.encode()
    ).hexdigest() != ledger.get("vapi_private_key_sha256"):
        raise LiveTestError("Vapi API-key secret differs from preflight")


def create_vapi_public_key_secret(ledger: dict[str, Any], env: dict[str, str]) -> str:
    public_key = bound_vapi_public_key(ledger)
    directory = ledger_path(ledger["execution_id"]).parent
    with tempfile.NamedTemporaryFile(
        mode="w", dir=directory, prefix=".vapi-public-key-", delete=False
    ) as handle:
        json.dump({"public_key": public_key}, handle)
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    try:
        result = aws_json(
            [
                "secretsmanager",
                "create-secret",
                "--region",
                ledger["region"],
                "--name",
                f"bridgefu-{ledger['execution_id']}-vapi-public-key",
                "--description",
                "Temporary Vapi public key for headless qualification",
                "--secret-string",
                f"file://{temporary}",
                "--tags",
                *tag_arguments(ledger["execution_id"]),
            ],
            env=env,
        )
    finally:
        temporary.unlink(missing_ok=True)
    return result["ARN"]


def validate_vapi_public_key_secret(
    ledger: dict[str, Any], env: dict[str, str], secret_arn: str
) -> None:
    response = aws_json(
        [
            "secretsmanager",
            "get-secret-value",
            "--region",
            ledger["region"],
            "--secret-id",
            secret_arn,
        ],
        env=env,
    )
    raw = response.get("SecretString") if isinstance(response, dict) else None
    if not isinstance(raw, str):
        raise LiveTestError("Vapi public-key secret has no string value")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise LiveTestError("Vapi public-key secret is invalid JSON") from error
    public_key = value.get("public_key") if isinstance(value, dict) else None
    if (
        not isinstance(public_key, str)
        or set(value) != {"public_key"}
        or hashlib.sha256(public_key.encode()).hexdigest()
        != ledger.get("vapi_public_key_sha256")
    ):
        raise LiveTestError("Vapi public-key secret differs from preflight")


def describe_secret_if_exists(
    ledger: dict[str, Any], env: dict[str, str], secret_name: str
) -> dict[str, Any] | None:
    result = command(
        [
            "aws",
            "secretsmanager",
            "describe-secret",
            "--region",
            ledger["region"],
            "--secret-id",
            secret_name,
            "--output",
            "json",
            "--no-cli-pager",
        ],
        env=env,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr or ""
        if "ResourceNotFoundException" in detail:
            return None
        raise LiveTestError(
            "unable to determine whether the execution-owned secret exists"
        )
    try:
        value = json.loads(result.stdout or "")
    except json.JSONDecodeError as error:
        raise LiveTestError("secret description returned invalid JSON") from error
    if not isinstance(value, dict) or value.get("Name") != secret_name:
        raise LiveTestError("secret description violated the exact-name contract")
    return value


def ensure_vapi_verification_secrets(
    path: Path, ledger: dict[str, Any], env: dict[str, str]
) -> None:
    """Create or revalidate execution-owned test credentials after IAM refresh."""
    bound_vapi_private_key(ledger)
    secret_name = f"bridgefu-{ledger['execution_id']}-vapi-api-key"
    secret = describe_secret_if_exists(ledger, env, secret_name)
    if secret is not None:
        require_ownership_tags(secret.get("Tags", []), ledger["execution_id"])
        ledger["vapi_api_key_secret_arn"] = secret["ARN"]
        validate_vapi_private_key_secret(ledger, env, ledger["vapi_api_key_secret_arn"])
        if not created_resource(ledger, "secret", secret_name):
            record_created_resource(ledger, "secret", secret_name)
            record(path, ledger, "temporary_vapi_secret_adopted")
    else:
        ledger["vapi_api_key_secret_arn"] = create_vapi_secret(ledger, env)
        validate_vapi_private_key_secret(ledger, env, ledger["vapi_api_key_secret_arn"])
        record_created_resource(ledger, "secret", secret_name)
        record(path, ledger, "temporary_vapi_secret_created")

    if ledger.get("connect_mode") != "disposable":
        return
    bound_vapi_public_key(ledger)
    public_secret_name = f"bridgefu-{ledger['execution_id']}-vapi-public-key"
    public_secret = describe_secret_if_exists(ledger, env, public_secret_name)
    if public_secret is not None:
        require_ownership_tags(public_secret.get("Tags", []), ledger["execution_id"])
        ledger["vapi_public_key_secret_arn"] = public_secret["ARN"]
        validate_vapi_public_key_secret(
            ledger, env, ledger["vapi_public_key_secret_arn"]
        )
        if not created_resource(ledger, "secret", public_secret_name):
            record_created_resource(ledger, "secret", public_secret_name)
            record(path, ledger, "temporary_vapi_public_key_secret_adopted")
    else:
        ledger["vapi_public_key_secret_arn"] = create_vapi_public_key_secret(
            ledger, env
        )
        validate_vapi_public_key_secret(
            ledger, env, ledger["vapi_public_key_secret_arn"]
        )
        record_created_resource(ledger, "secret", public_secret_name)
        record(path, ledger, "temporary_vapi_public_key_secret_created")


def staged_release_manifest(
    release: Path,
    release_id: str,
    image_uri: str,
    *,
    expected_source_tree_sha256: str | None = None,
    expected_public_key_sha256: str | None = None,
) -> dict[str, Any]:
    manifest = release / "manifest.json"
    public_key = release / "manifest.pub"
    manifest_digest = release / "manifest.sha256"
    signature = release / "manifest.sig"
    if not all(
        path.is_file() and not path.is_symlink()
        for path in (
            release / ".bridgefu-release-build",
            manifest,
            public_key,
            manifest_digest,
            signature,
        )
    ):
        raise LiveTestError("staged release is missing a required regular file")
    manifest_bytes = manifest.read_bytes()
    full_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if full_manifest_sha256[:20] != release_id:
        raise LiveTestError("staged release ID does not match its manifest")
    if manifest_digest.read_text(encoding="ascii") != (
        f"{full_manifest_sha256}  manifest.json\n"
    ):
        raise LiveTestError("staged release manifest digest file is invalid")
    try:
        payload = json.loads(manifest_bytes)
    except json.JSONDecodeError as error:
        raise LiveTestError("staged release manifest is not valid JSON") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise LiveTestError("staged release manifest schema changed")
    if payload.get("bridgefu", {}).get("image_uri") != image_uri:
        raise LiveTestError("staged release image differs from the immutable image")
    if (
        expected_source_tree_sha256 is not None
        and payload.get("bridgefu", {}).get("source_tree_sha256")
        != expected_source_tree_sha256
    ):
        raise LiveTestError("staged release source digest differs from the candidate")
    public_key_sha256 = hashlib.sha256(public_key.read_bytes()).hexdigest()
    if (
        expected_public_key_sha256 is not None
        and public_key_sha256 != expected_public_key_sha256
    ):
        raise LiveTestError("staged release signing public key changed")
    verified = command(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            os.fspath(public_key),
            "-in",
            os.fspath(manifest),
            "-sigfile",
            os.fspath(signature),
        ],
        check=False,
    )
    if verified.returncode != 0:
        raise LiveTestError("staged release manifest signature is invalid")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise LiveTestError("staged release manifest has no artifact inventory")
    expected_files = {
        ".bridgefu-release-build",
        "manifest.json",
        "manifest.pub",
        "manifest.sha256",
        "manifest.sig",
    }
    seen: set[str] = set()
    for entry in artifacts:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise LiveTestError("staged release artifact entry has an invalid shape")
        relative = entry.get("path")
        digest = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in seen
            or re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            or not isinstance(size_bytes, int)
            or size_bytes < 0
            or size_bytes > MAX_RELEASE_BYTES
        ):
            raise LiveTestError("staged release artifact inventory is unsafe")
        artifact = release / relative
        if artifact.is_symlink() or not artifact.is_file():
            raise LiveTestError("staged release artifact is not a regular file")
        if (
            artifact.stat().st_size != size_bytes
            or hashlib.sha256(artifact.read_bytes()).hexdigest() != digest
        ):
            raise LiveTestError("staged release artifact differs from its manifest")
        seen.add(relative)
        expected_files.add(relative)
    actual_files = {
        item.relative_to(release).as_posix()
        for item in release.rglob("*")
        if item.is_file()
    }
    if actual_files != expected_files:
        raise LiveTestError("staged release file set differs from its manifest")
    return payload


def validate_staged_release(release: Path, release_id: str, image_uri: str) -> bool:
    try:
        staged_release_manifest(release, release_id, image_uri)
    except (LiveTestError, OSError, UnicodeError):
        return False
    return True


def bounded_release_files(release: Path) -> list[tuple[Path, str, int]]:
    result: list[tuple[Path, str, int]] = []
    total_bytes = 0
    for item in sorted(release.rglob("*")):
        if not item.is_file() or item.name == ".bridgefu-release-build":
            continue
        size_bytes = item.stat().st_size
        total_bytes += size_bytes
        relative = item.relative_to(release).as_posix()
        result.append((item, relative, size_bytes))
        if len(result) > MAX_RELEASE_OBJECTS:
            raise LiveTestError(
                f"release exceeds the {MAX_RELEASE_OBJECTS}-object publication guard"
            )
        if total_bytes > MAX_RELEASE_BYTES:
            raise LiveTestError(
                f"release exceeds the {MAX_RELEASE_BYTES}-byte publication guard"
            )
    if not result:
        raise LiveTestError("release bundle is empty")
    return result


def validate_candidate_release(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    release = path.parent / "release"
    release_id = ledger.get("release_id")
    image_uri = ledger.get("bridgefu_image_uri")
    source_digest = ledger.get("publication_source_tree_sha256")
    public_key_digest = ledger.get("release_manifest_public_key_sha256")
    if (
        not isinstance(release_id, str)
        or re.fullmatch(r"[0-9a-f]{20}", release_id) is None
        or not isinstance(image_uri, str)
        or "@sha256:" not in image_uri
        or re.fullmatch(r"[0-9a-f]{64}", str(source_digest)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(public_key_digest)) is None
    ):
        raise LiveTestError("candidate release ledger binding is incomplete")
    payload = staged_release_manifest(
        release,
        release_id,
        image_uri,
        expected_source_tree_sha256=source_digest,
        expected_public_key_sha256=public_key_digest,
    )
    manifest_sha256 = hashlib.sha256(
        (release / "manifest.json").read_bytes()
    ).hexdigest()
    if ledger.get("release_manifest_sha256") != manifest_sha256:
        raise LiveTestError("candidate manifest digest differs from the ledger")
    expected_prefix = f"qualification/{ledger['execution_id']}/{release_id}"
    if ledger.get("release_prefix") != expected_prefix:
        raise LiveTestError("candidate release prefix differs from its release ID")
    published = ledger.get("published_objects")
    if not isinstance(published, dict):
        raise LiveTestError("candidate has no immutable published object inventory")
    files = bounded_release_files(release)
    if set(published) != {relative for _, relative, _ in files}:
        raise LiveTestError("published object inventory differs from the release")
    for item, relative, size_bytes in files:
        expected_sha256 = hashlib.sha256(item.read_bytes()).hexdigest()
        record_value = published.get(relative)
        if (
            not isinstance(record_value, dict)
            or record_value.get("key") != f"{expected_prefix}/{relative}"
            or record_value.get("sha256") != expected_sha256
            or record_value.get("size_bytes") != size_bytes
            or not isinstance(record_value.get("version_id"), str)
            or not record_value["version_id"]
        ):
            raise LiveTestError("published object is not bound to the staged release")
        if environment is not None:
            observed = aws_json(
                [
                    "s3api",
                    "head-object",
                    "--region",
                    ledger["region"],
                    "--bucket",
                    ledger["artifact_bucket"],
                    "--key",
                    record_value["key"],
                    "--version-id",
                    record_value["version_id"],
                ],
                env=environment,
            )
            if (
                not isinstance(observed, dict)
                or observed.get("ContentLength") != size_bytes
                or observed.get("Metadata", {}).get("sha256") != expected_sha256
            ):
                raise LiveTestError(
                    "immutable S3 object differs from the reviewed release"
                )
            if relative.startswith("recipe/cloudformation/") and relative.endswith(
                (".yaml", ".yml")
            ):
                latest = aws_json(
                    [
                        "s3api",
                        "head-object",
                        "--region",
                        ledger["region"],
                        "--bucket",
                        ledger["artifact_bucket"],
                        "--key",
                        record_value["key"],
                    ],
                    env=environment,
                )
                if (
                    not isinstance(latest, dict)
                    or latest.get("VersionId") != record_value["version_id"]
                    or latest.get("ContentLength") != size_bytes
                    or latest.get("Metadata", {}).get("sha256") != expected_sha256
                ):
                    raise LiveTestError(
                        "versionless nested-template URL no longer selects the signed version"
                    )
    return payload


def working_tree_digest(root: Path) -> str:
    """Hash immutable tracked or non-ignored source for candidate freezing."""
    packaged_marker = root / ".bridgefu-source-tree-sha256"
    if os.environ.get("BRIDGEFU_PACKAGED_SOURCE") == "1" and packaged_marker.is_file():
        value = packaged_marker.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise LiveTestError("packaged source-tree marker is invalid")
        return value
    listed = command(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root,
    ).stdout.splitlines()
    digest = hashlib.sha256()
    for relative in sorted(
        item for item in listed if item and item not in MUTABLE_SOURCE_DIGEST_PATHS
    ):
        item = root / relative
        if not item.is_file():
            continue
        encoded = relative.encode()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(item.stat().st_size.to_bytes(8, "big"))
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def candidate_image_tag(ledger: dict[str, Any]) -> str:
    generation = ledger.get("publication_generation", 1)
    if not isinstance(generation, int) or generation < 1 or generation > 99:
        raise LiveTestError("publication generation is invalid")
    if generation == 1:
        return ledger["execution_id"]
    return f"{ledger['execution_id']}-r{generation}"


def refresh_publication_candidate(ledger: dict[str, Any]) -> None:
    if ledger.get("status") not in {"published", "publishing"}:
        raise LiveTestError(
            "candidate refresh requires an undeployed publication candidate"
        )
    if any(
        ledger.get(field)
        for field in (
            "change_set_arn",
            "change_set_name",
            "stack_id",
            "qualification_change_set_arn",
            "qualification_change_set_name",
            "qualification_stack_id",
        )
    ):
        raise LiveTestError(
            "candidate refresh is forbidden after deployment review starts"
        )
    generation = ledger.get("publication_generation", 1)
    if not isinstance(generation, int) or generation < 1 or generation >= 99:
        raise LiveTestError("publication generation cannot be refreshed")
    ledger.setdefault("superseded_candidates", []).append(
        {
            "at": utc_now(),
            "generation": generation,
            "image_uri": ledger.get("bridgefu_image_uri"),
            "release_id": ledger.get("release_id"),
            "release_prefix": ledger.get("release_prefix"),
            "object_count": len(ledger.get("published_objects", {})),
            "bootstrap_refresh_change_set_arn": ledger.get(
                "bootstrap_refresh_change_set_arn"
            ),
            "bootstrap_refresh_template_sha256": ledger.get(
                "bootstrap_refresh_template_sha256"
            ),
        }
    )
    ledger["publication_generation"] = generation + 1
    for field in (
        "bridgefu_image_uri",
        "bridgefu_image_tag",
        "release_id",
        "release_prefix",
        "nested_template_base_url",
        "publication_source_tree_sha256",
        "release_manifest_sha256",
        "release_manifest_public_key_sha256",
    ):
        ledger.pop(field, None)
    for field in (
        "change_set_arn",
        "change_set_name",
        "review_stack_id",
        "change_set_review_sha256",
        "qualification_change_set_arn",
        "qualification_change_set_name",
        "qualification_review_stack_id",
        "qualification_change_set_review_sha256",
    ):
        ledger.pop(field, None)
    ledger["published_objects"] = {}
    ledger["bootstrap_refresh_complete"] = False
    for field in (
        "bootstrap_refresh_change_set_arn",
        "bootstrap_refresh_change_set_name",
        "bootstrap_refresh_template_sha256",
        "bootstrap_refresh_release_id",
    ):
        ledger.pop(field, None)
    ledger["status"] = "publishing"


def retire_unexecuted_create_review(
    ledger: dict[str, Any],
    environment: dict[str, str],
    existing_stack: dict[str, Any] | None,
    *,
    stack_name_key: str,
    change_set_arn_key: str,
    change_set_name_key: str,
    review_stack_id_key: str,
    review_sha256_key: str,
    expected_change_set_name: str,
) -> str | None:
    """Remove an exact failed or available CREATE review with zero resources."""
    change_set_arn = ledger.get(change_set_arn_key)
    change_set_name = ledger.get(change_set_name_key)
    if not change_set_arn and not change_set_name and existing_stack is None:
        ledger.pop(review_stack_id_key, None)
        ledger.pop(review_sha256_key, None)
        return None
    stack_name = ledger.get(stack_name_key)
    if (
        bool(change_set_arn) != bool(change_set_name)
        or existing_stack is None
        or existing_stack.get("StackName") != stack_name
        or existing_stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
    ):
        raise LiveTestError(
            "candidate refresh is forbidden after deployment review starts"
        )
    expected_stack_id = require_stack_id_for_name(
        ledger,
        existing_stack.get("StackId"),
        stack_name,
        "unexecuted review",
    )
    recorded_review_stack_id = ledger.get(review_stack_id_key)
    if (
        recorded_review_stack_id is not None
        and recorded_review_stack_id != expected_stack_id
    ):
        recorded_review_stack_id = require_stack_id_for_name(
            ledger,
            recorded_review_stack_id,
            stack_name,
            "stale unexecuted review",
        )
        stale_review_status = stack_status_if_exists(
            recorded_review_stack_id, ledger["region"], environment
        )
        if stale_review_status not in {None, "DELETE_COMPLETE"}:
            raise LiveTestError("stale review stack identity is still active")
    if not change_set_arn:
        recovered = describe_change_set_if_exists(
            ledger,
            environment,
            stack_name,
            expected_change_set_name,
            expected_stack_id=expected_stack_id,
        )
        if recovered is None:
            raise LiveTestError(
                "unrecorded review stack has no exact recoverable change set"
            )
        change_set_arn = recovered["ChangeSetId"]
        change_set_name = expected_change_set_name
    if change_set_name != expected_change_set_name:
        raise LiveTestError(
            "candidate refresh is forbidden after deployment review starts"
        )
    change_set_arn = require_change_set_id_authority(
        ledger,
        change_set_arn,
        "unexecuted review",
        expected_name=expected_change_set_name,
    )
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": ledger["execution_id"],
        "BridgefuRecipe": RECIPE,
    }
    description = aws_json(
        [
            "cloudformation",
            "describe-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
            "--change-set-name",
            change_set_arn,
        ],
        env=environment,
    )
    if (
        description.get("ChangeSetId") != change_set_arn
        or description.get("ChangeSetName") != expected_change_set_name
        or description.get("StackName") != stack_name
        or description.get("StackId") != expected_stack_id
        or (
            description.get("Status"),
            description.get("ExecutionStatus"),
        )
        not in {
            ("FAILED", "UNAVAILABLE"),
            ("CREATE_COMPLETE", "AVAILABLE"),
        }
    ):
        raise LiveTestError(
            "only an exact unexecuted application review can be retired"
        )
    observed_tags = {item["Key"]: item["Value"] for item in description.get("Tags", [])}
    if any(observed_tags.get(key) != value for key, value in expected_tags.items()):
        raise LiveTestError("failed application review ownership tags changed")
    resources = aws_json(
        [
            "cloudformation",
            "list-stack-resources",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
        ],
        env=environment,
    ).get("StackResourceSummaries", [])
    if resources:
        raise LiveTestError(
            "failed application review unexpectedly contains stack resources"
        )
    aws_json(
        [
            "cloudformation",
            "delete-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
            "--change-set-name",
            change_set_arn,
        ],
        env=environment,
    )
    aws_json(
        [
            "cloudformation",
            "delete-stack",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
        ],
        env=environment,
    )
    aws_wait(
        [
            "cloudformation",
            "wait",
            "stack-delete-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
        ],
        env=environment,
    )
    ledger.pop(change_set_arn_key, None)
    ledger.pop(change_set_name_key, None)
    ledger.pop(review_stack_id_key, None)
    ledger.pop(review_sha256_key, None)
    return expected_change_set_name


def retire_unexecuted_application_review(
    ledger: dict[str, Any],
    environment: dict[str, str],
    existing_stack: dict[str, Any] | None,
) -> str | None:
    return retire_unexecuted_create_review(
        ledger,
        environment,
        existing_stack,
        stack_name_key="stack_name",
        change_set_arn_key="change_set_arn",
        change_set_name_key="change_set_name",
        review_stack_id_key="review_stack_id",
        review_sha256_key="change_set_review_sha256",
        expected_change_set_name=f"reviewed-{ledger['execution_id']}",
    )


def retire_unexecuted_qualification_review(
    ledger: dict[str, Any],
    environment: dict[str, str],
    existing_stack: dict[str, Any] | None,
) -> str | None:
    return retire_unexecuted_create_review(
        ledger,
        environment,
        existing_stack,
        stack_name_key="qualification_stack_name",
        change_set_arn_key="qualification_change_set_arn",
        change_set_name_key="qualification_change_set_name",
        review_stack_id_key="qualification_review_stack_id",
        review_sha256_key="qualification_change_set_review_sha256",
        expected_change_set_name=f"qualification-{ledger['execution_id']}",
    )


def retire_pending_bootstrap_refresh(
    ledger: dict[str, Any], environment: dict[str, str]
) -> str | None:
    change_set_arn = ledger.get("bootstrap_refresh_change_set_arn")
    if ledger.get("bootstrap_refresh_complete") or not change_set_arn:
        return None
    expected_name = ledger.get("bootstrap_refresh_change_set_name")
    candidate_release_ids = {
        candidate.get("release_id")
        for candidate in ledger.get("superseded_candidates", [])
        if isinstance(candidate, dict) and candidate.get("release_id")
    }
    if ledger.get("release_id"):
        candidate_release_ids.add(ledger["release_id"])
    if expected_name not in {
        f"bootstrap-refresh-{release_id}" for release_id in candidate_release_ids
    }:
        raise LiveTestError(
            "pending bootstrap refresh is not bound to the published candidate"
        )
    bootstrap_stack_name, bootstrap_stack_id = exact_bootstrap_stack_identity(ledger)
    change_set_arn = require_change_set_id_authority(
        ledger,
        change_set_arn,
        "pending bootstrap refresh",
        expected_name=expected_name,
    )
    description = aws_json(
        [
            "cloudformation",
            "describe-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--change-set-name",
            change_set_arn,
            "--include-property-values",
        ],
        env=environment,
    )
    if (
        description.get("ChangeSetId") != change_set_arn
        or description.get("ChangeSetName") != expected_name
        or description.get("StackName") != bootstrap_stack_name
        or description.get("StackId") != bootstrap_stack_id
        or (
            description.get("Status"),
            description.get("ExecutionStatus"),
        )
        not in {
            ("FAILED", "UNAVAILABLE"),
            ("CREATE_COMPLETE", "AVAILABLE"),
        }
    ):
        raise LiveTestError(
            "pending bootstrap refresh is not the exact unexecuted reviewed change set"
        )
    aws_json(
        [
            "cloudformation",
            "delete-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
            "--change-set-name",
            change_set_arn,
        ],
        env=environment,
    )
    return expected_name


def publish(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    refresh = bool(getattr(args, "refresh_candidate", False))
    allowed_statuses = {"bootstrap_complete", "publishing"}
    if refresh:
        if ledger.get("status") not in {"published", "publishing"}:
            raise LiveTestError(
                "--refresh-candidate requires an undeployed publication candidate"
            )
    elif ledger.get("status") not in allowed_statuses:
        raise LiveTestError(
            "publish requires a completed bootstrap or resumable publication"
        )
    require_qualification_deadline(path, ledger, "release publication")
    public_key_was_unbound = (
        ledger.get("enable_demo_site") or ledger.get("connect_mode") == "disposable"
    ) and ledger.get("vapi_public_key_sha256") is None
    private_key_was_unbound = ledger.get("vapi_private_key_sha256") is None
    bound_vapi_public_key(ledger, allow_bind=refresh)
    bound_vapi_private_key(ledger, allow_bind=refresh)
    if public_key_was_unbound:
        record(path, ledger, "vapi_public_key_bound_during_candidate_refresh")
    if private_key_was_unbound:
        record(path, ledger, "vapi_private_key_bound_during_candidate_refresh")
    env = assume_env(ledger, "deployment")
    if refresh:

        def review_stack(stack_name: str) -> dict[str, Any] | None:
            response = aws_json(
                [
                    "cloudformation",
                    "describe-stacks",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    stack_name,
                ],
                env=env,
                check=False,
            )
            stacks = (response or {}).get("Stacks", [])
            if len(stacks) > 1:
                raise LiveTestError("review stack lookup returned multiple stacks")
            return stacks[0] if stacks else None

        retired_application_review = retire_unexecuted_application_review(
            ledger,
            env,
            review_stack(ledger["stack_name"]),
        )
        retired_qualification_review = None
        if ledger.get("connect_mode") == "disposable":
            retired_qualification_review = retire_unexecuted_qualification_review(
                ledger,
                env,
                review_stack(ledger["qualification_stack_name"]),
            )
        retired_bootstrap_refresh = retire_pending_bootstrap_refresh(ledger, env)
        refresh_publication_candidate(ledger)
        if retired_application_review:
            record(
                path,
                ledger,
                "unexecuted_application_review_retired",
                change_set_name=retired_application_review,
            )
        if retired_qualification_review:
            record(
                path,
                ledger,
                "unexecuted_qualification_review_retired",
                change_set_name=retired_qualification_review,
            )
        if retired_bootstrap_refresh:
            record(
                path,
                ledger,
                "bootstrap_refresh_change_set_retired",
                change_set_name=retired_bootstrap_refresh,
            )
        record(
            path,
            ledger,
            "publication_candidate_refreshed",
            generation=ledger["publication_generation"],
        )
    if ledger["status"] == "bootstrap_complete":
        ledger.setdefault("publication_generation", 1)
        ledger["status"] = "publishing"
        record(path, ledger, "publication_started")
    ledger.setdefault("publication_generation", 1)
    source_digest = working_tree_digest(root_dir())
    recorded_source = ledger.get("publication_source_tree_sha256")
    if recorded_source and recorded_source != source_digest:
        raise LiveTestError(
            "working tree changed after publication started; refresh the candidate explicitly"
        )
    if not recorded_source:
        ledger["publication_source_tree_sha256"] = source_digest
        record(path, ledger, "publication_source_frozen")
    if ledger["dns_mode"] == "temporary_delegated_zone":
        zone_id = ledger.get("public_hosted_zone_id", "none")
        if zone_id != "none" and created_resource(
            ledger, "route53_hosted_zone", zone_id
        ):
            hosted_zone = aws_json(
                ["route53", "get-hosted-zone", "--id", zone_id], env=env
            )
            if hosted_zone["HostedZone"]["Name"].rstrip(".") != ledger[
                "public_hosted_zone_name"
            ] or hosted_zone["HostedZone"]["Config"].get("PrivateZone"):
                raise LiveTestError("recorded delegated hosted zone does not match")
            tags = aws_json(
                [
                    "route53",
                    "list-tags-for-resource",
                    "--resource-type",
                    "hostedzone",
                    "--resource-id",
                    zone_id,
                ],
                env=env,
            )
            require_ownership_tags(
                tags["ResourceTagSet"]["Tags"], ledger["execution_id"]
            )
        else:
            if zone_id != "none":
                raise LiveTestError(
                    "delegated hosted zone is not recorded as test-owned"
                )
            require_qualification_deadline(path, ledger, "hosted-zone creation")
            hosted_zone = aws_json(
                [
                    "route53",
                    "create-hosted-zone",
                    "--name",
                    ledger["public_hosted_zone_name"],
                    "--caller-reference",
                    ledger["execution_id"],
                    "--hosted-zone-config",
                    f"Comment=Temporary Bridgefu qualification {ledger['execution_id']},PrivateZone=false",
                ],
                env=env,
            )
            zone_id = normalize_zone_id(hosted_zone["HostedZone"]["Id"])
            aws_json(
                [
                    "route53",
                    "change-tags-for-resource",
                    "--resource-type",
                    "hostedzone",
                    "--resource-id",
                    zone_id,
                    "--add-tags",
                    *tag_arguments(ledger["execution_id"]),
                ],
                env=env,
            )
            ledger["public_hosted_zone_id"] = zone_id
            ledger["delegation_verified"] = False
            record_created_resource(ledger, "route53_hosted_zone", zone_id)
            record(path, ledger, "temporary_delegated_zone_created")
        ledger["delegation_name_servers"] = sorted(
            hosted_zone["DelegationSet"]["NameServers"]
        )

    if created_resource(ledger, "s3_bucket", ledger["artifact_bucket"]):
        command(
            [
                "aws",
                "s3api",
                "head-bucket",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--no-cli-pager",
            ],
            env=env,
        )
        bucket_tags = aws_json(
            ["s3api", "get-bucket-tagging", "--bucket", ledger["artifact_bucket"]],
            env=env,
        )
        require_ownership_tags(bucket_tags["TagSet"], ledger["execution_id"])
    else:
        bucket_exists = exact_probe_exists(
            [
                "s3api",
                "head-bucket",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
            ],
            absent_markers=("(404)", "Not Found", "NoSuchBucket"),
            label="ephemeral artifact bucket",
            environment=env,
        )
        if bucket_exists:
            bucket_tags = aws_json(
                [
                    "s3api",
                    "get-bucket-tagging",
                    "--bucket",
                    ledger["artifact_bucket"],
                ],
                env=env,
            )
            require_ownership_tags(bucket_tags["TagSet"], ledger["execution_id"])
        else:
            require_qualification_deadline(path, ledger, "artifact bucket creation")
            create_bucket(ledger, env)
        record_created_resource(ledger, "s3_bucket", ledger["artifact_bucket"])
        record(
            path,
            ledger,
            "artifact_bucket_adopted" if bucket_exists else "artifact_bucket_created",
        )
    mirror_recovery_snapshot(path, ledger, env)

    if created_resource(ledger, "ecr_repository", ledger["ecr_repository"]):
        repository = aws_json(
            [
                "ecr",
                "describe-repositories",
                "--region",
                ledger["region"],
                "--repository-names",
                ledger["ecr_repository"],
            ],
            env=env,
        )["repositories"][0]
        repository_tags = aws_json(
            [
                "ecr",
                "list-tags-for-resource",
                "--region",
                ledger["region"],
                "--resource-arn",
                repository["repositoryArn"],
            ],
            env=env,
        )
        require_ownership_tags(repository_tags["tags"], ledger["execution_id"])
    else:
        repository_exists = exact_probe_exists(
            [
                "ecr",
                "describe-repositories",
                "--region",
                ledger["region"],
                "--repository-names",
                ledger["ecr_repository"],
            ],
            absent_markers=("RepositoryNotFoundException",),
            label="ephemeral ECR repository",
            environment=env,
        )
        if repository_exists:
            repository = aws_json(
                [
                    "ecr",
                    "describe-repositories",
                    "--region",
                    ledger["region"],
                    "--repository-names",
                    ledger["ecr_repository"],
                ],
                env=env,
            )["repositories"][0]
            repository_tags = aws_json(
                [
                    "ecr",
                    "list-tags-for-resource",
                    "--region",
                    ledger["region"],
                    "--resource-arn",
                    repository["repositoryArn"],
                ],
                env=env,
            )
            require_ownership_tags(repository_tags["tags"], ledger["execution_id"])
        else:
            require_qualification_deadline(path, ledger, "ECR repository creation")
            repository = aws_json(
                [
                    "ecr",
                    "create-repository",
                    "--region",
                    ledger["region"],
                    "--repository-name",
                    ledger["ecr_repository"],
                    "--image-tag-mutability",
                    "IMMUTABLE",
                    "--image-scanning-configuration",
                    "scanOnPush=true",
                    "--encryption-configuration",
                    "encryptionType=AES256",
                    "--tags",
                    *tag_arguments(ledger["execution_id"]),
                ],
                env=env,
            )["repository"]
        record_created_resource(ledger, "ecr_repository", ledger["ecr_repository"])
        record(
            path,
            ledger,
            (
                "ecr_repository_adopted"
                if repository_exists
                else "ecr_repository_created"
            ),
        )
    ledger["ecr_repository_arn"] = repository["repositoryArn"]
    ledger["ecr_repository_uri"] = repository["repositoryUri"]
    immutable_image = ledger.get("bridgefu_image_uri")
    if immutable_image:
        expected_prefix = f"{repository['repositoryUri']}@"
        if not immutable_image.startswith(expected_prefix):
            raise LiveTestError("recorded image does not belong to the test repository")
        digest = immutable_image.rsplit("@", 1)[-1]
        image = aws_json(
            [
                "ecr",
                "describe-images",
                "--region",
                ledger["region"],
                "--repository-name",
                ledger["ecr_repository"],
                "--image-ids",
                f"imageDigest={digest}",
            ],
            env=env,
        )["imageDetails"][0]
        if image["imageDigest"] != digest:
            raise LiveTestError("recorded immutable image digest is unavailable")
    else:
        image_tag = candidate_image_tag(ledger)
        ledger["bridgefu_image_tag"] = image_tag
        existing_image = aws_json(
            [
                "ecr",
                "describe-images",
                "--region",
                ledger["region"],
                "--repository-name",
                ledger["ecr_repository"],
                "--image-ids",
                f"imageTag={image_tag}",
            ],
            env=env,
            check=False,
        )
        if existing_image:
            image = existing_image["imageDetails"][0]
        else:
            require_qualification_deadline(path, ledger, "container publication")
            password = command(
                [
                    "aws",
                    "ecr",
                    "get-login-password",
                    "--region",
                    ledger["region"],
                    "--no-cli-pager",
                ],
                env=env,
            ).stdout
            registry = repository["repositoryUri"].split("/", 1)[0]
            with isolated_docker_environment(path.parent) as docker_env:
                command(
                    [
                        "docker",
                        "login",
                        "--username",
                        "AWS",
                        "--password-stdin",
                        registry,
                    ],
                    env=docker_env,
                    input_text=password,
                )
                revision = command(
                    ["git", "rev-parse", "HEAD"],
                    env=os.environ.copy(),
                    cwd=root_dir(),
                ).stdout.strip()
                source_epoch = command(
                    ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=root_dir()
                ).stdout.strip()
                build_date = (
                    dt.datetime.fromtimestamp(int(source_epoch), tz=dt.timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                tagged_image = f"{repository['repositoryUri']}:{image_tag}"
                command(
                    [
                        "docker",
                        "build",
                        "--platform",
                        "linux/arm64",
                        "--file",
                        os.fspath(root_dir() / "deploy" / "Dockerfile"),
                        "--tag",
                        tagged_image,
                        "--build-arg",
                        f"VCS_REF={revision}",
                        "--build-arg",
                        f"BUILD_DATE={build_date}",
                        os.fspath(root_dir()),
                    ],
                    env=docker_env,
                    capture=False,
                    cwd=root_dir(),
                )
                if working_tree_digest(root_dir()) != source_digest:
                    raise LiveTestError(
                        "working tree changed while the image was building"
                    )
                command(
                    ["docker", "push", tagged_image],
                    env=docker_env,
                    capture=False,
                )
            image = aws_json(
                [
                    "ecr",
                    "describe-images",
                    "--region",
                    ledger["region"],
                    "--repository-name",
                    ledger["ecr_repository"],
                    "--image-ids",
                    f"imageTag={image_tag}",
                ],
                env=env,
            )["imageDetails"][0]
        immutable_image = f"{repository['repositoryUri']}@{image['imageDigest']}"
        ledger["bridgefu_image_uri"] = immutable_image
        record(path, ledger, "immutable_image_published", digest=image["imageDigest"])

    if working_tree_digest(root_dir()) != source_digest:
        raise LiveTestError("working tree changed before release staging")
    release = path.parent / "release"
    resume_release_id = ledger.get("release_id")
    reuse_release = bool(
        resume_release_id
        and validate_staged_release(release, resume_release_id, immutable_image)
    )
    if not reuse_release:
        key_dir = Path(tempfile.mkdtemp(prefix=".release-signing-", dir=path.parent))
        try:
            private_key = key_dir / "private.pem"
            public_key = key_dir / "public.pem"
            command(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "Ed25519",
                    "-out",
                    os.fspath(private_key),
                ]
            )
            command(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    os.fspath(private_key),
                    "-pubout",
                    "-out",
                    os.fspath(public_key),
                ]
            )
            command(
                [
                    "python3",
                    os.fspath(root_dir() / "scripts" / "build-recipe-release.py"),
                    "--image-uri",
                    immutable_image,
                    "--output",
                    os.fspath(release),
                    "--signing-key",
                    os.fspath(private_key),
                    "--signing-public-key",
                    os.fspath(public_key),
                ]
            )
        finally:
            shutil.rmtree(key_dir)
    if working_tree_digest(root_dir()) != source_digest:
        raise LiveTestError("working tree changed while building the release bundle")
    manifest_bytes = (release / "manifest.json").read_bytes()
    release_id = hashlib.sha256(manifest_bytes).hexdigest()[:20]
    staged_release_manifest(
        release,
        release_id,
        immutable_image,
        expected_source_tree_sha256=source_digest,
    )
    prefix = f"qualification/{ledger['execution_id']}/{release_id}"
    if ledger.get("release_id") != release_id:
        ledger["published_objects"] = {}
    ledger["release_id"] = release_id
    ledger["release_prefix"] = prefix
    ledger["release_manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    ledger["release_manifest_public_key_sha256"] = hashlib.sha256(
        (release / "manifest.pub").read_bytes()
    ).hexdigest()
    ledger["nested_template_base_url"] = (
        f"https://{ledger['artifact_bucket']}.s3.{ledger['region']}.amazonaws.com/"
        f"{prefix}/recipe/cloudformation"
    )
    published: dict[str, dict[str, Any]] = ledger.setdefault("published_objects", {})
    release_files = bounded_release_files(release)
    record(
        path,
        ledger,
        "release_bundle_upload_started",
        object_count=len(release_files),
        resumed=reuse_release,
    )
    for item, relative, size_bytes in release_files:
        key = f"{prefix}/{relative}"
        digest = hashlib.sha256(item.read_bytes()).hexdigest()
        previous = published.get(relative)
        if (
            previous
            and previous.get("key") == key
            and previous.get("sha256") == digest
            and previous.get("size_bytes") == size_bytes
        ):
            existing = aws_json(
                [
                    "s3api",
                    "head-object",
                    "--region",
                    ledger["region"],
                    "--bucket",
                    ledger["artifact_bucket"],
                    "--key",
                    key,
                    "--version-id",
                    previous["version_id"],
                ],
                env=env,
                check=False,
            )
            if (
                existing
                and existing.get("ContentLength") == size_bytes
                and existing.get("Metadata", {}).get("sha256") == digest
            ):
                continue
        require_qualification_deadline(path, ledger, "release object publication")
        result = aws_json(
            [
                "s3api",
                "put-object",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--key",
                key,
                "--body",
                os.fspath(item),
                "--server-side-encryption",
                "AES256",
                "--metadata",
                f"sha256={digest}",
                "--tagging",
                f"Project={PROJECT}&ManagedBy={MANAGED_BY}&BridgefuExecutionId={ledger['execution_id']}",
            ],
            env=env,
        )
        published[relative] = {
            "key": key,
            "version_id": result["VersionId"],
            "sha256": digest,
            "size_bytes": size_bytes,
        }
        persist_ledger(path, ledger)
    if working_tree_digest(root_dir()) != source_digest:
        raise LiveTestError("working tree changed while the release was publishing")
    validate_candidate_release(path, ledger, env)
    ledger["status"] = "published"
    record(path, ledger, "release_bundle_published", object_count=len(published))
    print(immutable_image)
    print(f"published {len(published)} immutable object versions")
    if ledger["dns_mode"] == "temporary_delegated_zone":
        print(f"delegate {ledger['public_hosted_zone_name']} to:")
        for server in ledger["delegation_name_servers"]:
            print(f"  {server}")


def resolve_ns(name: str) -> list[str]:
    result = command(["dig", "+short", "NS", name], check=False)
    if result.returncode != 0:
        raise LiveTestError("dig is required to verify public DNS delegation")
    return sorted(
        line.rstrip(".").lower() for line in result.stdout.splitlines() if line
    )


def dns_status(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if ledger.get("dns_mode") != "temporary_delegated_zone":
        print("existing Route 53 zone does not require parent delegation")
        return
    expected = sorted(
        server.rstrip(".").lower() for server in ledger["delegation_name_servers"]
    )
    observed = resolve_ns(ledger["public_hosted_zone_name"])
    verified = observed == expected
    ledger["delegation_verified"] = verified
    record(
        path,
        ledger,
        "dns_delegation_checked",
        verified=verified,
        observed_count=len(observed),
    )
    if not verified:
        raise LiveTestError("public parent DNS delegation is not active yet")
    print("public DNS delegation verified")


def parameter(key: str, value: Any) -> str:
    return f"ParameterKey={key},ParameterValue={value}"


def previous_parameter_arguments(
    stack: dict[str, Any], overrides: dict[str, str]
) -> list[str]:
    names = {
        item.get("ParameterKey")
        for item in stack.get("Parameters", [])
        if isinstance(item.get("ParameterKey"), str)
    }
    missing = sorted(set(overrides) - names)
    if missing:
        raise LiveTestError(f"stack is missing update parameters: {missing}")
    return [
        (
            parameter(name, overrides[name])
            if name in overrides
            else f"ParameterKey={name},UsePreviousValue=true"
        )
        for name in sorted(names)
    ]


def available_availability_zones(
    ledger: dict[str, Any], environment: dict[str, str]
) -> list[str]:
    response = aws_json(
        [
            "ec2",
            "describe-availability-zones",
            "--region",
            ledger["region"],
            "--filters",
            "Name=state,Values=available",
        ],
        env=environment,
    )
    zones = response.get("AvailabilityZones") if isinstance(response, dict) else None
    if not isinstance(zones, list):
        raise LiveTestError("availability-zone discovery returned an invalid result")
    names = sorted(
        item["ZoneName"]
        for item in zones
        if isinstance(item, dict)
        and isinstance(item.get("ZoneName"), str)
        and item.get("ZoneType", "availability-zone") == "availability-zone"
    )
    if not names or len(names) != len(set(names)):
        raise LiveTestError("availability-zone discovery is empty or ambiguous")
    return names


def service_quota_limit(
    ledger: dict[str, Any],
    environment: dict[str, str],
    service_code: str,
    quota_code: str,
) -> int:
    response = aws_json(
        [
            "service-quotas",
            "get-service-quota",
            "--region",
            ledger["region"],
            "--service-code",
            service_code,
            "--quota-code",
            quota_code,
        ],
        env=environment,
    )
    quota = response.get("Quota") if isinstance(response, dict) else None
    value = quota.get("Value") if isinstance(quota, dict) else None
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or value <= 0
        or int(value) != value
    ):
        raise LiveTestError(f"service quota {quota_code} is missing or non-integral")
    return int(value)


def capacity_requirements(ledger: dict[str, Any], phase: str) -> dict[str, Any]:
    if phase not in {"qualification", "application"}:
        raise LiveTestError("capacity phase is invalid")
    runtime_profile = ledger.get("runtime_profile", "starter")
    if runtime_profile not in {"starter", "high_availability"}:
        raise LiveTestError("capacity gate received an invalid runtime profile")
    zones = ledger.get("deployment_availability_zones")
    if not isinstance(zones, list) or not zones:
        raise LiveTestError("capacity gate has no bound availability zones")
    disposable = ledger.get("connect_mode") == "disposable"
    application = {
        "vpcs": 1,
        "internet_gateways": 1,
        "elastic_ips": 1 if runtime_profile == "starter" else 4,
        "connect_instances": 1 if disposable else 0,
        "nat_gateways_by_zone": (
            {} if runtime_profile == "starter" else {zone: 1 for zone in zones[:2]}
        ),
    }
    if phase == "application":
        return application
    qualification_zone = ledger.get("qualification_availability_zone")
    if not isinstance(qualification_zone, str) or qualification_zone not in zones:
        raise LiveTestError("qualification runner availability zone is not bound")
    # Before creating the runner, reserve enough capacity for both disposable
    # stacks. This prevents a half-deployed test environment that cannot create
    # the application stack after the runner has consumed the last VPC/IGW.
    result = dict(application)
    result["vpcs"] += 1
    result["internet_gateways"] += 1
    nat = dict(application["nat_gateways_by_zone"])
    nat[qualification_zone] = nat.get(qualification_zone, 0) + 1
    result["nat_gateways_by_zone"] = nat
    return result


def capacity_snapshot(
    ledger: dict[str, Any], environment: dict[str, str], phase: str
) -> dict[str, Any]:
    requirements = capacity_requirements(ledger, phase)
    region = ledger["region"]
    current_zones = available_availability_zones(ledger, environment)
    required_zones = set(requirements["nat_gateways_by_zone"])
    if not required_zones.issubset(current_zones):
        raise LiveTestError("a capacity-bound availability zone is no longer available")
    vpcs = aws_json(["ec2", "describe-vpcs", "--region", region], env=environment)
    gateways = aws_json(
        ["ec2", "describe-internet-gateways", "--region", region],
        env=environment,
    )
    addresses = aws_json(
        ["ec2", "describe-addresses", "--region", region], env=environment
    )
    connect = aws_json(
        ["connect", "list-instances", "--region", region], env=environment
    )
    subnets = aws_json(["ec2", "describe-subnets", "--region", region], env=environment)
    nat_gateways = aws_json(
        ["ec2", "describe-nat-gateways", "--region", region], env=environment
    )
    collections = {
        "vpcs": (vpcs, "Vpcs"),
        "internet_gateways": (gateways, "InternetGateways"),
        "elastic_ips": (addresses, "Addresses"),
        "connect_instances": (connect, "InstanceSummaryList"),
        "subnets": (subnets, "Subnets"),
        "nat_gateways": (nat_gateways, "NatGateways"),
    }
    for label, (document, key) in collections.items():
        if not isinstance(document, dict) or not isinstance(document.get(key), list):
            raise LiveTestError(
                f"{label} capacity inventory returned an invalid result"
            )
    vpc_limit = service_quota_limit(ledger, environment, "vpc", VPC_QUOTA_CODE)
    eip_limit = service_quota_limit(ledger, environment, "ec2", EIP_QUOTA_CODE)
    connect_limit = service_quota_limit(
        ledger, environment, "connect", CONNECT_INSTANCE_QUOTA_CODE
    )
    nat_limit = service_quota_limit(ledger, environment, "vpc", NAT_GATEWAY_QUOTA_CODE)
    zone_by_subnet = {
        item["SubnetId"]: item["AvailabilityZone"]
        for item in subnets["Subnets"]
        if isinstance(item, dict)
        and isinstance(item.get("SubnetId"), str)
        and isinstance(item.get("AvailabilityZone"), str)
    }
    nat_usage: dict[str, int] = {}
    for gateway in nat_gateways["NatGateways"]:
        if not isinstance(gateway, dict) or gateway.get("State") not in {
            "pending",
            "available",
            "deleting",
        }:
            continue
        zone = zone_by_subnet.get(gateway.get("SubnetId"))
        if not zone:
            raise LiveTestError(
                "active NAT gateway has no resolvable availability zone"
            )
        nat_usage[zone] = nat_usage.get(zone, 0) + 1

    checks: dict[str, dict[str, int]] = {}

    def add_check(name: str, used: int, required: int, limit: int) -> None:
        checks[name] = {
            "used": used,
            "required": required,
            "minimum_reserve": MIN_CAPACITY_RESERVE,
            "limit": limit,
            "remaining_after": limit - used - required,
            "minimum_limit": used + required + MIN_CAPACITY_RESERVE,
        }

    add_check("vpcs", len(vpcs["Vpcs"]), requirements["vpcs"], vpc_limit)
    # AWS ties the regional IGW quota directly to the VPC quota, but both
    # inventories must fit because unattached gateways also consume it.
    add_check(
        "internet_gateways",
        len(gateways["InternetGateways"]),
        requirements["internet_gateways"],
        vpc_limit,
    )
    add_check(
        "elastic_ips",
        len(addresses["Addresses"]),
        requirements["elastic_ips"],
        eip_limit,
    )
    add_check(
        "connect_instances",
        len(connect["InstanceSummaryList"]),
        requirements["connect_instances"],
        connect_limit,
    )
    for zone, required in sorted(requirements["nat_gateways_by_zone"].items()):
        add_check(f"nat_gateways:{zone}", nat_usage.get(zone, 0), required, nat_limit)
    blocked = sorted(
        name
        for name, check in checks.items()
        if check["remaining_after"] < check["minimum_reserve"]
    )
    return {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "release_id": ledger["release_id"],
        "region": region,
        "phase": phase,
        "checked_at": utc_now(),
        "requirements": requirements,
        "available_zones": current_zones,
        "checks": checks,
        "blocked": blocked,
        "passed": not blocked,
    }


def ensure_capacity_before_execute(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    phase: str,
) -> None:
    evidence = capacity_snapshot(ledger, environment, phase)
    evidence_path = path.parent / f"{phase}-capacity-pre-execute.json"
    atomic_json(evidence_path, evidence)
    ledger[f"{phase}_capacity_evidence_sha256"] = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    record(
        path,
        ledger,
        f"{phase}_capacity_checked",
        passed=evidence["passed"],
        blocked=evidence["blocked"],
    )
    if not evidence["passed"]:
        raise LiveTestError(
            "pre-execution capacity reserve is insufficient for: "
            + ", ".join(evidence["blocked"])
        )


def change_set_parameters_sha256(description: dict[str, Any]) -> str:
    parameters = description.get("Parameters")
    if not isinstance(parameters, list) or not parameters:
        raise LiveTestError("change set is missing its reviewed parameters")
    normalized: list[dict[str, str]] = []
    for item in parameters:
        if not isinstance(item, dict) or not isinstance(item.get("ParameterKey"), str):
            raise LiveTestError("change set returned an invalid parameter")
        normalized.append(
            {
                "ParameterKey": item["ParameterKey"],
                **(
                    {"ParameterValue": item["ParameterValue"]}
                    if isinstance(item.get("ParameterValue"), str)
                    else {}
                ),
                **(
                    {"UsePreviousValue": str(item["UsePreviousValue"])}
                    if "UsePreviousValue" in item
                    else {}
                ),
            }
        )
    keys = [item["ParameterKey"] for item in normalized]
    if len(set(keys)) != len(keys):
        raise LiveTestError("change set returned duplicate parameters")
    return canonical_json_sha256(
        sorted(normalized, key=lambda item: item["ParameterKey"])
    )


def signed_cloudformation_template_hashes(path: Path) -> dict[str, str]:
    release = path.parent / "release"
    manifest = json.loads((release / "manifest.json").read_text())
    result: dict[str, str] = {}
    for entry in manifest.get("artifacts", []):
        relative = entry.get("path") if isinstance(entry, dict) else None
        if (
            isinstance(relative, str)
            and relative.startswith("recipe/cloudformation/")
            and relative.endswith((".yaml", ".yml"))
        ):
            result[relative] = canonical_template_sha256(release / relative)
    if not result:
        raise LiveTestError("signed release has no CloudFormation template inventory")
    return result


DISPOSABLE_STARTER_TEMPLATE_PATHS = frozenset(
    {
        "recipe/cloudformation/demo-template.yaml",
        "recipe/cloudformation/template.yaml",
        "recipe/cloudformation/nested/demo-connect.yaml",
        "recipe/cloudformation/nested/network.yaml",
        "recipe/cloudformation/nested/handoff-service.yaml",
        "recipe/cloudformation/nested/connect.yaml",
        "recipe/cloudformation/nested/runtime-starter.yaml",
        "recipe/cloudformation/nested/vapi.yaml",
        "recipe/cloudformation/nested/observability.yaml",
    }
)
DISPOSABLE_STARTER_OPTIONAL_TEMPLATE_PATHS = frozenset(
    {"recipe/cloudformation/nested/demo-site.yaml"}
)
DISPOSABLE_STARTER_TEMPLATE_CONTAINERS = {
    "root": "recipe/cloudformation/demo-template.yaml",
    "root/DemoConnect": "recipe/cloudformation/nested/demo-connect.yaml",
    "root/RecipeApplication": "recipe/cloudformation/template.yaml",
    "root/RecipeApplication/Network": "recipe/cloudformation/nested/network.yaml",
    "root/RecipeApplication/HandoffService": (
        "recipe/cloudformation/nested/handoff-service.yaml"
    ),
    "root/RecipeApplication/ConnectIntegration": (
        "recipe/cloudformation/nested/connect.yaml"
    ),
    "root/RecipeApplication/StarterRuntime": (
        "recipe/cloudformation/nested/runtime-starter.yaml"
    ),
    "root/RecipeApplication/VapiResources": ("recipe/cloudformation/nested/vapi.yaml"),
    "root/RecipeApplication/StarterObservability": (
        "recipe/cloudformation/nested/observability.yaml"
    ),
}
DISPOSABLE_STARTER_OPTIONAL_TEMPLATE_CONTAINERS = {
    "root/RecipeApplication/DemoSite": ("recipe/cloudformation/nested/demo-site.yaml")
}
DISPOSABLE_FORBIDDEN_RESOURCE_TYPES = frozenset(
    {
        "AWS::AutoScaling::AutoScalingGroup",
        "AWS::AutoScaling::LifecycleHook",
        "AWS::CertificateManager::Certificate",
        "AWS::EC2::NatGateway",
        "AWS::ECS::Cluster",
        "AWS::ECS::Service",
        "AWS::ECS::TaskDefinition",
        "AWS::ElastiCache::ReplicationGroup",
        "AWS::ElastiCache::SubnetGroup",
        "AWS::ElastiCache::User",
        "AWS::ElastiCache::UserGroup",
        "AWS::ElasticLoadBalancingV2::Listener",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::ElasticLoadBalancingV2::TargetGroup",
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBParameterGroup",
        "AWS::RDS::DBSubnetGroup",
    }
)
DISPOSABLE_FORBIDDEN_LOGICAL_IDS = frozenset(
    {
        "CertificatePassphraseSecret",
        "PublicCertificate",
        "SecureSipIngress1",
        "SecureSipIngress2",
        "SecureSipIngress3",
        "SecureSipIngress4",
        "SipDnsRecord",
    }
)


def disposable_starter_template_hashes(
    ledger: dict[str, Any], signed_templates: dict[str, str]
) -> set[str]:
    return set(disposable_starter_template_contract(ledger, signed_templates).values())


def disposable_starter_template_contract(
    ledger: dict[str, Any], signed_templates: dict[str, str]
) -> dict[str, str]:
    expected_paths = set(DISPOSABLE_STARTER_TEMPLATE_PATHS)
    containers = dict(DISPOSABLE_STARTER_TEMPLATE_CONTAINERS)
    if ledger.get("enable_demo_site"):
        expected_paths.update(DISPOSABLE_STARTER_OPTIONAL_TEMPLATE_PATHS)
        containers.update(DISPOSABLE_STARTER_OPTIONAL_TEMPLATE_CONTAINERS)
    if set(containers.values()) != expected_paths:
        raise LiveTestError("disposable Starter template topology is inconsistent")
    missing = expected_paths - set(signed_templates)
    if missing:
        raise LiveTestError(
            "signed release is missing a disposable Starter template: "
            + ", ".join(sorted(missing))
        )
    return {
        container: signed_templates[relative]
        for container, relative in containers.items()
    }


def parameter_argument_values(arguments: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for argument in arguments:
        prefix = "ParameterKey="
        separator = ",ParameterValue="
        if not isinstance(argument, str) or not argument.startswith(prefix):
            raise LiveTestError("CloudFormation parameter argument is invalid")
        key, found, value = argument[len(prefix) :].partition(separator)
        if not found or not key or key in values:
            raise LiveTestError("CloudFormation parameter argument is ambiguous")
        values[key] = value
    return values


def expected_create_parameter_values(
    template: Path, arguments: list[str]
) -> dict[str, str]:
    document = cloudformation_document(template.read_text())
    declarations = document.get("Parameters")
    if not isinstance(declarations, dict) or not declarations:
        raise LiveTestError("CloudFormation root template has no parameter contract")
    supplied = parameter_argument_values(arguments)
    if not set(supplied).issubset(declarations):
        raise LiveTestError("controller supplied an unknown CloudFormation parameter")
    expected: dict[str, str] = {}
    for key, declaration in declarations.items():
        if key in supplied:
            expected[key] = supplied[key]
            continue
        default = declaration.get("Default") if isinstance(declaration, dict) else None
        if isinstance(default, bool):
            expected[key] = "true" if default else "false"
        elif isinstance(default, (str, int, float)) and not isinstance(default, bool):
            expected[key] = str(default)
        else:
            raise LiveTestError(
                f"controller omitted required CloudFormation parameter: {key}"
            )
    return expected


def described_create_parameter_values(description: dict[str, Any]) -> dict[str, str]:
    raw = description.get("Parameters")
    if not isinstance(raw, list) or not raw:
        raise LiveTestError("change set has no described root parameters")
    values: dict[str, str] = {}
    for item in raw:
        key = item.get("ParameterKey") if isinstance(item, dict) else None
        value = item.get("ParameterValue") if isinstance(item, dict) else None
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or key in values
            or item.get("UsePreviousValue") is True
        ):
            raise LiveTestError("change set root parameter is invalid")
        values[key] = value
    return values


def require_disposable_starter_review(
    ledger: dict[str, Any],
    description: dict[str, Any],
    changes: list[dict[str, Any]],
    template: Path,
    parameter_arguments: list[str],
    expected_template_contract: dict[str, str],
) -> None:
    if ledger.get("connect_mode") != "disposable":
        return
    expected_parameters = expected_create_parameter_values(
        template, parameter_arguments
    )
    observed_parameters = described_create_parameter_values(description)
    if observed_parameters != expected_parameters:
        raise LiveTestError(
            "disposable root parameters differ from the exact IP-only Starter request"
        )
    require_disposable_starter_change_contract(
        ledger, description, changes, expected_template_contract
    )


def require_disposable_starter_change_contract(
    ledger: dict[str, Any],
    description: dict[str, Any],
    changes: list[dict[str, Any]],
    expected_template_contract: dict[str, str],
) -> None:
    if ledger.get("connect_mode") != "disposable":
        return
    observed_parameters = described_create_parameter_values(description)
    if (
        observed_parameters.get("PublicHostedZoneId") != "none"
        or observed_parameters.get("SipSecurity") != "sip_rtp"
        or observed_parameters.get("SipHostname") != "unused.bridgefu.invalid"
        or observed_parameters.get("RootVolumeGiB") != "12"
        or observed_parameters.get("DataVolumeGiB") != "8"
    ):
        raise LiveTestError(
            "disposable root parameters are not the approved IP-only posture"
        )
    observed_template_contract: dict[str, str] = {}
    for item in changes:
        resource_path = str(item.get("path", ""))
        container_path, separator, logical_id = resource_path.rpartition("/")
        template_hash = item.get("container_template_sha256")
        if (
            not separator
            or not container_path
            or not logical_id
            or not isinstance(template_hash, str)
            or (
                container_path in observed_template_contract
                and observed_template_contract[container_path] != template_hash
            )
        ):
            raise LiveTestError("disposable change set template path is ambiguous")
        observed_template_contract[container_path] = template_hash
    if observed_template_contract != expected_template_contract:
        raise LiveTestError(
            "disposable change set does not use the exact Starter template topology"
        )
    for item in changes:
        path_parts = str(item.get("path", "")).split("/")
        if (
            item.get("resource_type") in DISPOSABLE_FORBIDDEN_RESOURCE_TYPES
            or path_parts[-1] in DISPOSABLE_FORBIDDEN_LOGICAL_IDS
            or any(
                part in {"HighAvailabilityRuntime", "HighAvailabilityObservability"}
                or part.lower().startswith("runtimeha")
                or part.lower().startswith("observabilityha")
                for part in path_parts
            )
        ):
            raise LiveTestError(
                "disposable change set contains HA, DNS, certificate, or multi-AZ resources"
            )


def review_change_set_tree(
    ledger: dict[str, Any],
    env: dict[str, str],
    root_change_set_id: str,
    *,
    expected_action: str,
    allowed_template_sha256: set[str] | None = None,
    expected_root_template_sha256: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if expected_action not in {"Add", "Modify"}:
        raise LiveTestError("invalid expected change-set action")
    pending = [
        (
            "root",
            require_change_set_id_authority(
                ledger, root_change_set_id, "root change set"
            ),
            0,
        )
    ]
    seen: set[str] = set()
    flattened: list[dict[str, Any]] = []
    root_description: dict[str, Any] | None = None
    while pending:
        path, change_set_id, depth = pending.pop()
        change_set_id = require_change_set_id_authority(
            ledger, change_set_id, "reviewed change set"
        )
        if depth > 8 or len(seen) >= 64:
            raise LiveTestError("nested change-set tree exceeds its safety bounds")
        if change_set_id in seen:
            raise LiveTestError("nested change-set tree contains a duplicate child")
        seen.add(change_set_id)
        description = aws_json(
            [
                "cloudformation",
                "describe-change-set",
                "--region",
                ledger["region"],
                "--change-set-name",
                change_set_id,
                "--include-property-values",
            ],
            env=env,
        )
        if (
            not isinstance(description, dict)
            or description.get("Status") != "CREATE_COMPLETE"
            or description.get("ChangeSetId") != change_set_id
        ):
            raise LiveTestError("nested change set is not ready for review")
        if root_description is None:
            root_description = description
        container_template_sha256: str | None = None
        if allowed_template_sha256 is not None:
            live_template = aws_json(
                [
                    "cloudformation",
                    "get-template",
                    "--region",
                    ledger["region"],
                    "--change-set-name",
                    change_set_id,
                    "--template-stage",
                    "Original",
                ],
                env=env,
            )
            if (
                not isinstance(live_template, dict)
                or "TemplateBody" not in live_template
            ):
                raise LiveTestError("change set did not return its live template")
            container_template_sha256 = canonical_template_sha256(
                live_template["TemplateBody"]
            )
            if container_template_sha256 not in allowed_template_sha256:
                raise LiveTestError(
                    "change set template is absent from the signed release"
                )
            if (
                path == "root"
                and expected_root_template_sha256 is not None
                and container_template_sha256 != expected_root_template_sha256
            ):
                raise LiveTestError(
                    "root change set template differs from the signed root template"
                )
        changes = description.get("Changes", [])
        if not isinstance(changes, list):
            raise LiveTestError("nested change set returned an invalid change list")
        for change in changes:
            resource = change.get("ResourceChange", {})
            logical_id = resource.get("LogicalResourceId")
            resource_type = resource.get("ResourceType")
            action = resource.get("Action")
            replacement = resource.get("Replacement")
            if not isinstance(logical_id, str) or not logical_id:
                raise LiveTestError(
                    "change set contains a resource without a logical ID"
                )
            entry = {
                "path": f"{path}/{logical_id}",
                "action": action,
                "resource_type": resource_type,
                "replacement": replacement,
                "resource_change_sha256": canonical_json_sha256(resource),
                **(
                    {"container_template_sha256": container_template_sha256}
                    if container_template_sha256 is not None
                    else {}
                ),
            }
            flattened.append(entry)
            if len(flattened) > 1_000:
                raise LiveTestError(
                    "nested change-set resource count exceeds its bound"
                )
            if resource_type not in ALLOWED_STACK_RESOURCE_TYPES:
                raise LiveTestError(
                    f"change set contains unapproved resource type: {resource_type}"
                )
            if action != expected_action:
                raise LiveTestError(
                    f"change set contains unexpected {action} action for {resource_type}"
                )
            if expected_action == "Modify" and replacement not in {None, "False"}:
                raise LiveTestError(
                    f"change set would replace {resource_type}: {replacement}"
                )
            if resource_type == "AWS::CloudFormation::Stack":
                child_id = require_change_set_id_authority(
                    ledger,
                    resource.get("ChangeSetId"),
                    "nested reviewed change set",
                )
                pending.append((entry["path"], child_id, depth + 1))
    if root_description is None or not flattened:
        raise LiveTestError("change-set tree unexpectedly contains no changes")
    return root_description, sorted(flattened, key=lambda item: item["path"])


def review_qualification_runner_change_set(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    objects: dict[str, Any],
) -> None:
    """Create and recursively review the independently owned runner stack."""
    manifest = json.loads(
        (
            path.parent / "release" / "artifacts" / "qualification" / "manifest.json"
        ).read_text()
    )
    qualification_object = objects["artifacts/qualification/qualification-source.zip"]
    params = [
        parameter("DeploymentId", ledger["execution_id"]),
        parameter("ArtifactBucket", ledger["artifact_bucket"]),
        parameter("QualificationArtifactKey", qualification_object["key"]),
        parameter("QualificationArtifactVersion", qualification_object["version_id"]),
        parameter("QualificationArtifactSha256", manifest["archive"]["sha256"]),
        parameter("RunnerRoleArn", ledger["qualification_runner_role_arn"]),
        parameter(
            "SourceEipAllocationId",
            ledger["qualification_source_eip_allocation_id"],
        ),
        parameter(
            "SourceEipPublicIp",
            ledger["qualification_source_cidr"].removesuffix("/32"),
        ),
        parameter(
            "RunnerAvailabilityZone",
            ledger["qualification_availability_zone"],
        ),
        parameter("LogRetentionDays", "1"),
    ]
    change_set_name = f"qualification-{ledger['execution_id']}"
    description_text = (
        f"Approved Bridgefu qualification runner {ledger['execution_id']}"
    )
    template = (
        path.parent
        / "release"
        / "recipe"
        / "cloudformation"
        / "nested"
        / "qualification-runner.yaml"
    )
    if ledger.get("qualification_change_set_arn"):
        if ledger.get("qualification_change_set_name") != change_set_name:
            raise LiveTestError(
                "recorded qualification change-set name violates the execution contract"
            )
        qualification_review_stack_id = require_stack_id_for_name(
            ledger,
            ledger.get("qualification_review_stack_id"),
            ledger["qualification_stack_name"],
            "qualification review",
        )
        qualification_change_set_id = require_change_set_id_authority(
            ledger,
            ledger.get("qualification_change_set_arn"),
            "qualification review",
            expected_name=change_set_name,
        )
        result = {
            "Id": qualification_change_set_id,
            "StackId": qualification_review_stack_id,
        }
        record(path, ledger, "recorded_qualification_change_set_reused_for_review")
    else:
        recovered = describe_change_set_if_exists(
            ledger,
            environment,
            ledger["qualification_stack_name"],
            change_set_name,
        )
        if recovered is not None:
            result = {
                "Id": recovered["ChangeSetId"],
                "StackId": recovered["StackId"],
            }
            event = "qualification_change_set_request_reconciled"
        else:
            require_qualification_deadline(path, ledger, "qualification runner review")
            result = aws_json(
                [
                    "cloudformation",
                    "create-change-set",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    ledger["qualification_stack_name"],
                    "--change-set-name",
                    change_set_name,
                    "--change-set-type",
                    "CREATE",
                    "--description",
                    description_text,
                    "--template-body",
                    template_body_argument(template),
                    "--parameters",
                    *params,
                    "--on-stack-failure",
                    "DO_NOTHING",
                    "--client-token",
                    f"qualification-review-{ledger['execution_id']}",
                    "--role-arn",
                    ledger["cloudformation_execution_role_arn"],
                    "--tags",
                    *tag_arguments(ledger["execution_id"]),
                ],
                env=environment,
            )
            event = "qualification_change_set_requested"
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("Id"), str)
            or not result["Id"].startswith("arn:")
        ):
            raise LiveTestError("qualification review returned no exact change-set ARN")
        qualification_review_stack_id = require_stack_id_for_name(
            ledger,
            result.get("StackId"),
            ledger["qualification_stack_name"],
            "qualification review",
        )
        require_change_set_id_authority(
            ledger,
            result.get("Id"),
            "qualification review",
            expected_name=change_set_name,
        )
        existing_review_stack_id = ledger.get("qualification_review_stack_id")
        if (
            existing_review_stack_id is not None
            and existing_review_stack_id != qualification_review_stack_id
        ):
            raise LiveTestError("qualification review stack identity changed")
        ledger["qualification_change_set_arn"] = result["Id"]
        ledger["qualification_change_set_name"] = change_set_name
        ledger["qualification_review_stack_id"] = qualification_review_stack_id
        record(path, ledger, event)
    if not isinstance(result.get("Id"), str) or not result["Id"].startswith("arn:"):
        raise LiveTestError("qualification review has no exact change-set ARN")
    require_change_set_id_authority(
        ledger,
        result["Id"],
        "qualification review",
        expected_name=change_set_name,
    )
    aws_wait(
        [
            "cloudformation",
            "wait",
            "change-set-create-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            qualification_review_stack_id,
            "--change-set-name",
            result["Id"],
        ],
        env=environment,
    )
    signed_templates = signed_cloudformation_template_hashes(path)
    root_template_sha256 = signed_templates[
        "recipe/cloudformation/nested/qualification-runner.yaml"
    ]
    description, changes = review_change_set_tree(
        ledger,
        environment,
        result["Id"],
        expected_action="Add",
        allowed_template_sha256=set(signed_templates.values()),
        expected_root_template_sha256=root_template_sha256,
    )
    review_stack = stack_description(ledger, environment, qualification_review_stack_id)
    if (
        description.get("ChangeSetId") != result["Id"]
        or description.get("StackId") != qualification_review_stack_id
        or description.get("StackName") != ledger["qualification_stack_name"]
        or review_stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
        or description.get("Description") != description_text
        or description.get("IncludeNestedStacks") not in {None, False}
        or description.get("OnStackFailure") != "DO_NOTHING"
        or review_stack.get("RoleARN") != ledger["cloudformation_execution_role_arn"]
        or description.get("ExecutionStatus") != "AVAILABLE"
        or description.get("ChangeSetName") != change_set_name
        or any(
            item["resource_type"] == "AWS::CloudFormation::Stack" for item in changes
        )
    ):
        raise LiveTestError(
            "recorded qualification runner change set violates the review contract"
        )
    evidence = {
        "change_set_id": description["ChangeSetId"],
        "change_set_name": change_set_name,
        "stack_id": qualification_review_stack_id,
        "status": description["Status"],
        "execution_status": description["ExecutionStatus"],
        "on_stack_failure": description["OnStackFailure"],
        "cloudformation_role_arn": review_stack["RoleARN"],
        "release_id": ledger["release_id"],
        "template_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
        "parameters_sha256": change_set_parameters_sha256(description),
        "changes": changes,
        "reviewed_at": utc_now(),
    }
    evidence_path = path.parent / "qualification-change-set-review.json"
    atomic_json(evidence_path, evidence)
    ledger["qualification_review_stack_id"] = qualification_review_stack_id
    ledger["qualification_change_set_review_sha256"] = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    record(
        path,
        ledger,
        "qualification_change_set_reviewed",
        change_count=len(changes),
    )


def create_change_set(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if ledger["status"] != "published":
        raise LiveTestError("change-set requires a published release")
    if not ledger.get("bootstrap_refresh_complete") or ledger.get(
        "bootstrap_refresh_release_id"
    ) != ledger.get("release_id"):
        raise LiveTestError("change-set requires a completed bootstrap refresh")
    if ledger.get("bootstrap_policy_validation_error_count") != 0:
        raise LiveTestError(
            "change-set requires an error-free IAM Access Analyzer result"
        )
    validation_path = path.parent / "bootstrap-policy-validation.json"
    if not validation_path.is_file():
        raise LiveTestError("change-set requires bootstrap policy evidence")
    if ledger.get("dns_mode") == "temporary_delegated_zone" and not ledger.get(
        "delegation_verified"
    ):
        raise LiveTestError(
            "verify the delegated DNS zone before creating the change set"
        )
    if not ledger.get("qualification_source_cidr"):
        raise LiveTestError(
            "bind the controlled qualification source /32 before creating the change set"
        )
    require_qualification_deadline(path, ledger, "deployment review")
    env = assume_env(ledger, "deployment")
    validate_candidate_release(path, ledger, env)
    discovered_zones = available_availability_zones(ledger, env)
    recorded_zones = ledger.get("deployment_availability_zones")
    if recorded_zones is not None and recorded_zones != discovered_zones:
        raise LiveTestError(
            "availability-zone inventory changed after it was bound; refresh the review"
        )
    ledger["deployment_availability_zones"] = discovered_zones
    ledger["qualification_availability_zone"] = discovered_zones[0]
    record(
        path,
        ledger,
        "deployment_availability_zones_bound",
        qualification_zone=discovered_zones[0],
    )
    ensure_vapi_verification_secrets(path, ledger, env)
    runtime_profile = ledger.get("runtime_profile", "starter")
    cloudformation_profile = (
        "HighAvailability" if runtime_profile == "high_availability" else "Starter"
    )
    if runtime_profile == "high_availability" and not ledger.get(
        "private_tls_secret_arn"
    ):
        helper = root_dir() / "scripts" / "create-recipe-ha-private-tls.py"
        result = command(
            [
                sys.executable,
                os.fspath(helper),
                "--deployment-id",
                ledger["execution_id"],
                "--worker-hostname",
                f"worker.{ledger['sip_hostname']}",
                "--region",
                ledger["region"],
            ],
            env=env,
        )
        arn = (result.stdout or "").strip()
        expected_prefix = (
            f"arn:aws:secretsmanager:{ledger['region']}:"
            f"{ledger['account_id']}:secret:bridgefu-{ledger['execution_id']}-"
        )
        if not arn.startswith(expected_prefix):
            raise LiveTestError(
                "HA private TLS helper returned an unexpected secret ARN"
            )
        ledger["private_tls_secret_arn"] = arn
        record(path, ledger, "ha_private_tls_secret_created")
    objects = ledger["published_objects"]
    runtime_manifest = json.loads(
        (
            path.parent / "release" / "artifacts" / "runtime" / "manifest.json"
        ).read_text()
    )
    site_manifest = json.loads(
        (
            path.parent / "release" / "artifacts" / "demo-site" / "manifest.json"
        ).read_text()
    )
    params = [
        parameter("DeploymentId", ledger["execution_id"]),
        parameter("RuntimeProfile", cloudformation_profile),
        parameter("NestedTemplateBaseUrl", ledger["nested_template_base_url"]),
        parameter("ArtifactBucket", ledger["artifact_bucket"]),
        parameter(
            "PrepareArtifactKey", objects["artifacts/lambda/prepare_handoff.zip"]["key"]
        ),
        parameter(
            "PrepareArtifactVersion",
            objects["artifacts/lambda/prepare_handoff.zip"]["version_id"],
        ),
        parameter(
            "TransferArtifactKey",
            objects["artifacts/lambda/transfer_destination.zip"]["key"],
        ),
        parameter(
            "TransferArtifactVersion",
            objects["artifacts/lambda/transfer_destination.zip"]["version_id"],
        ),
        parameter(
            "LookupArtifactKey", objects["artifacts/lambda/connect_lookup.zip"]["key"]
        ),
        parameter(
            "LookupArtifactVersion",
            objects["artifacts/lambda/connect_lookup.zip"]["version_id"],
        ),
        parameter(
            "ProvisionerArtifactKey",
            objects["artifacts/lambda/vapi_provisioner.zip"]["key"],
        ),
        parameter(
            "ProvisionerArtifactVersion",
            objects["artifacts/lambda/vapi_provisioner.zip"]["version_id"],
        ),
        parameter(
            "RuntimeArtifactKey",
            objects["artifacts/runtime/starter-runtime.zip"]["key"],
        ),
        parameter(
            "RuntimeArtifactVersion",
            objects["artifacts/runtime/starter-runtime.zip"]["version_id"],
        ),
        parameter("RuntimeArtifactSha256", runtime_manifest["artifact"]["sha256"]),
        parameter("BridgefuImageUri", ledger["bridgefu_image_uri"]),
        parameter("BridgefuRegistryType", "PrivateEcr"),
        parameter("BridgefuImageRepositoryArn", ledger["ecr_repository_arn"]),
        parameter("ConnectInstanceArn", ledger["connect_instance_arn"]),
        parameter("TargetContactFlowArn", ledger["target_flow_arn"]),
        parameter("VapiApiKeySecretArn", ledger["vapi_api_key_secret_arn"]),
        parameter("PublicHostedZoneId", ledger["public_hosted_zone_id"]),
        parameter("SipHostname", ledger["sip_hostname"]),
        parameter("SipSecurity", ledger.get("sip_security", "sips_srtp")),
        parameter("VapiSignalingCidr3", ledger["qualification_source_cidr"]),
        parameter("NetworkMode", "NewVpc"),
        parameter("MaxConcurrentCalls", "10"),
        parameter("RootVolumeGiB", "12"),
        parameter("DataVolumeGiB", "8"),
        parameter("ContextTtlSeconds", "900"),
        parameter("DataRetentionMode", "TestDelete"),
        parameter("LogRetentionDays", "1"),
        parameter("RetainVapiResourcesOnDelete", "false"),
    ]
    if runtime_profile == "starter":
        params.append(parameter("InstanceType", "t4g.medium"))
    else:
        params.extend(
            [
                parameter("PrivateTlsSecretArn", ledger["private_tls_secret_arn"]),
                parameter("GatewayInstanceType", "c7g.large"),
                parameter("WorkerInstanceType", "c7g.large"),
                parameter("MaxConcurrentCallsPerWorker", "10"),
                parameter("DatabaseInstanceClass", "db.t4g.medium"),
                parameter("DatabaseAllocatedStorageGiB", "20"),
                parameter("DatabaseMaxStorageGiB", "100"),
                parameter("RedisNodeType", "cache.t4g.small"),
            ]
        )
    if ledger.get("enable_demo_site"):
        public_key = bound_vapi_public_key(ledger)
        site_object = objects["artifacts/demo-site/demo-site.zip"]
        params.extend(
            [
                parameter("EnableDemoSite", "true"),
                parameter("SiteArtifactKey", site_object["key"]),
                parameter("SiteArtifactVersion", site_object["version_id"]),
                parameter("SiteArtifactSha256", site_manifest["archive_sha256"]),
                parameter("VapiPublicKey", public_key),
            ]
        )
    if ledger.get("connect_mode") == "disposable":
        public_key = bound_vapi_public_key(ledger)
        review_qualification_runner_change_set(path, ledger, env, objects)
        params = [
            parameter("DemoAcknowledgement", "CREATE_NONPRODUCTION_CONNECT"),
            parameter("DeploymentId", ledger["execution_id"]),
            parameter("NestedTemplateBaseUrl", ledger["nested_template_base_url"]),
            parameter("ArtifactBucket", ledger["artifact_bucket"]),
            parameter(
                "PrepareArtifactKey",
                objects["artifacts/lambda/prepare_handoff.zip"]["key"],
            ),
            parameter(
                "PrepareArtifactVersion",
                objects["artifacts/lambda/prepare_handoff.zip"]["version_id"],
            ),
            parameter(
                "TransferArtifactKey",
                objects["artifacts/lambda/transfer_destination.zip"]["key"],
            ),
            parameter(
                "TransferArtifactVersion",
                objects["artifacts/lambda/transfer_destination.zip"]["version_id"],
            ),
            parameter(
                "LookupArtifactKey",
                objects["artifacts/lambda/connect_lookup.zip"]["key"],
            ),
            parameter(
                "LookupArtifactVersion",
                objects["artifacts/lambda/connect_lookup.zip"]["version_id"],
            ),
            parameter(
                "ProvisionerArtifactKey",
                objects["artifacts/lambda/vapi_provisioner.zip"]["key"],
            ),
            parameter(
                "ProvisionerArtifactVersion",
                objects["artifacts/lambda/vapi_provisioner.zip"]["version_id"],
            ),
            parameter(
                "RuntimeArtifactKey",
                objects["artifacts/runtime/starter-runtime.zip"]["key"],
            ),
            parameter(
                "RuntimeArtifactVersion",
                objects["artifacts/runtime/starter-runtime.zip"]["version_id"],
            ),
            parameter("RuntimeArtifactSha256", runtime_manifest["artifact"]["sha256"]),
            parameter("BridgefuImageUri", ledger["bridgefu_image_uri"]),
            parameter("BridgefuRegistryType", "PrivateEcr"),
            parameter("BridgefuImageRepositoryArn", ledger["ecr_repository_arn"]),
            parameter("VapiApiKeySecretArn", ledger["vapi_api_key_secret_arn"]),
            parameter("VapiPublicKey", public_key),
            parameter("PublicHostedZoneId", ledger["public_hosted_zone_id"]),
            parameter("SipHostname", ledger["sip_hostname"]),
            parameter("SipSecurity", ledger.get("sip_security", "sip_rtp")),
            parameter("VapiSignalingCidr3", ledger["qualification_source_cidr"]),
            parameter("InstanceType", "t4g.medium"),
            parameter("MaxConcurrentCalls", "10"),
            parameter("RootVolumeGiB", "12"),
            parameter("DataVolumeGiB", "8"),
            parameter("ContextTtlSeconds", "900"),
            parameter("LogRetentionDays", "1"),
        ]
        if ledger.get("enable_demo_site"):
            site_object = objects["artifacts/demo-site/demo-site.zip"]
            params.extend(
                [
                    parameter("EnableDemoSite", "true"),
                    parameter("SiteArtifactKey", site_object["key"]),
                    parameter("SiteArtifactVersion", site_object["version_id"]),
                    parameter("SiteArtifactSha256", site_manifest["archive_sha256"]),
                ]
            )
    change_set_name = f"reviewed-{ledger['execution_id']}"
    template_name = (
        "demo-template.yaml"
        if ledger.get("connect_mode") == "disposable"
        else "template.yaml"
    )
    template = path.parent / "release" / "recipe" / "cloudformation" / template_name
    if ledger.get("change_set_arn"):
        if ledger.get("change_set_name") != change_set_name:
            raise LiveTestError(
                "recorded change-set name violates the execution contract"
            )
        review_stack_id = require_stack_id_for_name(
            ledger,
            ledger.get("review_stack_id"),
            ledger["stack_name"],
            "application review",
        )
        application_change_set_id = require_change_set_id_authority(
            ledger,
            ledger.get("change_set_arn"),
            "application review",
            expected_name=change_set_name,
        )
        result = {"Id": application_change_set_id, "StackId": review_stack_id}
        record(path, ledger, "recorded_change_set_reused_for_review")
    else:
        recovered = describe_change_set_if_exists(
            ledger, env, ledger["stack_name"], change_set_name
        )
        if recovered is not None:
            result = {
                "Id": recovered["ChangeSetId"],
                "StackId": recovered["StackId"],
            }
            event = "change_set_request_reconciled"
        else:
            require_qualification_deadline(path, ledger, "application review")
            result = aws_json(
                [
                    "cloudformation",
                    "create-change-set",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    ledger["stack_name"],
                    "--change-set-name",
                    change_set_name,
                    "--change-set-type",
                    "CREATE",
                    "--description",
                    f"Approved Bridgefu qualification {ledger['execution_id']}",
                    "--template-body",
                    template_body_argument(template),
                    "--parameters",
                    *params,
                    "--capabilities",
                    "CAPABILITY_NAMED_IAM",
                    "CAPABILITY_AUTO_EXPAND",
                    "--include-nested-stacks",
                    "--on-stack-failure",
                    "DO_NOTHING",
                    "--client-token",
                    f"application-review-{ledger['execution_id']}",
                    "--role-arn",
                    ledger["cloudformation_execution_role_arn"],
                    "--tags",
                    *tag_arguments(ledger["execution_id"]),
                ],
                env=env,
            )
            event = "change_set_requested"
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("Id"), str)
            or not result["Id"].startswith("arn:")
        ):
            raise LiveTestError("application review returned no exact change-set ARN")
        review_stack_id = require_stack_id_for_name(
            ledger,
            result.get("StackId"),
            ledger["stack_name"],
            "application review",
        )
        require_change_set_id_authority(
            ledger,
            result.get("Id"),
            "application review",
            expected_name=change_set_name,
        )
        existing_review_stack_id = ledger.get("review_stack_id")
        if (
            existing_review_stack_id is not None
            and existing_review_stack_id != review_stack_id
        ):
            raise LiveTestError("application review stack identity changed")
        ledger["change_set_arn"] = result["Id"]
        ledger["change_set_name"] = change_set_name
        ledger["review_stack_id"] = review_stack_id
        record(path, ledger, event)
    if not isinstance(result.get("Id"), str) or not result["Id"].startswith("arn:"):
        raise LiveTestError("application review has no exact change-set ARN")
    require_change_set_id_authority(
        ledger,
        result["Id"],
        "application review",
        expected_name=change_set_name,
    )
    aws_wait(
        [
            "cloudformation",
            "wait",
            "change-set-create-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            review_stack_id,
            "--change-set-name",
            result["Id"],
        ],
        env=env,
    )
    signed_templates = signed_cloudformation_template_hashes(path)
    root_template_sha256 = signed_templates[f"recipe/cloudformation/{template_name}"]
    disposable_template_contract = (
        disposable_starter_template_contract(ledger, signed_templates)
        if ledger.get("connect_mode") == "disposable"
        else None
    )
    allowed_application_template_hashes = (
        set(disposable_template_contract.values())
        if disposable_template_contract is not None
        else set(signed_templates.values())
    )
    description, changes = review_change_set_tree(
        ledger,
        env,
        result["Id"],
        expected_action="Add",
        allowed_template_sha256=allowed_application_template_hashes,
        expected_root_template_sha256=root_template_sha256,
    )
    require_disposable_starter_review(
        ledger,
        description,
        changes,
        template,
        params,
        disposable_template_contract or {},
    )
    # DescribeChangeSet omits the request-only ChangeSetType field. The create
    # request above fixes it to CREATE; bind the response to its exact review
    # placeholder stack, description, name, ID, and nested-stack posture.
    review_stack = stack_description(ledger, env, review_stack_id)
    if (
        description.get("ChangeSetId") != result["Id"]
        or description.get("StackId") != review_stack_id
        or description.get("StackName") != ledger["stack_name"]
        or review_stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
        or description.get("Description")
        != f"Approved Bridgefu qualification {ledger['execution_id']}"
        or description.get("IncludeNestedStacks") is not True
        or description.get("OnStackFailure") != "DO_NOTHING"
        or review_stack.get("RoleARN") != ledger["cloudformation_execution_role_arn"]
        or description.get("ExecutionStatus") != "AVAILABLE"
        or description.get("ChangeSetName") != change_set_name
    ):
        raise LiveTestError("recorded root change set violates the review contract")
    evidence = {
        "change_set_id": description["ChangeSetId"],
        "change_set_name": change_set_name,
        "stack_id": review_stack_id,
        "status": description["Status"],
        "execution_status": description["ExecutionStatus"],
        "on_stack_failure": description["OnStackFailure"],
        "cloudformation_role_arn": review_stack["RoleARN"],
        "release_id": ledger["release_id"],
        "template_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
        "parameters_sha256": change_set_parameters_sha256(description),
        "nested_change_set_count": sum(
            entry["resource_type"] == "AWS::CloudFormation::Stack" for entry in changes
        ),
        "changes": changes,
        "reviewed_at": utc_now(),
    }
    evidence_path = path.parent / "change-set-review.json"
    atomic_json(evidence_path, evidence)
    ledger["review_stack_id"] = review_stack_id
    ledger["change_set_review_sha256"] = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    ledger["status"] = "change_set_reviewed"
    record(path, ledger, "change_set_reviewed", change_count=len(changes))
    mirror_recovery_snapshot(path, ledger, env)
    print(path.parent / "change-set-review.json")


def bind_qualification_source(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if args.confirm != args.execution_id:
        raise LiveTestError(
            "binding a qualification source requires the exact execution ID"
        )
    if ledger.get("status") != "published" or ledger.get("change_set_arn"):
        raise LiveTestError(
            "qualification source binding is allowed only before change-set review"
        )
    try:
        network = ipaddress.ip_network(args.cidr, strict=True)
    except ValueError as error:
        raise LiveTestError(
            "qualification source must be one exact IPv4 /32"
        ) from error
    if (
        network.version != 4
        or network.prefixlen != 32
        or not network.network_address.is_global
    ):
        raise LiveTestError("qualification source must be one public IPv4 /32")
    value = str(network)
    existing = ledger.get("qualification_source_cidr")
    if existing is not None and existing != value:
        raise LiveTestError(
            "qualification source is already bound; refresh requires a new execution"
        )
    ledger["qualification_source_cidr"] = value
    record(path, ledger, "qualification_source_bound")
    print(value)


def write_stack_failure_events(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    stack_name: str,
    filename: str,
) -> None:
    pending = [(stack_name, "root", 0)]
    seen: set[str] = set()
    redacted: list[dict[str, Any]] = []
    unavailable: list[str] = []
    while pending:
        target, stack_path, depth = pending.pop()
        if target in seen:
            continue
        if depth > 8 or len(seen) >= 64:
            unavailable.append(f"{stack_path}:safety-bound")
            continue
        seen.add(target)
        response = aws_json(
            [
                "cloudformation",
                "describe-stack-events",
                "--region",
                ledger["region"],
                "--stack-name",
                target,
            ],
            env=environment,
            check=False,
        )
        events = response.get("StackEvents") if isinstance(response, dict) else None
        if not isinstance(events, list):
            unavailable.append(stack_path)
            continue
        for event in events[:100]:
            if not isinstance(event, dict):
                continue
            logical_id = event.get("LogicalResourceId")
            redacted.append(
                {
                    "stack_path": stack_path,
                    **{
                        key: event.get(key)
                        for key in (
                            "Timestamp",
                            "LogicalResourceId",
                            "ResourceType",
                            "ResourceStatus",
                            "ResourceStatusReason",
                        )
                    },
                }
            )
            child_id = event.get("PhysicalResourceId")
            if (
                event.get("ResourceType") == "AWS::CloudFormation::Stack"
                and isinstance(logical_id, str)
                and isinstance(child_id, str)
                and child_id.startswith("arn:")
                and ":cloudformation:" in child_id
                and ":stack/" in child_id
            ):
                pending.append((child_id, f"{stack_path}/{logical_id}", depth + 1))
    atomic_json(
        path.parent / filename,
        {
            "schema_version": 1,
            "execution_id": ledger["execution_id"],
            "captured_at": utc_now(),
            "stack_count": len(seen),
            "events": redacted,
            "unavailable_stack_paths": sorted(set(unavailable)),
        },
    )


def validate_reviewed_create_for_execution(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    *,
    qualification: bool,
) -> str:
    prefix = "qualification_" if qualification else ""
    change_set_arn = ledger.get(f"{prefix}change_set_arn")
    change_set_name = ledger.get(f"{prefix}change_set_name")
    stack_name = ledger["qualification_stack_name" if qualification else "stack_name"]
    expected_stack_id = reviewed_create_stack_id(ledger, qualification=qualification)
    evidence_path = path.parent / (
        "qualification-change-set-review.json"
        if qualification
        else "change-set-review.json"
    )
    expected_evidence_sha256 = ledger.get(f"{prefix}change_set_review_sha256")
    if (
        not isinstance(change_set_arn, str)
        or not change_set_arn.startswith("arn:")
        or not isinstance(change_set_name, str)
        or not evidence_path.is_file()
        or hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        != expected_evidence_sha256
    ):
        raise LiveTestError("reviewed create evidence is missing or changed")
    change_set_arn = require_change_set_id_authority(
        ledger,
        change_set_arn,
        "reviewed create",
        expected_name=change_set_name,
    )
    try:
        evidence = json.loads(evidence_path.read_text())
    except json.JSONDecodeError as error:
        raise LiveTestError("reviewed create evidence is invalid JSON") from error
    template_name = (
        "nested/qualification-runner.yaml"
        if qualification
        else (
            "demo-template.yaml"
            if ledger.get("connect_mode") == "disposable"
            else "template.yaml"
        )
    )
    template = path.parent / "release" / "recipe" / "cloudformation" / template_name
    template_sha256 = hashlib.sha256(template.read_bytes()).hexdigest()
    signed_templates = signed_cloudformation_template_hashes(path)
    root_template_sha256 = signed_templates[f"recipe/cloudformation/{template_name}"]
    disposable_template_contract = (
        disposable_starter_template_contract(ledger, signed_templates)
        if not qualification and ledger.get("connect_mode") == "disposable"
        else None
    )
    allowed_execution_template_hashes = (
        set(disposable_template_contract.values())
        if disposable_template_contract is not None
        else set(signed_templates.values())
    )
    description, changes = review_change_set_tree(
        ledger,
        environment,
        change_set_arn,
        expected_action="Add",
        allowed_template_sha256=allowed_execution_template_hashes,
        expected_root_template_sha256=root_template_sha256,
    )
    if not qualification:
        require_disposable_starter_change_contract(
            ledger,
            description,
            changes,
            disposable_template_contract or {},
    )
    stack = stack_description(ledger, environment, expected_stack_id)
    # CREATE review shells do not expose stack tags until execution. The
    # reviewed change set is the authoritative pre-execution tag contract;
    # deployed-stack verification checks the resulting stack tags later.
    require_ownership_tags(description.get("Tags", []), ledger["execution_id"])
    expected_description = (
        f"Approved Bridgefu qualification runner {ledger['execution_id']}"
        if qualification
        else f"Approved Bridgefu qualification {ledger['execution_id']}"
    )
    expected_nested = None if qualification else True
    if (
        evidence.get("change_set_id") != change_set_arn
        or evidence.get("change_set_name") != change_set_name
        or evidence.get("stack_id") != expected_stack_id
        or evidence.get("status") != "CREATE_COMPLETE"
        or evidence.get("execution_status") != "AVAILABLE"
        or evidence.get("on_stack_failure") != "DO_NOTHING"
        or evidence.get("cloudformation_role_arn")
        != ledger.get("cloudformation_execution_role_arn")
        or evidence.get("release_id") != ledger.get("release_id")
        or evidence.get("template_sha256") != template_sha256
        or evidence.get("parameters_sha256")
        != change_set_parameters_sha256(description)
        or evidence.get("changes") != changes
        or description.get("ChangeSetId") != change_set_arn
        or description.get("ChangeSetName") != change_set_name
        or description.get("StackId") != expected_stack_id
        or description.get("StackName") != stack_name
        or description.get("Description") != expected_description
        or description.get("OnStackFailure") != "DO_NOTHING"
        or description.get("ExecutionStatus")
        not in {"AVAILABLE", "EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE"}
        or stack.get("RoleARN") != ledger.get("cloudformation_execution_role_arn")
        or (
            qualification
            and description.get("IncludeNestedStacks") not in {None, False}
        )
        or (
            not qualification
            and description.get("IncludeNestedStacks") is not expected_nested
        )
    ):
        raise LiveTestError(
            "live create change set no longer matches its exact review evidence"
        )
    return str(description["ExecutionStatus"])


def execute(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    allowed_statuses = {
        "change_set_reviewed",
        "qualification_runner_deploying",
        "qualification_runner_wait_interrupted",
        "qualification_runner_deployment_failed",
        "qualification_runner_deployed",
        "deploying",
        "deployment_wait_interrupted",
        "deployment_failed",
    }
    if ledger["status"] not in allowed_statuses:
        raise LiveTestError("execute requires a reviewed or resumable change set")
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    require_qualification_deadline(path, ledger, "stack execution")
    env = assume_env(ledger, "deployment")
    validate_candidate_release(path, ledger, env)
    application_stack_id = reviewed_create_stack_id(ledger, qualification=False)

    if ledger.get("connect_mode") == "disposable" and ledger["status"] in {
        "change_set_reviewed",
        "qualification_runner_deploying",
        "qualification_runner_wait_interrupted",
        "qualification_runner_deployment_failed",
    }:
        qualification_stack_id = reviewed_create_stack_id(ledger, qualification=True)
        qualification_execution = validate_reviewed_create_for_execution(
            path, ledger, env, qualification=True
        )
        if qualification_execution == "AVAILABLE":
            ensure_capacity_before_execute(path, ledger, env, phase="qualification")
            require_qualification_deadline(
                path, ledger, "qualification stack execution"
            )
            ledger["status"] = "qualification_runner_deploying"
            record(path, ledger, "qualification_change_set_execution_requested")
            mirror_recovery_snapshot(path, ledger, env)
            aws_json(
                [
                    "cloudformation",
                    "execute-change-set",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    qualification_stack_id,
                    "--change-set-name",
                    ledger["qualification_change_set_arn"],
                    "--client-request-token",
                    f"qualification-execute-{ledger['execution_id']}",
                ],
                env=env,
            )
            record(path, ledger, "qualification_change_set_executed")
        elif ledger["status"] != "qualification_runner_deploying":
            ledger["status"] = "qualification_runner_deploying"
            record(path, ledger, "qualification_change_set_execution_reconciled")
        try:
            aws_wait(
                [
                    "cloudformation",
                    "wait",
                    "stack-create-complete",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    qualification_stack_id,
                ],
                env=env,
            )
        except LiveTestError as wait_error:
            try:
                env = assume_env(ledger, "deployment")
                runner_stack = stack_description(ledger, env, qualification_stack_id)
            except LiveTestError:
                ledger["status"] = "qualification_runner_wait_interrupted"
                record(path, ledger, "qualification_runner_wait_interrupted")
                raise wait_error
            write_stack_failure_events(
                path,
                ledger,
                env,
                qualification_stack_id,
                "qualification-runner-failure-events.json",
            )
            if runner_stack.get("StackStatus") != "CREATE_COMPLETE":
                in_progress = str(runner_stack.get("StackStatus", "")).endswith(
                    "_IN_PROGRESS"
                )
                ledger["status"] = (
                    "qualification_runner_wait_interrupted"
                    if in_progress
                    else "qualification_runner_deployment_failed"
                )
                record(path, ledger, ledger["status"])
                raise wait_error
            record(path, ledger, "qualification_runner_wait_completion_reconciled")
        runner_stack = stack_description(ledger, env, qualification_stack_id)
        runner_values = outputs(runner_stack)
        required_runner_outputs = {
            "ProjectName",
            "RunnerSourceCidr",
            "RunnerLogGroupName",
        }
        if (
            runner_stack.get("StackStatus") != "CREATE_COMPLETE"
            or not required_runner_outputs.issubset(runner_values)
            or runner_values["RunnerSourceCidr"] != ledger["qualification_source_cidr"]
        ):
            raise LiveTestError(
                "independent qualification runner violates its deployment contract"
            )
        ledger["qualification_stack_id"] = qualification_stack_id
        ledger["qualification_project_name"] = runner_values["ProjectName"]
        ledger["qualification_runner_log_group_name"] = runner_values[
            "RunnerLogGroupName"
        ]
        ledger["status"] = "qualification_runner_deployed"
        record(path, ledger, "qualification_runner_ready")
        mirror_recovery_snapshot(path, ledger, env)

    if ledger["status"] in {
        "change_set_reviewed",
        "qualification_runner_deployed",
        "deploying",
        "deployment_wait_interrupted",
        "deployment_failed",
    }:
        application_execution = validate_reviewed_create_for_execution(
            path, ledger, env, qualification=False
        )
        if application_execution == "AVAILABLE":
            ensure_capacity_before_execute(path, ledger, env, phase="application")
            require_qualification_deadline(path, ledger, "application stack execution")
            ledger["status"] = "deploying"
            record(path, ledger, "change_set_execution_requested")
            mirror_recovery_snapshot(path, ledger, env)
            aws_json(
                [
                    "cloudformation",
                    "execute-change-set",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    application_stack_id,
                    "--change-set-name",
                    ledger["change_set_arn"],
                    "--client-request-token",
                    f"application-execute-{ledger['execution_id']}",
                ],
                env=env,
            )
            record(path, ledger, "change_set_executed")
        elif ledger["status"] != "deploying":
            ledger["status"] = "deploying"
            record(path, ledger, "change_set_execution_reconciled")
    try:
        aws_wait(
            [
                "cloudformation",
                "wait",
                "stack-create-complete",
                "--region",
                ledger["region"],
                "--stack-name",
                application_stack_id,
            ],
            env=env,
        )
    except LiveTestError as wait_error:
        try:
            env = assume_env(ledger, "deployment")
            root_stack = stack_description(ledger, env, application_stack_id)
        except LiveTestError:
            ledger["status"] = "deployment_wait_interrupted"
            record(path, ledger, "deployment_wait_interrupted")
            raise wait_error
        write_stack_failure_events(
            path,
            ledger,
            env,
            application_stack_id,
            "failure-events.json",
        )
        if root_stack.get("StackStatus") != "CREATE_COMPLETE":
            in_progress = str(root_stack.get("StackStatus", "")).endswith(
                "_IN_PROGRESS"
            )
            ledger["status"] = (
                "deployment_wait_interrupted" if in_progress else "deployment_failed"
            )
            record(path, ledger, ledger["status"])
            raise wait_error
        record(path, ledger, "deployment_wait_completion_reconciled")
    if ledger.get("connect_mode") == "disposable":
        root_stack = stack_description(ledger, env, application_stack_id)
        root_values = outputs(root_stack)
        required_outputs = {
            "ConnectInstanceArn",
            "ConnectLoginUrl",
            "AgentCredentialSecretArn",
        }
        if not required_outputs.issubset(root_values):
            raise LiveTestError("disposable demo outputs are incomplete")
        ledger["connect_instance_arn"] = root_values["ConnectInstanceArn"]
        ledger["connect_login_url"] = root_values["ConnectLoginUrl"]
        ledger["agent_credential_secret_arn"] = root_values["AgentCredentialSecretArn"]
        application_nested_stack_id = nested_stack_id(
            ledger, env, "RecipeApplication", application_stack_id
        )
        exact_nested_stack_description(
            ledger,
            env,
            application_nested_stack_id,
            parent_stack_id=application_stack_id,
            root_stack_id=application_stack_id,
        )
        ledger["application_stack_name"] = application_nested_stack_id
    else:
        root_stack = stack_description(ledger, env, application_stack_id)
    ledger["stack_id"] = application_stack_id
    bind_deployed_vapi_resources(path, ledger, env)
    ledger["status"] = "deployed"
    record(path, ledger, "stack_ready")
    mirror_recovery_snapshot(path, ledger, env)
    print(f"stack ready: {ledger['stack_name']}")


def require_stack_id_for_name(
    ledger: dict[str, Any], stack_id: Any, stack_name: str, label: str
) -> str:
    exact_stack_id = require_stack_id_authority(ledger, stack_id, label)
    recorded_name = exact_stack_id.split(":stack/", 1)[1].split("/", 1)[0]
    if recorded_name != stack_name:
        raise LiveTestError(f"{label} has no exact stack ID")
    return exact_stack_id


def require_stack_id_authority(
    ledger: dict[str, Any], stack_id: Any, label: str
) -> str:
    partition = ledger.get("partition")
    region = ledger.get("region")
    account_id = ledger.get("account_id")
    if not all(
        isinstance(value, str) and value for value in (partition, region, account_id)
    ):
        raise LiveTestError(f"{label} has no exact account/region authority")
    expected = re.compile(
        rf"arn:{re.escape(partition)}:cloudformation:{re.escape(region)}:"
        rf"{re.escape(account_id)}:stack/[^/]+/{AWS_UUID_PATTERN_TEXT}"
    )
    if not isinstance(stack_id, str) or expected.fullmatch(stack_id) is None:
        raise LiveTestError(f"{label} has no exact stack ID")
    return stack_id


def require_change_set_id_authority(
    ledger: dict[str, Any],
    change_set_id: Any,
    label: str,
    *,
    expected_name: str | None = None,
) -> str:
    partition = ledger.get("partition")
    region = ledger.get("region")
    account_id = ledger.get("account_id")
    if not all(
        isinstance(value, str) and value for value in (partition, region, account_id)
    ):
        raise LiveTestError(f"{label} has no exact account/region authority")
    expected = re.compile(
        rf"arn:{re.escape(partition)}:cloudformation:{re.escape(region)}:"
        rf"{re.escape(account_id)}:changeSet/([^/]+)/({AWS_UUID_PATTERN_TEXT})"
    )
    if not isinstance(change_set_id, str):
        raise LiveTestError(f"{label} has no exact change-set ID")
    match = expected.fullmatch(change_set_id)
    if match is None or (expected_name is not None and match.group(1) != expected_name):
        raise LiveTestError(f"{label} has no exact change-set ID")
    return change_set_id


def reviewed_create_stack_id(ledger: dict[str, Any], *, qualification: bool) -> str:
    stack_name = ledger["qualification_stack_name" if qualification else "stack_name"]
    review_field = (
        "qualification_review_stack_id" if qualification else "review_stack_id"
    )
    deployed_field = "qualification_stack_id" if qualification else "stack_id"
    review_stack_id = require_stack_id_for_name(
        ledger, ledger.get(review_field), stack_name, "reviewed create"
    )
    deployed_stack_id = ledger.get(deployed_field)
    if deployed_stack_id is not None and deployed_stack_id != review_stack_id:
        raise LiveTestError("deployed stack ID differs from its reviewed create ID")
    return review_stack_id


def stack_description(
    ledger: dict[str, Any], env: dict[str, str] | None, identifier: str
) -> dict[str, Any]:
    expected_stack_id = require_stack_id_authority(
        ledger, identifier, "stack description"
    )
    expected_name = expected_stack_id.split(":stack/", 1)[1].split("/", 1)[0]
    response = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
        ],
        env=env,
    )
    stacks = response.get("Stacks") if isinstance(response, dict) else None
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or stacks[0].get("StackName") != expected_name
        or stacks[0].get("StackId") != expected_stack_id
    ):
        raise LiveTestError(
            f"stack description violated the exact-identifier contract: {expected_stack_id}"
        )
    return stacks[0]


def stack_description_by_name(
    ledger: dict[str, Any],
    env: dict[str, str] | None,
    stack_name: str,
) -> dict[str, Any]:
    """Use a mutable name only to detect and reject a replacement stack."""
    response = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            stack_name,
        ],
        env=env,
    )
    stacks = response.get("Stacks") if isinstance(response, dict) else None
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or stacks[0].get("StackName") != stack_name
        or not isinstance(stacks[0].get("StackId"), str)
    ):
        raise LiveTestError(
            f"stack description violated the name-probe contract: {stack_name}"
        )
    return stacks[0]


def bound_stack_status_or_reject_replacement(
    ledger: dict[str, Any],
    environment: dict[str, str] | None,
    stack_name: str,
    expected_stack_id: Any,
    label: str,
) -> str | None:
    """Resolve a bound stack without ever transferring authority by name."""
    if expected_stack_id is None:
        stack_status = stack_status_if_exists(stack_name, ledger["region"], environment)
        if stack_status == "DELETE_COMPLETE":
            return None
        return stack_status

    exact_stack_id = require_stack_id_for_name(
        ledger, expected_stack_id, stack_name, label
    )
    exact_status = stack_status_if_exists(exact_stack_id, ledger["region"], environment)
    if exact_status not in {None, "DELETE_COMPLETE"}:
        return exact_status

    # CloudFormation retains deleted-stack records by ID.  Only the mutable name
    # lookup can prove that no live replacement currently occupies that name.
    name_status = stack_status_if_exists(stack_name, ledger["region"], environment)
    if name_status in {None, "DELETE_COMPLETE"}:
        return None
    replacement = stack_description_by_name(ledger, environment, stack_name)
    replacement_stack_id = replacement.get("StackId")
    if replacement_stack_id != exact_stack_id:
        raise LiveTestError(f"{label} name resolves to a different live stack ID")
    raise LiveTestError(f"{label} identity reads are inconsistent")


def outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def nested_stack_id(
    ledger: dict[str, Any],
    env: dict[str, str],
    logical_id: str,
    parent_stack_id: str,
) -> str:
    exact_parent_stack_id = require_stack_id_authority(
        ledger, parent_stack_id, "nested-stack parent"
    )
    result = aws_json(
        [
            "cloudformation",
            "describe-stack-resource",
            "--region",
            ledger["region"],
            "--stack-name",
            exact_parent_stack_id,
            "--logical-resource-id",
            logical_id,
        ],
        env=env,
    )
    resource = result.get("StackResourceDetail") if isinstance(result, dict) else None
    if (
        not isinstance(resource, dict)
        or resource.get("StackId") != exact_parent_stack_id
        or resource.get("LogicalResourceId") != logical_id
        or resource.get("ResourceType") != "AWS::CloudFormation::Stack"
    ):
        raise LiveTestError("CloudFormation nested-resource identity changed")
    return require_stack_id_authority(
        ledger,
        resource.get("PhysicalResourceId"),
        f"nested stack {logical_id}",
    )


def describe_exact_stack_resource_if_exists(
    ledger: dict[str, Any],
    environment: dict[str, str],
    parent_stack_id: str,
    logical_id: str,
) -> dict[str, Any] | None:
    """Read one exact nested-stack resource and distinguish authoritative absence."""
    exact_parent_stack_id = require_stack_id_authority(
        ledger, parent_stack_id, "nested-resource parent"
    )
    result = command(
        [
            "aws",
            "cloudformation",
            "describe-stack-resource",
            "--region",
            ledger["region"],
            "--stack-name",
            exact_parent_stack_id,
            "--logical-resource-id",
            logical_id,
            "--output",
            "json",
            "--no-cli-pager",
        ],
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr or ""
        if "ValidationError" in detail and "does not exist for stack" in detail:
            return None
        raise LiveTestError(
            f"unable to classify exact CloudFormation resource {logical_id}"
        )
    try:
        response = json.loads(result.stdout or "")
    except json.JSONDecodeError as error:
        raise LiveTestError(
            "CloudFormation resource classification is invalid JSON"
        ) from error
    resource = (
        response.get("StackResourceDetail") if isinstance(response, dict) else None
    )
    if (
        not isinstance(resource, dict)
        or resource.get("StackId") != exact_parent_stack_id
        or resource.get("LogicalResourceId") != logical_id
        or resource.get("ResourceType") != "AWS::CloudFormation::Stack"
        or not isinstance(resource.get("ResourceStatus"), str)
    ):
        raise LiveTestError("CloudFormation nested-resource identity changed")
    physical_id = resource.get("PhysicalResourceId")
    if physical_id is not None:
        require_stack_id_authority(
            ledger, physical_id, "CloudFormation nested resource"
        )
    return resource


def exact_nested_stack_description(
    ledger: dict[str, Any],
    environment: dict[str, str],
    stack_id: str,
    *,
    parent_stack_id: str,
    root_stack_id: str,
) -> dict[str, Any]:
    exact_stack_id = require_stack_id_authority(ledger, stack_id, "nested stack")
    exact_parent_stack_id = require_stack_id_authority(
        ledger, parent_stack_id, "nested-stack parent"
    )
    exact_root_stack_id = require_stack_id_authority(
        ledger, root_stack_id, "nested-stack root"
    )
    description = stack_description(ledger, environment, exact_stack_id)
    if (
        description.get("StackId") != exact_stack_id
        or description.get("ParentId") != exact_parent_stack_id
        or description.get("RootId") != exact_root_stack_id
    ):
        raise LiveTestError("nested CloudFormation stack ancestry changed")
    return description


VAPI_OUTPUT_BINDINGS = (
    ("AssistantId", "vapi_assistant_id", "assistant"),
    ("PrepareToolId", "vapi_prepare_tool_id", "tool"),
    ("WebhookCredentialId", "vapi_webhook_credential_id", "credential"),
)


def require_vapi_resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or VAPI_RESOURCE_ID_PATTERN.fullmatch(value) is None:
        raise LiveTestError(f"{label} is not a bounded Vapi resource ID")
    return value


def bind_deployed_vapi_resources(
    path: Path, ledger: dict[str, Any], environment: dict[str, str]
) -> dict[str, str]:
    """Persist the exact external IDs before CloudFormation can delete its outputs."""
    root_stack_id = reviewed_create_stack_id(ledger, qualification=False)
    application_stack_id = ledger.get("application_stack_name")
    if application_stack_id is not None:
        application_stack_id = require_stack_id_authority(
            ledger, application_stack_id, "application nested stack"
        )
        discovered_application_stack_id = nested_stack_id(
            ledger, environment, "RecipeApplication", root_stack_id
        )
        if discovered_application_stack_id != application_stack_id:
            raise LiveTestError(
                "application nested stack differs from its ledger binding"
            )
        exact_nested_stack_description(
            ledger,
            environment,
            application_stack_id,
            parent_stack_id=root_stack_id,
            root_stack_id=root_stack_id,
        )
    else:
        application_stack_id = root_stack_id
    vapi_stack_id = nested_stack_id(
        ledger,
        environment,
        "VapiResources",
        application_stack_id,
    )
    description = exact_nested_stack_description(
        ledger,
        environment,
        vapi_stack_id,
        parent_stack_id=application_stack_id,
        root_stack_id=root_stack_id,
    )
    handoff_stack_id = nested_stack_id(
        ledger,
        environment,
        "HandoffService",
        application_stack_id,
    )
    handoff = exact_nested_stack_description(
        ledger,
        environment,
        handoff_stack_id,
        parent_stack_id=application_stack_id,
        root_stack_id=root_stack_id,
    )
    prepare_url = require_vapi_prepare_url(outputs(handoff).get("PrepareUrl"))
    existing_prepare_url = ledger.get("vapi_prepare_url")
    if existing_prepare_url is not None and existing_prepare_url != prepare_url:
        raise LiveTestError("Vapi prepare URL differs from its ledger binding")
    ledger["vapi_prepare_url"] = prepare_url
    return bind_vapi_stack_outputs(path, ledger, vapi_stack_id, description)


def bind_vapi_stack_outputs(
    path: Path,
    ledger: dict[str, Any],
    vapi_stack_id: str,
    description: dict[str, Any],
) -> dict[str, str]:
    """Bind complete Vapi outputs from an already ancestry-checked stack."""
    if description.get("StackId") != vapi_stack_id:
        raise LiveTestError("Vapi nested stack identity changed during binding")
    values = outputs(description)
    bindings = {
        ledger_field: require_vapi_resource_id(values.get(output_key), output_key)
        for output_key, ledger_field, _resource in VAPI_OUTPUT_BINDINGS
    }
    existing_stack_id = ledger.get("vapi_stack_id")
    if existing_stack_id is not None and existing_stack_id != vapi_stack_id:
        raise LiveTestError("Vapi nested stack differs from the ledger-bound stack")
    for ledger_field, value in bindings.items():
        existing = ledger.get(ledger_field)
        if existing is not None and existing != value:
            raise LiveTestError("Vapi resource output differs from its ledger binding")
    changed = (
        existing_stack_id is None
        or any(ledger.get(ledger_field) is None for ledger_field in bindings)
        or ledger.get("vapi_teardown_mode") != "bound_ids"
    )
    ledger["vapi_stack_id"] = vapi_stack_id
    ledger.update(bindings)
    ledger["vapi_teardown_mode"] = "bound_ids"
    if changed:
        record(path, ledger, "vapi_external_resources_bound")
    return values


def record_vapi_not_created(path: Path, ledger: dict[str, Any], *, reason: str) -> str:
    existing = ledger.get("vapi_teardown_mode")
    if existing not in {None, "not_created"}:
        raise LiveTestError("Vapi teardown classification changed unexpectedly")
    changed = existing is None or ledger.get("vapi_not_created_reason") != reason
    ledger["vapi_teardown_mode"] = "not_created"
    ledger["vapi_not_created_reason"] = reason
    if changed:
        record(path, ledger, "vapi_creation_authoritatively_not_reached", reason=reason)
    return "not_created"


def require_vapi_prepare_url(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 2_048
        or not value.startswith("https://")
        or any(character.isspace() for character in value)
    ):
        raise LiveTestError("Vapi prepare URL is invalid")
    return value


def recover_vapi_teardown_contract(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
    *,
    application_exists: bool,
    application_attempted: bool,
) -> str:
    """Classify Vapi teardown before stack outputs can disappear.

    A failed CREATE is safe to delete only after exact parent/child ancestry is
    recovered.  A physical Vapi nested stack without complete outputs uses the
    custom resource's pending-ID owner scan, followed by an independent scan.
    """
    bindings = bound_vapi_resource_ids(ledger)
    if bindings and ledger.get("vapi_prepare_url") is not None:
        require_vapi_prepare_url(ledger["vapi_prepare_url"])
        changed = ledger.get("vapi_teardown_mode") != "bound_ids"
        ledger["vapi_teardown_mode"] = "bound_ids"
        if changed:
            record(path, ledger, "vapi_bound_teardown_contract_recovered")
        return "bound_ids"
    if not application_attempted:
        return record_vapi_not_created(path, ledger, reason="application_not_executed")
    if not application_exists:
        if bindings:
            raise LiveTestError(
                "bound Vapi resources have no persisted prepare URL for owner-scan proof"
            )
        mode = ledger.get("vapi_teardown_mode")
        if mode in {"not_created", "owner_scan"}:
            return mode
        raise LiveTestError(
            "attempted application is absent without a persisted Vapi teardown classification"
        )

    root_stack_id = ledger.get("stack_id") or ledger.get("review_stack_id")
    if not isinstance(root_stack_id, str) or not root_stack_id.startswith("arn:"):
        raise LiveTestError("application teardown has no exact root stack ID")
    root = stack_description(ledger, environment, root_stack_id)
    if root.get("StackId") != root_stack_id:
        raise LiveTestError("application teardown root identity changed")
    root_status = root.get("StackStatus")
    if not isinstance(root_status, str):
        raise LiveTestError("application teardown root has no status")
    if root_status == "DELETE_IN_PROGRESS":
        mode = ledger.get("vapi_teardown_mode")
        if mode in {"not_created", "owner_scan"}:
            return mode
        raise LiveTestError(
            "application deletion began without a persisted Vapi teardown classification"
        )
    if root_status.endswith("_IN_PROGRESS"):
        raise LiveTestError(
            "application creation must reach a terminal state before Vapi classification"
        )

    application_stack_id = root_stack_id
    if ledger.get("connect_mode") == "disposable":
        application_resource = describe_exact_stack_resource_if_exists(
            ledger,
            environment,
            root_stack_id,
            "RecipeApplication",
        )
        if application_resource is not None and application_resource[
            "ResourceStatus"
        ].endswith("_IN_PROGRESS"):
            raise LiveTestError(
                "RecipeApplication must be terminal before Vapi classification"
            )
        if application_resource is None or not application_resource.get(
            "PhysicalResourceId"
        ):
            return record_vapi_not_created(
                path,
                ledger,
                reason="recipe_application_has_no_physical_stack",
            )
        application_stack_id = application_resource["PhysicalResourceId"]
        existing_application_id = ledger.get("application_stack_name")
        if (
            existing_application_id is not None
            and existing_application_id != application_stack_id
        ):
            raise LiveTestError(
                "recipe application stack differs from its ledger binding"
            )
        application = exact_nested_stack_description(
            ledger,
            environment,
            application_stack_id,
            parent_stack_id=root_stack_id,
            root_stack_id=root_stack_id,
        )
        application_status = application.get("StackStatus")
        if not isinstance(application_status, str) or application_status.endswith(
            "_IN_PROGRESS"
        ):
            raise LiveTestError(
                "RecipeApplication must be terminal before Vapi classification"
            )
        ledger["application_stack_name"] = application_stack_id

    vapi_resource = describe_exact_stack_resource_if_exists(
        ledger,
        environment,
        application_stack_id,
        "VapiResources",
    )
    if vapi_resource is not None and vapi_resource["ResourceStatus"].endswith(
        "_IN_PROGRESS"
    ):
        raise LiveTestError(
            "VapiResources must be terminal before teardown classification"
        )
    if vapi_resource is None or not vapi_resource.get("PhysicalResourceId"):
        return record_vapi_not_created(
            path,
            ledger,
            reason="vapi_nested_resource_has_no_physical_stack",
        )
    vapi_stack_id = vapi_resource["PhysicalResourceId"]
    existing_vapi_stack_id = ledger.get("vapi_stack_id")
    if existing_vapi_stack_id is not None and existing_vapi_stack_id != vapi_stack_id:
        raise LiveTestError("Vapi nested stack differs from its ledger binding")
    vapi_stack = exact_nested_stack_description(
        ledger,
        environment,
        vapi_stack_id,
        parent_stack_id=application_stack_id,
        root_stack_id=root_stack_id,
    )
    vapi_stack_status = vapi_stack.get("StackStatus")
    if not isinstance(vapi_stack_status, str) or vapi_stack_status.endswith(
        "_IN_PROGRESS"
    ):
        raise LiveTestError("Vapi nested stack must be terminal before teardown")
    ledger["vapi_stack_id"] = vapi_stack_id

    handoff_resource = describe_exact_stack_resource_if_exists(
        ledger,
        environment,
        application_stack_id,
        "HandoffService",
    )
    if handoff_resource is None or not handoff_resource.get("PhysicalResourceId"):
        raise LiveTestError("invoked Vapi stack has no exact HandoffService stack")
    handoff_stack = exact_nested_stack_description(
        ledger,
        environment,
        handoff_resource["PhysicalResourceId"],
        parent_stack_id=application_stack_id,
        root_stack_id=root_stack_id,
    )
    prepare_url = require_vapi_prepare_url(outputs(handoff_stack).get("PrepareUrl"))
    existing_prepare_url = ledger.get("vapi_prepare_url")
    if existing_prepare_url is not None and existing_prepare_url != prepare_url:
        raise LiveTestError("Vapi prepare URL differs from its ledger binding")
    ledger["vapi_prepare_url"] = prepare_url

    vapi_values = outputs(vapi_stack)
    output_keys = {output_key for output_key, _field, _resource in VAPI_OUTPUT_BINDINGS}
    present_output_keys = output_keys.intersection(vapi_values)
    if present_output_keys == output_keys:
        bind_vapi_stack_outputs(path, ledger, vapi_stack_id, vapi_stack)
        return "bound_ids"
    if present_output_keys:
        raise LiveTestError("failed Vapi nested stack exposes incomplete external IDs")
    if vapi_stack_status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise LiveTestError(
            "complete Vapi nested stack has no external resource outputs"
        )

    existing_mode = ledger.get("vapi_teardown_mode")
    if existing_mode not in {None, "owner_scan"}:
        raise LiveTestError("Vapi teardown classification changed unexpectedly")
    changed = existing_mode is None
    ledger["vapi_teardown_mode"] = "owner_scan"
    if changed:
        record(
            path,
            ledger,
            "vapi_failed_create_owner_scan_bound",
            vapi_stack_id=vapi_stack_id,
            vapi_stack_status=vapi_stack.get("StackStatus"),
        )
    return "owner_scan"


def verify_instance_hardening(
    ledger: dict[str, Any], env: dict[str, str], instances: list[dict[str, Any]]
) -> None:
    if not instances:
        raise LiveTestError("runtime has no running instances")
    for instance in instances:
        if (
            instance.get("KeyName")
            or instance.get("MetadataOptions", {}).get("HttpTokens") != "required"
        ):
            raise LiveTestError("runtime host violates the no-SSH/IMDSv2 gate")
    volume_ids = [
        mapping["Ebs"]["VolumeId"]
        for instance in instances
        for mapping in instance.get("BlockDeviceMappings", [])
        if mapping.get("Ebs", {}).get("VolumeId")
    ]
    if not volume_ids:
        raise LiveTestError("runtime host has no inspectable volumes")
    volumes = aws_json(
        [
            "ec2",
            "describe-volumes",
            "--region",
            ledger["region"],
            "--volume-ids",
            *volume_ids,
        ],
        env=env,
    )["Volumes"]
    if len(volumes) != len(volume_ids) or not all(
        volume.get("Encrypted") is True for volume in volumes
    ):
        raise LiveTestError("runtime volume encryption gate failed")


def ipv4_addresses(hostname: str) -> set[str]:
    try:
        return {
            item[4][0]
            for item in socket.getaddrinfo(
                hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        }
    except socket.gaierror as error:
        raise LiveTestError("public signaling DNS did not resolve") from error


def http_post(url: str, token: str, payload: dict[str, Any]) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        method="POST",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "bridgefu-qualification/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            decoded = json.loads(body)
        except Exception:
            decoded = {"error": "non_json_response"}
        return error.code, decoded


def http_get(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            "user-agent": "bridgefu-qualification/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise LiveTestError(
                    "demo site response exceeds the qualification limit"
                )
            return (
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                body,
            )
    except urllib.error.HTTPError as error:
        return error.code, {}, error.read(1024)


def verify_demo_site(
    ledger: dict[str, Any], root_outputs: dict[str, str], assistant_id: str
) -> None:
    if not ledger.get("enable_demo_site"):
        return
    site_url = root_outputs.get("DemoSiteUrl", "")
    if not site_url.startswith("https://"):
        raise LiveTestError("the enabled demo site has no HTTPS stack output")
    index_status, index_headers, index_body = http_get(site_url + "/")
    if index_status != 200 or b"Bridgefu recipe test call" not in index_body:
        raise LiveTestError("the CloudFront demo page is not readable")
    security_policy = index_headers.get("content-security-policy", "")
    if "frame-ancestors 'none'" not in security_policy:
        raise LiveTestError(
            "the CloudFront demo page is missing browser isolation headers"
        )
    config_status, _, config_body = http_get(site_url + "/config.json")
    if config_status != 200:
        raise LiveTestError("the CloudFront demo configuration is not readable")
    try:
        config = json.loads(config_body)
    except (TypeError, ValueError) as error:
        raise LiveTestError("the CloudFront demo configuration is invalid") from error
    expected_keys = {
        "schema_version",
        "recipe",
        "vapi_public_key",
        "vapi_assistant_id",
        "release_revision",
    }
    runtime_manifest = json.loads(
        (
            ledger_path(ledger["execution_id"]).parent
            / "release"
            / "artifacts"
            / "runtime"
            / "manifest.json"
        ).read_text()
    )
    if (
        set(config) != expected_keys
        or config.get("schema_version") != 1
        or config.get("recipe") != RECIPE
        or config.get("vapi_assistant_id") != assistant_id
        or config.get("release_revision") != runtime_manifest["artifact"]["sha256"]
        or not isinstance(config.get("vapi_public_key"), str)
        or hashlib.sha256(config["vapi_public_key"].encode()).hexdigest()
        != ledger.get("demo_site_public_key_sha256")
    ):
        raise LiveTestError(
            "the CloudFront demo configuration violates its public contract"
        )
    app_status, _, app_body = http_get(site_url + "/app.js")
    if app_status != 200 or b"__BRIDGEFU_RECIPE_TEST__" not in app_body:
        raise LiveTestError("the CloudFront demo automation surface is unavailable")


def secret_value(ledger: dict[str, Any], env: dict[str, str], arn: str) -> str:
    return aws_json(
        [
            "secretsmanager",
            "get-secret-value",
            "--region",
            ledger["region"],
            "--secret-id",
            arn,
        ],
        env=env,
    )["SecretString"]


class _VapiNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def vapi_get_resource(
    api_key: str,
    resource: str,
    resource_id: str,
) -> dict[str, Any] | None:
    """Read one exact Vapi object without redirects or unbounded responses."""
    if not isinstance(api_key, str) or len(api_key) < 24:
        raise LiveTestError("Vapi API key is invalid")
    if resource not in {"assistant", "tool", "credential"}:
        raise LiveTestError("unsupported Vapi resource type")
    resource_id = require_vapi_resource_id(resource_id, resource)
    opener = urllib.request.build_opener(_VapiNoRedirect())
    request = urllib.request.Request(
        f"https://api.vapi.ai/{resource}/{resource_id}",
        method="GET",
        headers={
            "authorization": f"Bearer {api_key}",
            "accept": "application/json",
            "user-agent": "bridgefu-qualification/1",
        },
    )
    for attempt in range(2):
        try:
            with opener.open(request, timeout=20) as response:
                if response.status != 200:
                    raise LiveTestError("Vapi resource read returned an invalid status")
                raw = response.read(MAX_VAPI_RESPONSE_BYTES + 1)
            break
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if error.code in {429, 500, 502, 503, 504} and attempt == 0:
                continue
            if error.code in {401, 403}:
                raise LiveTestError("Vapi resource inventory is unauthorized") from None
            raise LiveTestError("Vapi resource inventory request failed") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 0:
                continue
            raise LiveTestError("Vapi resource inventory is unavailable") from None
    if len(raw) > MAX_VAPI_RESPONSE_BYTES:
        raise LiveTestError("Vapi resource inventory response is too large")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise LiveTestError("Vapi resource inventory response is invalid") from None
    if not isinstance(value, dict) or value.get("id") != resource_id:
        raise LiveTestError("Vapi resource inventory identity changed")
    return value


def vapi_list_resources(api_key: str, resource: str) -> list[dict[str, Any]]:
    """Read one exhaustive maximum-size Vapi page or fail closed."""
    if not isinstance(api_key, str) or len(api_key) < 24:
        raise LiveTestError("Vapi API key is invalid")
    if resource not in {"assistant", "tool", "credential"}:
        raise LiveTestError("unsupported Vapi resource type")
    opener = urllib.request.build_opener(_VapiNoRedirect())
    request = urllib.request.Request(
        f"https://api.vapi.ai/{resource}?limit={VAPI_LIST_LIMIT}",
        method="GET",
        headers={
            "authorization": f"Bearer {api_key}",
            "accept": "application/json",
            "user-agent": "bridgefu-qualification/1",
        },
    )
    for attempt in range(2):
        try:
            with opener.open(request, timeout=20) as response:
                if response.status != 200:
                    raise LiveTestError("Vapi resource list returned an invalid status")
                raw = response.read(MAX_VAPI_RESPONSE_BYTES + 1)
            break
        except urllib.error.HTTPError as error:
            if error.code in {429, 500, 502, 503, 504} and attempt == 0:
                continue
            if error.code in {401, 403}:
                raise LiveTestError("Vapi resource inventory is unauthorized") from None
            raise LiveTestError("Vapi resource inventory request failed") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 0:
                continue
            raise LiveTestError("Vapi resource inventory is unavailable") from None
    if len(raw) > MAX_VAPI_RESPONSE_BYTES:
        raise LiveTestError("Vapi resource inventory response is too large")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise LiveTestError("Vapi resource inventory response is invalid") from None
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
        items = payload["results"]
    else:
        raise LiveTestError("Vapi resource inventory response is invalid")
    if len(items) >= VAPI_LIST_LIMIT or not all(
        isinstance(item, dict) for item in items
    ):
        raise LiveTestError("Vapi resource inventory is not provably exhaustive")
    return items


def vapi_owner_scan_expectation(ledger: dict[str, Any]) -> dict[str, str]:
    stack_id = ledger.get("vapi_stack_id")
    if not isinstance(stack_id, str) or not stack_id.startswith("arn:"):
        raise LiveTestError("Vapi owner scan has no exact nested stack ID")
    prepare_url = require_vapi_prepare_url(ledger.get("vapi_prepare_url"))
    owner_token = hashlib.sha256(stack_id.encode()).hexdigest()[:32]
    prefix = re.sub(r"[^A-Za-z0-9-]", "-", ledger["execution_id"])[:17]
    return {
        "vapi_stack_id": stack_id,
        "owner_token": owner_token,
        "assistant_name": f"Bridgefu {prefix} {owner_token[:10]}"[:40],
        "credential_name": f"Bridgefu {owner_token[:30]}",
        "prepare_url": prepare_url,
    }


def vapi_owner_scan_candidates(
    api_key: str, ledger: dict[str, Any]
) -> list[dict[str, str]]:
    """Find any object that could belong to a failed pending-ID create."""
    expected = vapi_owner_scan_expectation(ledger)
    candidates: list[dict[str, str]] = []
    assistants = vapi_list_resources(api_key, "assistant")
    for item in assistants:
        metadata = item.get("metadata")
        metadata_matches = isinstance(metadata, dict) and (
            metadata.get("bridgefu_owner") == expected["owner_token"]
            or metadata.get("bridgefu_deployment") == ledger["execution_id"]
        )
        if item.get("name") == expected["assistant_name"] or metadata_matches:
            candidates.append(
                {
                    "resource": "assistant",
                    "id": require_vapi_resource_id(item.get("id"), "assistant"),
                }
            )
    credentials = vapi_list_resources(api_key, "credential")
    for item in credentials:
        if item.get("name") == expected["credential_name"]:
            candidates.append(
                {
                    "resource": "credential",
                    "id": require_vapi_resource_id(item.get("id"), "credential"),
                }
            )
    tools = vapi_list_resources(api_key, "tool")
    for item in tools:
        server = item.get("server")
        if isinstance(server, dict) and server.get("url") == expected["prepare_url"]:
            candidates.append(
                {
                    "resource": "tool",
                    "id": require_vapi_resource_id(item.get("id"), "tool"),
                }
            )
    return sorted(candidates, key=lambda item: (item["resource"], item["id"]))


def bound_vapi_resource_ids(ledger: dict[str, Any]) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    present = 0
    for _output_key, ledger_field, resource in VAPI_OUTPUT_BINDINGS:
        resource_id = ledger.get(ledger_field)
        if resource_id is None:
            continue
        present += 1
        values.append(
            {
                "resource": resource,
                "id": require_vapi_resource_id(resource_id, ledger_field),
            }
        )
    if present not in {0, len(VAPI_OUTPUT_BINDINGS)}:
        raise LiveTestError("Vapi resource ledger binding is incomplete")
    if present and not isinstance(ledger.get("vapi_stack_id"), str):
        raise LiveTestError("Vapi resource ledger has no stack identity")
    return values


def verify_bound_vapi_resources(
    ledger: dict[str, Any],
    api_key: str,
    handoff: dict[str, str],
) -> None:
    resources = {
        item["resource"]: vapi_get_resource(api_key, item["resource"], item["id"])
        for item in bound_vapi_resource_ids(ledger)
    }
    if set(resources) != {"assistant", "tool", "credential"} or any(
        value is None for value in resources.values()
    ):
        raise LiveTestError("a ledger-bound Vapi resource is absent")
    assistant = resources["assistant"]
    tool = resources["tool"]
    credential = resources["credential"]
    assert assistant is not None and tool is not None and credential is not None
    owner_token = hashlib.sha256(ledger["vapi_stack_id"].encode()).hexdigest()[:32]
    metadata = assistant.get("metadata")
    model = assistant.get("model")
    server = assistant.get("server")
    assistant_credential_ids = assistant.get("credentialIds")
    if (
        not isinstance(metadata, dict)
        or metadata.get("bridgefu_recipe") != RECIPE
        or metadata.get("bridgefu_owner") != owner_token
        or metadata.get("bridgefu_deployment") != ledger["execution_id"]
        or not isinstance(model, dict)
        or ledger["vapi_prepare_tool_id"] not in model.get("toolIds", [])
        or not isinstance(server, dict)
        or server.get("credentialId") != ledger["vapi_webhook_credential_id"]
        or assistant_credential_ids != [ledger["vapi_webhook_credential_id"]]
    ):
        raise LiveTestError("Vapi assistant ownership check failed")
    function = tool.get("function")
    tool_server = tool.get("server")
    if (
        tool.get("type") != "function"
        or not isinstance(function, dict)
        or function.get("name") != "prepare_handoff"
        or not isinstance(tool_server, dict)
        or tool_server.get("url") != handoff["PrepareUrl"]
        or tool_server.get("credentialId") != ledger["vapi_webhook_credential_id"]
    ):
        raise LiveTestError("Vapi prepare-tool ownership check failed")
    if (
        credential.get("provider") != "custom-credential"
        or credential.get("name") != f"Bridgefu {owner_token[:30]}"
    ):
        raise LiveTestError("Vapi webhook-credential ownership check failed")


def cached_vapi_absence_proof_is_valid(path: Path, ledger: dict[str, Any]) -> bool:
    expected_sha256 = ledger.get("vapi_teardown_proof_sha256")
    proof_path = path.parent / "vapi-teardown-evidence.json"
    if not isinstance(expected_sha256, str) or not proof_path.is_file():
        return False
    try:
        proof = json.loads(proof_path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if (
        not isinstance(proof, dict)
        or proof.get("execution_id") != ledger["execution_id"]
        or proof.get("all_absent") is not True
        or canonical_json_sha256(proof) != expected_sha256
    ):
        return False
    bindings = bound_vapi_resource_ids(ledger)
    if bindings:
        try:
            expected_owner_scan = vapi_owner_scan_expectation(ledger)
        except LiveTestError:
            return False
        return (
            proof.get("proof_mode") == "bound_ids"
            and proof.get("resources") == bindings
            and proof.get("owner_scan") == expected_owner_scan
        )
    if ledger.get("vapi_teardown_mode") != "owner_scan":
        return False
    try:
        expected = vapi_owner_scan_expectation(ledger)
    except LiveTestError:
        return False
    return (
        proof.get("proof_mode") == "owner_scan"
        and proof.get("resources") == []
        and proof.get("owner_scan") == expected
    )


def prove_bound_vapi_resources_absent(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
) -> None:
    """Require authoritative 404s for every bound Vapi object before key deletion."""
    resources = bound_vapi_resource_ids(ledger)
    if not resources:
        raise LiveTestError(
            "no ledger-bound Vapi resources are available for teardown proof"
        )
    if cached_vapi_absence_proof_is_valid(path, ledger):
        return
    secret_arn = ledger.get("vapi_api_key_secret_arn")
    if not isinstance(secret_arn, str):
        raise LiveTestError("Vapi teardown proof has no API-key secret")
    api_key = secret_value(ledger, environment, secret_arn)
    remaining = list(resources)
    owner_candidates: list[dict[str, str]] = []
    for attempt in range(VAPI_ABSENCE_ATTEMPTS):
        remaining = [
            item
            for item in resources
            if vapi_get_resource(api_key, item["resource"], item["id"]) is not None
        ]
        owner_candidates = vapi_owner_scan_candidates(api_key, ledger)
        if not remaining and not owner_candidates:
            break
        if attempt + 1 < VAPI_ABSENCE_ATTEMPTS:
            time.sleep(VAPI_ABSENCE_INTERVAL_SECONDS)
    if remaining or owner_candidates:
        raise LiveTestError(
            "CloudFormation deletion left ledger-bound or owner-derived Vapi resources"
        )
    checked_at = utc_now()
    proof = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "checked_at": checked_at,
        "proof_mode": "bound_ids",
        "owner_scan": vapi_owner_scan_expectation(ledger),
        "resources": resources,
        "all_absent": True,
    }
    atomic_json(path.parent / "vapi-teardown-evidence.json", proof)
    ledger["vapi_teardown_proven_at"] = checked_at
    ledger["vapi_teardown_proof_sha256"] = canonical_json_sha256(proof)
    record(path, ledger, "vapi_external_teardown_proven")


def prove_owner_scanned_vapi_resources_absent(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
) -> None:
    """Prove a failed pending-ID create left no owner-derived Vapi objects."""
    if ledger.get("vapi_teardown_mode") != "owner_scan":
        raise LiveTestError(
            "Vapi owner-scan proof has no pending-create classification"
        )
    if bound_vapi_resource_ids(ledger):
        raise LiveTestError("Vapi owner-scan proof cannot replace exact bound-ID proof")
    if cached_vapi_absence_proof_is_valid(path, ledger):
        return
    secret_arn = ledger.get("vapi_api_key_secret_arn")
    if not isinstance(secret_arn, str):
        raise LiveTestError("Vapi teardown proof has no API-key secret")
    api_key = secret_value(ledger, environment, secret_arn)
    remaining: list[dict[str, str]] = []
    for attempt in range(VAPI_ABSENCE_ATTEMPTS):
        remaining = vapi_owner_scan_candidates(api_key, ledger)
        if not remaining:
            break
        if attempt + 1 < VAPI_ABSENCE_ATTEMPTS:
            time.sleep(VAPI_ABSENCE_INTERVAL_SECONDS)
    if remaining:
        raise LiveTestError("CloudFormation deletion left owner-derived Vapi resources")
    checked_at = utc_now()
    proof = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "checked_at": checked_at,
        "proof_mode": "owner_scan",
        "owner_scan": vapi_owner_scan_expectation(ledger),
        "resources": [],
        "all_absent": True,
    }
    atomic_json(path.parent / "vapi-teardown-evidence.json", proof)
    ledger["vapi_teardown_proven_at"] = checked_at
    ledger["vapi_teardown_proof_sha256"] = canonical_json_sha256(proof)
    record(path, ledger, "vapi_failed_create_teardown_proven")


def prove_vapi_teardown_contract(
    path: Path,
    ledger: dict[str, Any],
    environment: dict[str, str],
) -> None:
    mode = ledger.get("vapi_teardown_mode")
    if mode == "not_created":
        if bound_vapi_resource_ids(ledger):
            raise LiveTestError("Vapi not-created state has external ID bindings")
        return
    if mode == "bound_ids":
        prove_bound_vapi_resources_absent(path, ledger, environment)
        return
    if mode == "owner_scan":
        prove_owner_scanned_vapi_resources_absent(path, ledger, environment)
        return
    raise LiveTestError("attempted application has no Vapi teardown contract")


def ssm_shell(
    ledger: dict[str, Any],
    env: dict[str, str],
    instance_ids: list[str],
    script: str,
) -> list[str]:
    if not 1 <= len(instance_ids) <= 16 or len(script.encode("utf-8")) > 16_384:
        raise LiveTestError("bounded SSM verification command is invalid")
    result = aws_json(
        [
            "ssm",
            "send-command",
            "--region",
            ledger["region"],
            "--document-name",
            "AWS-RunShellScript",
            "--instance-ids",
            *instance_ids,
            "--parameters",
            json.dumps(
                {"commands": [script], "executionTimeout": ["120"]},
                separators=(",", ":"),
            ),
            "--timeout-seconds",
            "120",
            "--max-concurrency",
            "1",
            "--max-errors",
            "0",
            "--comment",
            f"Bridgefu immutable runtime verification {ledger['execution_id']}",
        ],
        env=env,
    )
    command_id = result.get("Command", {}).get("CommandId")
    if not isinstance(command_id, str):
        raise LiveTestError("SSM runtime verification was not accepted")
    outputs: list[str] = []
    for instance_id in instance_ids:
        deadline = time.monotonic() + 150
        invocation: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            value = aws_json(
                [
                    "ssm",
                    "get-command-invocation",
                    "--region",
                    ledger["region"],
                    "--command-id",
                    command_id,
                    "--instance-id",
                    instance_id,
                ],
                env=env,
                check=False,
            )
            if isinstance(value, dict):
                if value.get("Status") == "Success":
                    invocation = value
                    break
                if value.get("Status") in {
                    "Cancelled",
                    "Cancelling",
                    "Failed",
                    "TimedOut",
                    "Undeliverable",
                    "Terminated",
                }:
                    raise LiveTestError("SSM runtime verification failed")
            time.sleep(1)
        if invocation is None:
            raise LiveTestError("SSM runtime verification did not finish")
        output = invocation.get("StandardOutputContent", "")
        if not isinstance(output, str) or len(output.encode("utf-8")) > 16_384:
            raise LiveTestError("SSM runtime verification output is invalid")
        outputs.append(output)
    return outputs


def runtime_recipe_fingerprint(
    ledger: dict[str, Any], qualification_env: dict[str, str], instance_ids: list[str]
) -> str:
    script = """set -euo pipefail
found=0
for container in $(docker ps --quiet); do
  output="$(docker exec "$container" /usr/local/bin/bridgefu --config /etc/bridgefu/bridgefu.yaml recipe list --configured 2>/dev/null || true)"
  if printf '%s\n' "$output" | grep -Eq '^support[[:space:]]+vapi-amazon-connect-screen-pop@1[[:space:]]+'; then
    printf '%s\n' "$output"
    found=1
  fi
done
if test "$found" -eq 0; then
  printf 'bridgefu-no-recipe-on-this-slot\n'
fi
"""
    outputs = ssm_shell(ledger, qualification_env, instance_ids, script)
    fingerprints: set[str] = set()
    for output in outputs:
        for line in output.splitlines():
            fields = line.split()
            if (
                len(fields) == 4
                and fields[0] == "support"
                and fields[1] == RECIPE
                and re.fullmatch(r"[a-z_]+", fields[2])
                and re.fullmatch(r"[0-9a-f]{64}", fields[3])
            ):
                fingerprints.add(fields[3])
    if len(fingerprints) != 1:
        raise LiveTestError("deployed recipe fingerprint is absent or inconsistent")
    return next(iter(fingerprints))


def derive_correlation_id(
    key: str, execution_id: str, source_org_id: str, source_call_id: str
) -> str:
    if len(key.encode("utf-8")) < 32:
        raise LiveTestError("correlation key is shorter than the deployed contract")
    for value in (execution_id, source_org_id, source_call_id):
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is None:
            raise LiveTestError("private source identity is invalid")
    material = (f"bridgefu|{execution_id}|{source_org_id}|{source_call_id}").encode(
        "utf-8"
    )
    digest = hmac.new(key.encode("utf-8"), material, hashlib.sha256).digest()
    correlation_id = "bf1_" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip(
        "="
    )
    if not re.fullmatch(r"bf1_[A-Za-z0-9_-]{43}", correlation_id):
        raise LiveTestError("derived correlation ID violates the public contract")
    return correlation_id


def verify(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if ledger["status"] not in {
        "deployed",
        "verified",
        "updating",
        "updated",
        "rollback_drill",
        "rollback_incomplete",
        "lifecycle_verified",
    }:
        raise LiveTestError("verify requires a ready deployment")
    require_qualification_deadline(path, ledger, "deployment verification")
    env = assume_env(ledger, "qualification")
    application_stack_id = reviewed_create_stack_id(ledger, qualification=False)
    deployment_root = stack_description(ledger, env, application_stack_id)
    if deployment_root["StackStatus"] not in {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }:
        raise LiveTestError("root stack is not in a stable complete state")
    if ledger.get("connect_mode") == "disposable":
        qualification_stack_id = reviewed_create_stack_id(ledger, qualification=True)
        qualification_stack = stack_description(ledger, env, qualification_stack_id)
        qualification_outputs = outputs(qualification_stack)
        if (
            qualification_stack.get("StackStatus")
            not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or qualification_outputs.get("ProjectName")
            != ledger.get("qualification_project_name")
            or qualification_outputs.get("RunnerSourceCidr")
            != ledger.get("qualification_source_cidr")
            or qualification_outputs.get("RunnerLogGroupName")
            != ledger.get("qualification_runner_log_group_name")
        ):
            raise LiveTestError(
                "independent qualification runner violates its exact deployment contract"
            )
    application_nested_stack_id = ledger.get("application_stack_name")
    if application_nested_stack_id is not None:
        application_nested_stack_id = require_stack_id_authority(
            ledger,
            application_nested_stack_id,
            "application nested stack",
        )
        discovered_application_stack_id = nested_stack_id(
            ledger, env, "RecipeApplication", application_stack_id
        )
        if discovered_application_stack_id != application_nested_stack_id:
            raise LiveTestError(
                "application nested stack differs from its ledger binding"
            )
        root_stack = exact_nested_stack_description(
            ledger,
            env,
            application_nested_stack_id,
            parent_stack_id=application_stack_id,
            root_stack_id=application_stack_id,
        )
    else:
        application_nested_stack_id = application_stack_id
        root_stack = deployment_root
    root_outputs = outputs(root_stack)
    runtime_profile = ledger.get("runtime_profile", "starter")
    expected_profile = (
        "HighAvailability" if runtime_profile == "high_availability" else "Starter"
    )
    if root_outputs.get("RuntimeProfile") != expected_profile:
        raise LiveTestError(
            "deployed runtime profile does not match the qualification ledger"
        )
    handoff_stack_id = nested_stack_id(
        ledger, env, "HandoffService", application_nested_stack_id
    )
    handoff = outputs(
        exact_nested_stack_description(
            ledger,
            env,
            handoff_stack_id,
            parent_stack_id=application_nested_stack_id,
            root_stack_id=application_stack_id,
        )
    )
    runtime_logical_id = (
        "HighAvailabilityRuntime"
        if runtime_profile == "high_availability"
        else "StarterRuntime"
    )
    runtime_stack_id = nested_stack_id(
        ledger, env, runtime_logical_id, application_nested_stack_id
    )
    runtime = outputs(
        exact_nested_stack_description(
            ledger,
            env,
            runtime_stack_id,
            parent_stack_id=application_nested_stack_id,
            root_stack_id=application_stack_id,
        )
    )
    vapi = bind_deployed_vapi_resources(path, ledger, env)
    verify_demo_site(ledger, root_outputs, vapi["AssistantId"])
    webhook = secret_value(ledger, env, handoff["VapiWebhookSecretArn"])
    correlation_key = secret_value(ledger, env, handoff["CorrelationKeySecretArn"])
    synthetic = {
        "message": {
            "type": "tool-calls",
            "call": {"id": "call_bridgefu_qualification", "orgId": "org_bridgefu_test"},
            "toolCallList": [
                {
                    "id": "tool_bridgefu_qualification",
                    "name": "prepare_handoff",
                    "arguments": {
                        "customer_name": "Synthetic Caller",
                        "issue_summary": "Synthetic qualification request.",
                        "intent": "qualification",
                        "verification_status": "synthetic",
                    },
                }
            ],
        }
    }
    started = time.monotonic()
    prepare_status, prepare_body = http_post(handoff["PrepareUrl"], webhook, synthetic)
    replay_status, replay_body = http_post(handoff["PrepareUrl"], webhook, synthetic)
    if prepare_status != 200 or replay_status != 200 or prepare_body != replay_body:
        raise LiveTestError("prepare endpoint failed its idempotency gate")
    correlation_id = derive_correlation_id(
        correlation_key,
        ledger["execution_id"],
        "org_bridgefu_test",
        "call_bridgefu_qualification",
    )
    transfer_payload = {
        "message": {
            "type": "transfer-destination-request",
            "call": {"id": "call_bridgefu_qualification", "orgId": "org_bridgefu_test"},
        }
    }
    transfer_status, transfer_body = http_post(
        handoff["TransferUrl"], webhook, transfer_payload
    )
    if transfer_status != 200:
        raise LiveTestError("transfer destination endpoint did not reserve a route")
    destination = transfer_body.get("destination", {})
    expected_scheme = "sip:" if ledger.get("sip_security") == "sip_rtp" else "sips:"
    if (
        destination.get("type") != "sip"
        or not destination.get("sipUri", "").startswith(expected_scheme)
        or destination.get("sipHeaders") != {"X-Correlation-Id": correlation_id}
    ):
        raise LiveTestError("transfer response violates the fixed SIP/header contract")
    lookup_payload = {
        "Details": {"ContactData": {"Attributes": {"correlation_id": correlation_id}}}
    }
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as payload_file:
        payload_file.write(json.dumps(lookup_payload).encode())
        payload_name = Path(payload_file.name)
    response_name = path.parent / ".lookup-response.json"
    try:
        aws_json(
            [
                "lambda",
                "invoke",
                "--region",
                ledger["region"],
                "--function-name",
                handoff["LookupFunctionName"],
                "--cli-binary-format",
                "raw-in-base64-out",
                "--payload",
                f"fileb://{payload_name}",
                os.fspath(response_name),
            ],
            env=env,
        )
        lookup = json.loads(response_name.read_text())
    finally:
        payload_name.unlink(missing_ok=True)
        response_name.unlink(missing_ok=True)
    expected_fields = {
        "context_available",
        "customer_name",
        "issue_summary",
        "intent",
        "verification_status",
        "vapi_call_reference",
    }
    if set(lookup) != expected_fields or lookup["context_available"] != "true":
        raise LiveTestError("Connect-shaped lookup did not return the bounded flat map")
    profile_checks: dict[str, bool]
    runtime_instance_ids: list[str]
    if runtime_profile == "starter":
        instance = aws_json(
            [
                "ec2",
                "describe-instances",
                "--region",
                ledger["region"],
                "--instance-ids",
                runtime["InstanceId"],
            ],
            env=env,
        )["Reservations"][0]["Instances"][0]
        verify_instance_hardening(ledger, env, [instance])
        if ledger.get("sip_security") == "sip_rtp":
            if runtime.get("SipHostname") != runtime["PublicIp"]:
                raise LiveTestError("IP-only SIP proof did not advertise its exact EIP")
        elif ipv4_addresses(ledger["sip_hostname"]) != {runtime["PublicIp"]}:
            raise LiveTestError("public SIP DNS does not resolve to the recipe EIP")
        certificate_arn = runtime["CertificateArn"]
        runtime_instance_ids = [runtime["InstanceId"]]
        profile_checks = {
            (
                "starter_ip_matches_eip"
                if ledger.get("sip_security") == "sip_rtp"
                else "starter_dns_matches_eip"
            ): True
        }
    else:
        expected_services = {"gateway-a", "gateway-b", "worker-a", "worker-b"}
        services_response = aws_json(
            [
                "ecs",
                "describe-services",
                "--region",
                ledger["region"],
                "--cluster",
                runtime["ClusterName"],
                "--services",
                *sorted(expected_services),
            ],
            env=env,
        )
        if services_response.get("failures"):
            raise LiveTestError("AWS reported missing HA runtime services")
        services = services_response.get("services", [])
        if {service.get("serviceName") for service in services} != expected_services:
            raise LiveTestError("HA runtime service inventory is incomplete")
        for service in services:
            primary = [
                deployment
                for deployment in service.get("deployments", [])
                if deployment.get("status") == "PRIMARY"
            ]
            if (
                service.get("status") != "ACTIVE"
                or service.get("desiredCount") != 1
                or service.get("runningCount") != 1
                or service.get("pendingCount") != 0
                or len(primary) != 1
                or primary[0].get("rolloutState") not in {None, "COMPLETED"}
            ):
                raise LiveTestError("an HA runtime service is not stable")

        instance_response = aws_json(
            [
                "ec2",
                "describe-instances",
                "--region",
                ledger["region"],
                "--filters",
                f"Name=tag:BridgefuExecutionId,Values={ledger['execution_id']}",
                "Name=instance-state-name,Values=running",
            ],
            env=env,
        )
        instances = [
            instance
            for reservation in instance_response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
        slots: dict[str, str] = {}
        for instance in instances:
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            slot = tags.get("BridgefuSlot", "")
            if slot in slots:
                raise LiveTestError("HA runtime has a duplicate slot identity")
            slots[slot] = instance["InstanceId"]
        if set(slots) != expected_services:
            raise LiveTestError("HA runtime does not have exactly four bounded slots")
        verify_instance_hardening(ledger, env, instances)
        runtime_instance_ids = sorted(slots.values())

        gateway_ips = {
            runtime["GatewayEipAPublicIp"],
            runtime["GatewayEipBPublicIp"],
        }
        addresses = aws_json(
            [
                "ec2",
                "describe-addresses",
                "--region",
                ledger["region"],
                "--public-ips",
                *sorted(gateway_ips),
            ],
            env=env,
        ).get("Addresses", [])
        if {address.get("PublicIp") for address in addresses} != gateway_ips or {
            address.get("InstanceId") for address in addresses
        } != {slots["gateway-a"], slots["gateway-b"]}:
            raise LiveTestError("HA gateway EIP association is not reconciled")

        target_groups = {
            runtime["PublicSignalingTargetGroupArn"]: 2,
            runtime["ControlTargetGroupArn"]: 2,
            runtime["WorkerATargetGroupArn"]: 1,
            runtime["WorkerBTargetGroupArn"]: 1,
        }
        for target_group, expected_count in target_groups.items():
            health = aws_json(
                [
                    "elbv2",
                    "describe-target-health",
                    "--region",
                    ledger["region"],
                    "--target-group-arn",
                    target_group,
                ],
                env=env,
            ).get("TargetHealthDescriptions", [])
            if len(health) != expected_count or any(
                item.get("TargetHealth", {}).get("State") != "healthy"
                for item in health
            ):
                raise LiveTestError("an HA load-balancer target is not healthy")

        database = aws_json(
            [
                "rds",
                "describe-db-instances",
                "--region",
                ledger["region"],
                "--db-instance-identifier",
                runtime["DatabaseIdentifier"],
            ],
            env=env,
        )["DBInstances"][0]
        if (
            database.get("DBInstanceStatus") != "available"
            or database.get("MultiAZ") is not True
            or database.get("StorageEncrypted") is not True
            or database.get("PubliclyAccessible") is not False
        ):
            raise LiveTestError("HA PostgreSQL readiness or encryption gate failed")
        cache = aws_json(
            [
                "elasticache",
                "describe-replication-groups",
                "--region",
                ledger["region"],
                "--replication-group-id",
                runtime["RedisReplicationGroupId"],
            ],
            env=env,
        )["ReplicationGroups"][0]
        if (
            cache.get("Status") != "available"
            or cache.get("AtRestEncryptionEnabled") is not True
            or cache.get("TransitEncryptionEnabled") is not True
            or cache.get("AutomaticFailover") != "enabled"
            or cache.get("MultiAZ") != "enabled"
        ):
            raise LiveTestError("HA Valkey readiness or encryption gate failed")

        public_signaling_addresses: set[str] = set()
        sip_addresses: set[str] = set()
        for attempt in range(12):
            public_signaling_addresses = ipv4_addresses(
                runtime["PublicSignalingDnsName"]
            )
            sip_addresses = ipv4_addresses(ledger["sip_hostname"])
            if (
                public_signaling_addresses
                and sip_addresses == public_signaling_addresses
            ):
                break
            if attempt < 11:
                time.sleep(5)
        if (
            not public_signaling_addresses
            or sip_addresses != public_signaling_addresses
        ):
            raise LiveTestError(
                "public SIP DNS does not resolve to the HA signaling NLB"
            )
        certificate_arn = runtime["PublicCertificateArn"]
        profile_checks = {
            "ha_four_services_stable": True,
            "ha_four_slots_hardened": True,
            "ha_gateway_eips_reconciled": True,
            "ha_targets_healthy": True,
            "ha_postgres_and_valkey_ready": True,
            "ha_dns_matches_signaling_nlb": True,
        }
    certificate_verified = ledger.get("sip_security") != "sip_rtp"
    if certificate_verified:
        certificate = aws_json(
            [
                "acm",
                "describe-certificate",
                "--region",
                ledger["region"],
                "--certificate-arn",
                certificate_arn,
            ],
            env=env,
        )["Certificate"]
        if certificate["Status"] != "ISSUED":
            raise LiveTestError("SIPS certificate issuance gate failed")
    vapi_api_key = secret_value(ledger, env, ledger["vapi_api_key_secret_arn"])
    verify_bound_vapi_resources(ledger, vapi_api_key, handoff)
    recipe_fingerprint = runtime_recipe_fingerprint(
        ledger,
        env,
        runtime_instance_ids,
    )
    evidence = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "recipe": RECIPE,
        "runtime_profile": runtime_profile,
        "release_id": ledger["release_id"],
        "image_digest": ledger["bridgefu_image_uri"].rsplit("@", 1)[-1],
        "recipe_fingerprint": recipe_fingerprint,
        "verified_at": utc_now(),
        "checks": {
            "stack_ready": True,
            "prepare_idempotent": True,
            "opaque_correlation_contract": True,
            "fixed_sip_destination": True,
            "exact_single_correlation_header": True,
            "connect_lookup_flat_map": True,
            "no_ssh_and_imdsv2": True,
            "encrypted_volumes": True,
            **certificate_evidence_checks(ledger.get("sip_security", "sips_srtp")),
            "vapi_assistant_exists": True,
            "vapi_prepare_tool_exists": True,
            "vapi_webhook_credential_exists": True,
            "optional_demo_site_public_contract": True,
            **profile_checks,
        },
        "prepare_transfer_elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        "customer_data_retained": False,
    }
    atomic_json(path.parent / "qualification-evidence.json", evidence)
    ledger["status"] = "verified"
    record(path, ledger, "structural_and_contract_qualification_passed")
    print(path.parent / "qualification-evidence.json")


def reviewed_update_change_set(
    path: Path,
    ledger: dict[str, Any],
    env: dict[str, str],
    stack: dict[str, Any],
    *,
    name: str,
    description: str,
    overrides: dict[str, str],
    evidence_path: Path,
    ledger_prefix: str,
    attempt: int,
) -> dict[str, Any]:
    arn_field = f"{ledger_prefix}_change_set_arn"
    name_field = f"{ledger_prefix}_change_set_name"
    application_stack_id = reviewed_create_stack_id(ledger, qualification=False)
    recorded_arn = ledger.get(arn_field)
    if recorded_arn is not None:
        if ledger.get(name_field) != name or not isinstance(recorded_arn, str):
            raise LiveTestError("recorded lifecycle change-set identity changed")
        result = {
            "Id": require_change_set_id_authority(
                ledger,
                recorded_arn,
                "recorded lifecycle change set",
                expected_name=name,
            )
        }
    else:
        require_qualification_deadline(path, ledger, "lifecycle change-set review")
        result = aws_json(
            [
                "cloudformation",
                "create-change-set",
                "--region",
                ledger["region"],
                "--stack-name",
                application_stack_id,
                "--change-set-name",
                name,
                "--change-set-type",
                "UPDATE",
                "--description",
                description,
                "--use-previous-template",
                "--parameters",
                *previous_parameter_arguments(stack, overrides),
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
                "--include-nested-stacks",
                "--client-token",
                f"{ledger['execution_id']}-{ledger_prefix}-r{attempt}",
                "--tags",
                *tag_arguments(ledger["execution_id"]),
            ],
            env=env,
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("Id"), str)
            or result.get("StackId") != application_stack_id
        ):
            raise LiveTestError("lifecycle change-set request returned no exact ARN")
        require_change_set_id_authority(
            ledger,
            result["Id"],
            "lifecycle change set",
            expected_name=name,
        )
        ledger[arn_field] = result["Id"]
        ledger[name_field] = name
        record(path, ledger, f"{ledger_prefix}_change_set_requested")
    require_change_set_id_authority(
        ledger,
        result["Id"],
        "lifecycle change set",
        expected_name=name,
    )
    aws_wait(
        [
            "cloudformation",
            "wait",
            "change-set-create-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            application_stack_id,
            "--change-set-name",
            result["Id"],
        ],
        env=env,
    )
    signed_templates = signed_cloudformation_template_hashes(path)
    root_template_name = (
        "demo-template.yaml"
        if ledger.get("connect_mode") == "disposable"
        else "template.yaml"
    )
    change_set, changes = review_change_set_tree(
        ledger,
        env,
        result["Id"],
        expected_action="Modify",
        allowed_template_sha256=set(signed_templates.values()),
        expected_root_template_sha256=signed_templates[
            f"recipe/cloudformation/{root_template_name}"
        ],
    )
    live_stack = stack_description(ledger, env, application_stack_id)
    if (
        change_set.get("ChangeSetId") != result["Id"]
        or change_set.get("ChangeSetName") != name
        or change_set.get("StackId") != application_stack_id
        or change_set.get("StackName") != ledger["stack_name"]
        or change_set.get("Description") != description
        or change_set.get("ExecutionStatus") != "AVAILABLE"
        or change_set.get("IncludeNestedStacks") is not True
        or live_stack.get("RoleARN") != ledger.get("cloudformation_execution_role_arn")
    ):
        raise LiveTestError("lifecycle change set violates its review contract")
    template = (
        path.parent / "release" / "recipe" / "cloudformation" / root_template_name
    )
    evidence = {
        "change_set_id": change_set["ChangeSetId"],
        "change_set_name": name,
        "stack_id": application_stack_id,
        "status": change_set["Status"],
        "execution_status": change_set["ExecutionStatus"],
        "description": description,
        "cloudformation_role_arn": live_stack["RoleARN"],
        "release_id": ledger["release_id"],
        "template_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
        "parameters_sha256": change_set_parameters_sha256(change_set),
        "nested_change_set_count": sum(
            entry["resource_type"] == "AWS::CloudFormation::Stack" for entry in changes
        ),
        "changes": changes,
        "reviewed_at": utc_now(),
    }
    atomic_json(evidence_path, evidence)
    ledger[f"{ledger_prefix}_review_sha256"] = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()
    record(path, ledger, f"{ledger_prefix}_change_set_review_evidence_bound")
    return {"id": result["Id"], "name": name, "changes": changes}


def validate_reviewed_update_for_execution(
    path: Path,
    ledger: dict[str, Any],
    env: dict[str, str],
    change_set: dict[str, Any],
    *,
    evidence_path: Path,
    ledger_prefix: str,
) -> str:
    application_stack_id = reviewed_create_stack_id(ledger, qualification=False)
    expected_digest = ledger.get(f"{ledger_prefix}_review_sha256")
    if (
        not evidence_path.is_file()
        or hashlib.sha256(evidence_path.read_bytes()).hexdigest() != expected_digest
    ):
        raise LiveTestError("lifecycle review evidence is missing or changed")
    try:
        evidence = json.loads(evidence_path.read_text())
    except json.JSONDecodeError as error:
        raise LiveTestError("lifecycle review evidence is invalid JSON") from error
    if change_set.get("id") != ledger.get(
        f"{ledger_prefix}_change_set_arn"
    ) or change_set.get("name") != ledger.get(f"{ledger_prefix}_change_set_name"):
        raise LiveTestError("lifecycle execution identity differs from the ledger")
    change_set_id = require_change_set_id_authority(
        ledger,
        change_set.get("id"),
        "reviewed lifecycle change set",
        expected_name=change_set.get("name"),
    )
    signed_templates = signed_cloudformation_template_hashes(path)
    root_template_name = (
        "demo-template.yaml"
        if ledger.get("connect_mode") == "disposable"
        else "template.yaml"
    )
    description, changes = review_change_set_tree(
        ledger,
        env,
        change_set_id,
        expected_action="Modify",
        allowed_template_sha256=set(signed_templates.values()),
        expected_root_template_sha256=signed_templates[
            f"recipe/cloudformation/{root_template_name}"
        ],
    )
    stack = stack_description(ledger, env, application_stack_id)
    template = (
        path.parent / "release" / "recipe" / "cloudformation" / root_template_name
    )
    if (
        evidence.get("change_set_id") != change_set["id"]
        or evidence.get("change_set_name") != change_set["name"]
        or evidence.get("stack_id") != application_stack_id
        or evidence.get("status") != "CREATE_COMPLETE"
        or evidence.get("execution_status") != "AVAILABLE"
        or evidence.get("description") != description.get("Description")
        or evidence.get("cloudformation_role_arn")
        != ledger.get("cloudformation_execution_role_arn")
        or evidence.get("release_id") != ledger.get("release_id")
        or evidence.get("template_sha256")
        != hashlib.sha256(template.read_bytes()).hexdigest()
        or evidence.get("parameters_sha256")
        != change_set_parameters_sha256(description)
        or evidence.get("changes") != changes
        or description.get("ChangeSetId") != change_set["id"]
        or description.get("ChangeSetName") != change_set["name"]
        or description.get("StackId") != application_stack_id
        or description.get("StackName") != ledger["stack_name"]
        or description.get("IncludeNestedStacks") is not True
        or description.get("ExecutionStatus")
        not in {"AVAILABLE", "EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE"}
        or stack.get("RoleARN") != ledger.get("cloudformation_execution_role_arn")
    ):
        raise LiveTestError(
            "live lifecycle change set no longer matches its exact review evidence"
        )
    return str(description["ExecutionStatus"])


def execute_reviewed_update(
    path: Path,
    ledger: dict[str, Any],
    env: dict[str, str],
    change_set: dict[str, Any],
    *,
    evidence_path: Path,
    ledger_prefix: str,
    token_suffix: str,
    attempt: int,
) -> bool:
    application_stack_id = reviewed_create_stack_id(ledger, qualification=False)
    execution_status = validate_reviewed_update_for_execution(
        path,
        ledger,
        env,
        change_set,
        evidence_path=evidence_path,
        ledger_prefix=ledger_prefix,
    )
    if execution_status in {"EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE"}:
        return False
    require_qualification_deadline(path, ledger, "lifecycle stack execution")
    identity_digest = hashlib.sha256(change_set["id"].encode()).hexdigest()[:12]
    aws_json(
        [
            "cloudformation",
            "execute-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            application_stack_id,
            "--change-set-name",
            change_set["id"],
            "--client-request-token",
            (
                f"{ledger['execution_id']}-{token_suffix}-r{attempt}-"
                f"{identity_digest}"
            ),
        ],
        env=env,
    )
    return True


def lifecycle_test(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    resumable_statuses = {
        "verified",
        "lifecycle_verified",
        "updating",
        "updated",
        "rollback_drill",
    }
    if ledger.get("status") not in resumable_statuses:
        raise LiveTestError("lifecycle-test requires a verified deployment")
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    evidence_path = path.parent / "lifecycle-evidence.json"
    if ledger.get("lifecycle_test_passed"):
        if not evidence_path.is_file():
            raise LiveTestError("completed lifecycle evidence is missing")
        print(evidence_path)
        return

    require_qualification_deadline(path, ledger, "lifecycle test")
    env = assume_env(ledger, "deployment")
    validate_candidate_release(path, ledger, env)
    application_stack_id = reviewed_create_stack_id(ledger, qualification=False)
    stack = stack_description(ledger, env, application_stack_id)
    parameters = {
        item["ParameterKey"]: item.get("ParameterValue", "")
        for item in stack.get("Parameters", [])
    }
    phase = ledger.get("lifecycle_phase")
    if phase is None:
        if stack.get("StackStatus") not in {
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_COMPLETE",
        }:
            raise LiveTestError("lifecycle-test requires a stable root stack")
        attempt = int(ledger.get("lifecycle_attempt", 0)) + 1
        if attempt > 9:
            raise LiveTestError("lifecycle-test exceeded its bounded retry count")
        try:
            original_ttl = int(parameters["ContextTtlSeconds"])
        except (KeyError, ValueError) as error:
            raise LiveTestError(
                "root stack has no valid context TTL parameter"
            ) from error
        updated_ttl = original_ttl + 1 if original_ttl < 86_400 else original_ttl - 1
        if not 300 <= updated_ttl <= 86_400:
            raise LiveTestError("unable to select a bounded lifecycle test TTL")
        ledger.update(
            {
                "lifecycle_attempt": attempt,
                "lifecycle_original_ttl": original_ttl,
                "lifecycle_updated_ttl": updated_ttl,
                "lifecycle_phase": "update_review",
            }
        )
        record(path, ledger, "lifecycle_attempt_started", attempt=attempt)
        phase = "update_review"
    else:
        attempt = ledger.get("lifecycle_attempt")
        original_ttl = ledger.get("lifecycle_original_ttl")
        updated_ttl = ledger.get("lifecycle_updated_ttl")
        if (
            phase == "complete"
            or not isinstance(attempt, int)
            or not 1 <= attempt <= 9
            or not isinstance(original_ttl, int)
            or not isinstance(updated_ttl, int)
        ):
            raise LiveTestError("recorded lifecycle retry state is invalid")

    update_phases = {
        "update_review",
        "update_reviewed",
        "update_execution_prepared",
        "update_executing",
    }
    if phase in update_phases:
        update_name = f"lifecycle-update-{ledger['execution_id']}-r{attempt}"
        update_review_path = path.parent / "update-change-set-review.json"
        if ledger.get("lifecycle_update_review_sha256"):
            update = {
                "id": ledger.get("lifecycle_update_change_set_arn"),
                "name": ledger.get("lifecycle_update_change_set_name"),
            }
        else:
            update = reviewed_update_change_set(
                path,
                ledger,
                env,
                stack,
                name=update_name,
                description=(
                    f"Bridgefu qualification safe update {ledger['execution_id']}"
                ),
                overrides={"ContextTtlSeconds": str(updated_ttl)},
                evidence_path=update_review_path,
                ledger_prefix="lifecycle_update",
                attempt=attempt,
            )
            ledger["lifecycle_phase"] = "update_reviewed"
            record(path, ledger, "lifecycle_update_change_set_reviewed")
        if not ledger.get("lifecycle_update_started_at"):
            ledger["lifecycle_update_started_at"] = utc_now()
            ledger["lifecycle_phase"] = "update_execution_prepared"
            record(path, ledger, "lifecycle_update_execution_prepared")
        executed = execute_reviewed_update(
            path,
            ledger,
            env,
            update,
            evidence_path=update_review_path,
            ledger_prefix="lifecycle_update",
            token_suffix="safe-update",
            attempt=attempt,
        )
        ledger["status"] = "updating"
        ledger["lifecycle_phase"] = "update_executing"
        record(
            path,
            ledger,
            (
                "lifecycle_update_executed"
                if executed
                else "lifecycle_update_reconciled"
            ),
        )
        aws_wait(
            [
                "cloudformation",
                "wait",
                "stack-update-complete",
                "--region",
                ledger["region"],
                "--stack-name",
                application_stack_id,
            ],
            env=env,
        )
        updated_stack = stack_description(ledger, env, application_stack_id)
        updated_parameters = {
            item["ParameterKey"]: item.get("ParameterValue", "")
            for item in updated_stack.get("Parameters", [])
        }
        if updated_stack.get(
            "StackStatus"
        ) != "UPDATE_COMPLETE" or updated_parameters.get("ContextTtlSeconds") != str(
            updated_ttl
        ):
            raise LiveTestError("safe lifecycle update did not converge")
        expected_lookup_version = ledger["published_objects"][
            "artifacts/lambda/connect_lookup.zip"
        ]["version_id"]
        valid_lookup_version = updated_parameters.get("LookupArtifactVersion", "")
        if valid_lookup_version != expected_lookup_version:
            raise LiveTestError("deployed lookup artifact is not the published version")
        update_started = dt.datetime.fromisoformat(
            str(ledger["lifecycle_update_started_at"]).replace("Z", "+00:00")
        )
        update_seconds = round(
            max(
                0.0,
                (dt.datetime.now(dt.timezone.utc) - update_started).total_seconds(),
            ),
            3,
        )
        ledger.update(
            {
                "status": "updated",
                "lifecycle_phase": "update_complete",
                "lifecycle_update_seconds": update_seconds,
                "lifecycle_valid_lookup_version": valid_lookup_version,
            }
        )
        record(
            path,
            ledger,
            "lifecycle_update_passed",
            elapsed_seconds=update_seconds,
        )
        phase = "update_complete"
        stack = updated_stack
    else:
        update_seconds = ledger.get("lifecycle_update_seconds")
        valid_lookup_version = ledger.get("lifecycle_valid_lookup_version")
        if (
            not isinstance(update_seconds, (int, float))
            or isinstance(update_seconds, bool)
            or update_seconds < 0
            or not isinstance(valid_lookup_version, str)
            or not valid_lookup_version
        ):
            raise LiveTestError("completed lifecycle update evidence is invalid")

    rollback_name = f"lifecycle-rollback-{ledger['execution_id']}-r{attempt}"
    rollback_review_path = path.parent / "rollback-change-set-review.json"
    if ledger.get("lifecycle_rollback_review_sha256"):
        rollback = {
            "id": ledger.get("lifecycle_rollback_change_set_arn"),
            "name": ledger.get("lifecycle_rollback_change_set_name"),
        }
    else:
        current = stack_description(ledger, env, application_stack_id)
        if current.get("StackStatus") != "UPDATE_COMPLETE":
            raise LiveTestError("rollback review requires the completed safe update")
        rollback = reviewed_update_change_set(
            path,
            ledger,
            env,
            current,
            name=rollback_name,
            description=(
                f"Bridgefu qualification intentional rollback {ledger['execution_id']}"
            ),
            overrides={
                "LookupArtifactVersion": f"intentional-invalid-{ledger['execution_id']}"
            },
            evidence_path=rollback_review_path,
            ledger_prefix="lifecycle_rollback",
            attempt=attempt,
        )
        ledger["lifecycle_phase"] = "rollback_reviewed"
        record(path, ledger, "lifecycle_rollback_change_set_reviewed")
    if not ledger.get("lifecycle_rollback_started_at"):
        ledger["lifecycle_rollback_started_at"] = utc_now()
        ledger["lifecycle_phase"] = "rollback_execution_prepared"
        record(path, ledger, "lifecycle_rollback_execution_prepared")
    rollback_executed = execute_reviewed_update(
        path,
        ledger,
        env,
        rollback,
        evidence_path=rollback_review_path,
        ledger_prefix="lifecycle_rollback",
        token_suffix="rollback-drill",
        attempt=attempt,
    )
    ledger["status"] = "rollback_drill"
    ledger["lifecycle_phase"] = "rollback_executing"
    record(
        path,
        ledger,
        (
            "lifecycle_rollback_drill_executed"
            if rollback_executed
            else "lifecycle_rollback_drill_reconciled"
        ),
    )
    aws_wait(
        [
            "cloudformation",
            "wait",
            "stack-update-rollback-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            application_stack_id,
        ],
        env=env,
    )
    restored_stack = stack_description(ledger, env, application_stack_id)
    restored_parameters = {
        item["ParameterKey"]: item.get("ParameterValue", "")
        for item in restored_stack.get("Parameters", [])
    }
    if (
        restored_stack.get("StackStatus") != "UPDATE_ROLLBACK_COMPLETE"
        or restored_parameters.get("LookupArtifactVersion") != valid_lookup_version
        or restored_parameters.get("ContextTtlSeconds") != str(updated_ttl)
    ):
        ledger["status"] = "rollback_incomplete"
        record(path, ledger, "lifecycle_rollback_incomplete")
        raise LiveTestError("intentional update did not roll back to the working stack")
    rollback_started = dt.datetime.fromisoformat(
        str(ledger["lifecycle_rollback_started_at"]).replace("Z", "+00:00")
    )
    rollback_seconds = round(
        max(
            0.0,
            (dt.datetime.now(dt.timezone.utc) - rollback_started).total_seconds(),
        ),
        3,
    )
    evidence = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "recipe": RECIPE,
        "release_id": ledger["release_id"],
        "safe_update": {
            "reviewed_modify_only": True,
            "completed": True,
            "elapsed_seconds": update_seconds,
        },
        "intentional_failure": {
            "reviewed_modify_only": True,
            "rollback_complete": True,
            "working_artifact_restored": True,
            "elapsed_seconds": rollback_seconds,
        },
        "recorded_at": utc_now(),
        "redacted": True,
        "customer_data_retained": False,
    }
    atomic_json(evidence_path, evidence)
    ledger.update(
        {
            "lifecycle_test_passed": True,
            "lifecycle_phase": "complete",
            "lifecycle_rollback_seconds": rollback_seconds,
            "status": "lifecycle_verified",
        }
    )
    record(
        path,
        ledger,
        "cloudformation_update_and_rollback_passed",
        update_seconds=update_seconds,
        rollback_seconds=rollback_seconds,
    )
    print(evidence_path)


def empty_versioned_bucket(ledger: dict[str, Any], env: dict[str, str]) -> None:
    previous_batch: str | None = None
    unchanged_rounds = 0
    for _attempt in range(200):
        listing = aws_json(
            [
                "s3api",
                "list-object-versions",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--max-items",
                "1000",
                "--expected-bucket-owner",
                ledger["account_id"],
            ],
            env=env,
        )
        if not isinstance(listing, dict):
            raise LiveTestError("versioned bucket listing returned an invalid result")
        entries = [
            {"Key": value["Key"], "VersionId": value["VersionId"]}
            for group in ("Versions", "DeleteMarkers")
            for value in listing.get(group, [])
        ]
        if not entries:
            return
        batch = canonical_json_sha256(entries)
        unchanged_rounds = unchanged_rounds + 1 if batch == previous_batch else 0
        if unchanged_rounds >= 3:
            raise LiveTestError(
                "versioned bucket deletion made no progress for three rounds"
            )
        previous_batch = batch
        result = aws_json(
            [
                "s3api",
                "delete-objects",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--expected-bucket-owner",
                ledger["account_id"],
                "--delete",
                json.dumps({"Objects": entries, "Quiet": True}),
            ],
            env=env,
        )
        # DeleteObjects quiet mode deliberately has no response body when every
        # requested deletion succeeds. Treat that as provisional success only:
        # the next list-object-versions call must still prove the bucket empty.
        if result is None:
            continue
        if not isinstance(result, dict):
            raise LiveTestError("versioned bucket deletion returned an invalid result")
        if set(result) - {"Errors"}:
            raise LiveTestError("versioned bucket deletion returned an invalid result")
        errors = result.get("Errors", [])
        if not isinstance(errors, list) or errors:
            raise LiveTestError("versioned bucket deletion reported object errors")
    raise LiveTestError("versioned bucket deletion exceeded its bounded rounds")


def request_secret_force_delete(
    ledger: dict[str, Any],
    environment: dict[str, str],
    secret_arn: str,
    *,
    label: str,
) -> bool:
    result = command(
        [
            "aws",
            "secretsmanager",
            "describe-secret",
            "--region",
            ledger["region"],
            "--secret-id",
            secret_arn,
            "--output",
            "json",
            "--no-cli-pager",
        ],
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        if "ResourceNotFoundException" in (result.stderr or ""):
            return False
        raise LiveTestError(f"unable to inspect the exact {label}")
    try:
        description = json.loads(result.stdout or "")
    except json.JSONDecodeError as error:
        raise LiveTestError(f"exact {label} description is invalid JSON") from error
    if not isinstance(description, dict) or description.get("ARN") != secret_arn:
        raise LiveTestError(f"exact {label} identity changed")
    require_ownership_tags(description.get("Tags", []), ledger["execution_id"])
    if description.get("DeletedDate") is not None:
        return False
    exact_delete(
        [
            "secretsmanager",
            "delete-secret",
            "--region",
            ledger["region"],
            "--secret-id",
            secret_arn,
            "--force-delete-without-recovery",
        ],
        environment=environment,
        absent_markers=("ResourceNotFoundException",),
        label=label,
    )
    return True


def ec2_instance_is_tombstone(region: str, instance_id: str) -> bool:
    """Return true only when EC2 proves an indexed instance is already gone."""
    probe = command(
        [
            "aws",
            "ec2",
            "describe-instances",
            "--region",
            region,
            "--instance-ids",
            instance_id,
            "--no-cli-pager",
        ],
        check=False,
    )
    if probe.returncode != 0:
        return "InvalidInstanceID.NotFound" in (probe.stderr or "")
    try:
        document = json.loads(probe.stdout)
    except (TypeError, json.JSONDecodeError):
        return False
    states = [
        instance.get("State", {}).get("Name")
        for reservation in document.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]
    # Resource Groups Tagging can retain an ARN briefly after EC2 no longer
    # returns the instance. An exact successful lookup with no reservations is
    # therefore also authoritative absence, not an owned live resource.
    return not states or states == ["terminated"]


def ec2_nat_gateway_is_tombstone(region: str, nat_gateway_id: str) -> bool:
    """Return true only when EC2 proves an indexed NAT gateway is deleted."""
    probe = command(
        [
            "aws",
            "ec2",
            "describe-nat-gateways",
            "--region",
            region,
            "--nat-gateway-ids",
            nat_gateway_id,
            "--no-cli-pager",
        ],
        check=False,
    )
    if probe.returncode != 0:
        return False
    try:
        document = json.loads(probe.stdout)
    except (TypeError, json.JSONDecodeError):
        return False
    states = [gateway.get("State") for gateway in document.get("NatGateways", [])]
    return not states or states == ["deleted"]


def exact_probe_exists(
    arguments: list[str],
    *,
    absent_markers: tuple[str, ...],
    label: str,
    environment: dict[str, str] | None = None,
) -> bool:
    probe = command(
        ["aws", *arguments, "--no-cli-pager"],
        env=environment,
        check=False,
    )
    if probe.returncode == 0:
        return True
    detail = probe.stderr or ""
    if any(marker in detail for marker in absent_markers):
        return False
    raise LiveTestError(f"unable to prove whether the exact {label} exists")


def exact_delete(
    arguments: list[str],
    *,
    environment: dict[str, str],
    absent_markers: tuple[str, ...],
    label: str,
) -> bool:
    result = command(
        ["aws", *arguments, "--output", "json", "--no-cli-pager"],
        env=environment,
        check=False,
    )
    if result.returncode == 0:
        return True
    detail = result.stderr or ""
    if any(marker in detail for marker in absent_markers):
        return False
    raise LiveTestError(f"exact {label} deletion failed")


def application_execution_was_attempted(ledger: dict[str, Any]) -> bool:
    events = ledger.get("events", [])
    if not isinstance(events, list):
        raise LiveTestError("qualification event ledger is invalid")
    attempt_events = {
        "change_set_execution_requested",
        "change_set_executed",
        "change_set_execution_reconciled",
        "deployment_wait_interrupted",
        "deployment_failed",
        "deployment_wait_completion_reconciled",
        "stack_ready",
    }
    return any(
        isinstance(item, dict) and item.get("event") in attempt_events
        for item in events
    )


def application_execution_acceptance_was_recorded(ledger: dict[str, Any]) -> bool:
    events = ledger.get("events", [])
    if not isinstance(events, list):
        raise LiveTestError("qualification event ledger is invalid")
    accepted_events = {
        "change_set_executed",
        "change_set_execution_reconciled",
        "deployment_wait_interrupted",
        "deployment_failed",
        "deployment_wait_completion_reconciled",
        "stack_ready",
    }
    return any(
        isinstance(item, dict) and item.get("event") in accepted_events
        for item in events
    )


def reviewed_application_change_set_is_still_available(
    ledger: dict[str, Any],
    environment: dict[str, str],
    root_stack_id: str,
) -> bool:
    """Close the ExecuteChangeSet/ledger crash gap for a REVIEW shell."""
    root_stack_id = require_stack_id_for_name(
        ledger,
        root_stack_id,
        ledger["stack_name"],
        "application review",
    )
    change_set_id = ledger.get("change_set_arn")
    change_set_name = ledger.get("change_set_name")
    if (
        not isinstance(change_set_id, str)
        or not change_set_id.startswith("arn:")
        or not isinstance(change_set_name, str)
        or not change_set_name
    ):
        raise LiveTestError("application review has no exact change-set binding")
    change_set_id = require_change_set_id_authority(
        ledger,
        change_set_id,
        "application review",
        expected_name=change_set_name,
    )
    description = aws_json(
        [
            "cloudformation",
            "describe-change-set",
            "--region",
            ledger["region"],
            "--stack-name",
            root_stack_id,
            "--change-set-name",
            change_set_id,
        ],
        env=environment,
    )
    if (
        description.get("ChangeSetId") != change_set_id
        or description.get("ChangeSetName") != change_set_name
        or description.get("StackId") != root_stack_id
        or description.get("StackName") != ledger["stack_name"]
        or description.get("ChangeSetType") != "CREATE"
    ):
        raise LiveTestError("application review change-set identity changed")
    return (
        description.get("Status") == "CREATE_COMPLETE"
        and description.get("ExecutionStatus") == "AVAILABLE"
    )


def application_review_is_authoritatively_unexecuted(
    ledger: dict[str, Any],
    environment: dict[str, str],
    root_stack_id: str,
) -> bool:
    if application_execution_acceptance_was_recorded(ledger):
        return False
    if not reviewed_application_change_set_is_still_available(
        ledger, environment, root_stack_id
    ):
        return False
    reread = stack_description(ledger, environment, root_stack_id)
    return (
        reread.get("StackId") == root_stack_id
        and reread.get("StackStatus") == "REVIEW_IN_PROGRESS"
    )


def inventory_headless_build_ids(ledger: dict[str, Any]) -> list[str]:
    project_name = ledger.get("qualification_project_name")
    known_ids = known_headless_build_ids(ledger)
    listed_ids: list[str] = []
    if project_name is not None:
        if not isinstance(project_name, str) or not project_name:
            raise LiveTestError("qualification project name is invalid")
        result = command(
            [
                "aws",
                "codebuild",
                "list-builds-for-project",
                "--region",
                ledger["region"],
                "--project-name",
                project_name,
                "--sort-order",
                "DESCENDING",
                "--output",
                "json",
                "--no-cli-pager",
            ],
            check=False,
        )
        if result.returncode != 0:
            if "ResourceNotFoundException" not in (result.stderr or ""):
                raise LiveTestError("unable to inventory the exact CodeBuild project")
        else:
            try:
                listing = json.loads(result.stdout or "")
            except json.JSONDecodeError as error:
                raise LiveTestError(
                    "CodeBuild inventory returned invalid JSON"
                ) from error
            if (
                not isinstance(listing, dict)
                or listing.get("nextToken") is not None
                or not isinstance(listing.get("ids"), list)
                or len(listing["ids"]) > 100
                or len(listing["ids"]) != len(set(listing["ids"]))
                or any(
                    not headless_build_id_is_valid(ledger, build_id)
                    for build_id in listing["ids"]
                )
            ):
                raise LiveTestError("CodeBuild inventory is invalid or unbounded")
            listed_ids = listing["ids"]
    build_ids = list(dict.fromkeys([*listed_ids, *known_ids]))
    if len(build_ids) > 106:
        raise LiveTestError("CodeBuild inventory exceeds its build bound")
    active: list[str] = []
    for offset in range(0, len(build_ids), 100):
        batch = build_ids[offset : offset + 100]
        response = aws_json(
            [
                "codebuild",
                "batch-get-builds",
                "--region",
                ledger["region"],
                "--ids",
                *batch,
            ]
        )
        if not isinstance(response, dict) or not isinstance(
            response.get("builds"), list
        ):
            raise LiveTestError("CodeBuild inventory details are invalid")
        missing = response.get("buildsNotFound", [])
        if (
            not isinstance(missing, list)
            or any(item not in batch for item in missing)
            or len(missing) != len(set(missing))
        ):
            raise LiveTestError("CodeBuild missing-build inventory is invalid")
        observed: set[str] = set()
        for build in response["builds"]:
            build_id = build.get("id") if isinstance(build, dict) else None
            if (
                not headless_build_id_is_valid(ledger, build_id)
                or build_id not in batch
                or build_id in observed
                or build.get("projectName") != project_name
                or build.get("buildStatus") not in CODEBUILD_STATUSES
            ):
                raise LiveTestError("CodeBuild build inventory violates its binding")
            observed.add(build_id)
            if build["buildStatus"] not in CODEBUILD_TERMINAL_STATUSES:
                active.append(build_id)
        if observed | set(missing) != set(batch):
            raise LiveTestError("CodeBuild inventory omitted a requested build")
    return sorted(active)


def inventory_for_execution(ledger: dict[str, Any]) -> dict[str, Any]:
    bind_active_ledger_identity(ledger)
    execution_id = ledger["execution_id"]
    region = ledger["region"]
    tagged = aws_json(
        [
            "resourcegroupstaggingapi",
            "get-resources",
            "--region",
            region,
            "--tag-filters",
            f"Key=BridgefuExecutionId,Values={execution_id}",
        ],
    )
    if not isinstance(tagged, dict) or not isinstance(
        tagged.get("ResourceTagMappingList"), list
    ):
        raise LiveTestError("tagged-resource inventory returned an invalid result")
    stacks = aws_json(
        [
            "cloudformation",
            "list-stacks",
            "--region",
            region,
            "--stack-status-filter",
            "CREATE_IN_PROGRESS",
            "CREATE_FAILED",
            "CREATE_COMPLETE",
            "ROLLBACK_IN_PROGRESS",
            "ROLLBACK_FAILED",
            "ROLLBACK_COMPLETE",
            "DELETE_IN_PROGRESS",
            "DELETE_FAILED",
            "UPDATE_IN_PROGRESS",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_IN_PROGRESS",
            "UPDATE_ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "REVIEW_IN_PROGRESS",
        ],
    )
    if not isinstance(stacks, dict) or not isinstance(
        stacks.get("StackSummaries"), list
    ):
        raise LiveTestError("CloudFormation inventory returned an invalid result")
    matching_stacks = [
        stack
        for stack in stacks.get("StackSummaries", [])
        if execution_id in stack.get("StackName", "")
    ]
    names = [
        stack["StackName"]
        for stack in matching_stacks
        if stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
    ]
    review_stack_ids = [
        stack.get("StackId", stack["StackName"])
        for stack in matching_stacks
        if stack.get("StackStatus") == "REVIEW_IN_PROGRESS"
    ]
    roles = aws_json(["iam", "list-roles"])
    role_names = [
        role["RoleName"]
        for role in roles.get("Roles", [])
        if execution_id in role["RoleName"]
    ]
    policies = aws_json(["iam", "list-policies", "--scope", "Local"])
    policy_arns = [
        policy["Arn"]
        for policy in policies.get("Policies", [])
        if execution_id in policy.get("PolicyName", "")
    ]
    connect_logs = aws_json(
        [
            "logs",
            "describe-log-groups",
            "--region",
            region,
            "--log-group-name-prefix",
            f"/aws/connect/{execution_id}",
        ],
    )
    connect_log_group_names = [
        group["logGroupName"]
        for group in connect_logs.get("logGroups", [])
        if group.get("logGroupName") == f"/aws/connect/{execution_id}-connect"
    ]
    demo_bucket = ledger.get(
        "demo_site_bucket",
        f"bfu-{ledger['account_id']}-{region}-{execution_id}-site",
    )
    demo_bucket_exists = exact_probe_exists(
        [
            "s3api",
            "head-bucket",
            "--region",
            region,
            "--bucket",
            demo_bucket,
            "--expected-bucket-owner",
            ledger["account_id"],
        ],
        absent_markers=("(404)", "Not Found", "NoSuchBucket"),
        label="demo-site bucket",
    )
    artifact_bucket_names: list[str] = []
    if ledger.get("artifact_bucket") and exact_probe_exists(
        [
            "s3api",
            "head-bucket",
            "--region",
            region,
            "--bucket",
            ledger["artifact_bucket"],
            "--expected-bucket-owner",
            ledger["account_id"],
        ],
        absent_markers=("(404)", "Not Found", "NoSuchBucket"),
        label="artifact bucket",
    ):
        artifact_bucket_names.append(ledger["artifact_bucket"])
    ecr_repository_names: list[str] = []
    if ledger.get("ecr_repository") and exact_probe_exists(
        [
            "ecr",
            "describe-repositories",
            "--region",
            region,
            "--registry-id",
            ledger["account_id"],
            "--repository-names",
            ledger["ecr_repository"],
        ],
        absent_markers=("RepositoryNotFoundException",),
        label="ECR repository",
    ):
        ecr_repository_names.append(ledger["ecr_repository"])
    distributions = aws_json(["cloudfront", "list-distributions"])
    cloudfront_distributions = [
        item["Id"]
        for item in distributions.get("DistributionList", {}).get("Items", [])
        if execution_id in item.get("Comment", "")
    ]
    cache_policies = aws_json(["cloudfront", "list-cache-policies", "--type", "custom"])
    cloudfront_cache_policies = [
        item["CachePolicy"]["Id"]
        for item in cache_policies.get("CachePolicyList", {}).get("Items", [])
        if execution_id
        in item.get("CachePolicy", {}).get("CachePolicyConfig", {}).get("Name", "")
    ]
    response_policies = aws_json(
        ["cloudfront", "list-response-headers-policies", "--type", "custom"]
    )
    cloudfront_response_headers_policies = [
        item["ResponseHeadersPolicy"]["Id"]
        for item in response_policies.get("ResponseHeadersPolicyList", {}).get(
            "Items", []
        )
        if execution_id
        in item.get("ResponseHeadersPolicy", {})
        .get("ResponseHeadersPolicyConfig", {})
        .get("Name", "")
    ]
    origin_controls = aws_json(["cloudfront", "list-origin-access-controls"])
    cloudfront_origin_access_controls = [
        item["Id"]
        for item in origin_controls.get("OriginAccessControlList", {}).get("Items", [])
        if execution_id in item.get("OriginAccessControlConfig", {}).get("Name", "")
    ]
    private_tls_secret_arns: list[str] = []
    if ledger.get("private_tls_secret_arn"):
        if exact_probe_exists(
            [
                "secretsmanager",
                "describe-secret",
                "--region",
                region,
                "--secret-id",
                ledger["private_tls_secret_arn"],
            ],
            absent_markers=("ResourceNotFoundException",),
            label="private TLS secret",
        ):
            private_tls_secret_arns.append(ledger["private_tls_secret_arn"])
    temporary_secret_arns: list[str] = []
    for field in ("vapi_api_key_secret_arn", "vapi_public_key_secret_arn"):
        secret_arn = ledger.get(field)
        if secret_arn and exact_probe_exists(
            [
                "secretsmanager",
                "describe-secret",
                "--region",
                region,
                "--secret-id",
                secret_arn,
            ],
            absent_markers=("ResourceNotFoundException",),
            label="temporary Vapi secret",
        ):
            temporary_secret_arns.append(secret_arn)
    connect_instance_arns: list[str] = []
    if ledger.get("connect_mode") == "disposable":
        connect_arn = ledger.get("connect_instance_arn")
        if isinstance(connect_arn, str) and "/instance/" in connect_arn:
            instance_id = connect_arn.rsplit("/", 1)[-1]
            if instance_id != "unused" and exact_probe_exists(
                [
                    "connect",
                    "describe-instance",
                    "--region",
                    region,
                    "--instance-id",
                    instance_id,
                ],
                absent_markers=("ResourceNotFoundException",),
                label="disposable Connect instance",
            ):
                connect_instance_arns.append(connect_arn)
    elastic_ip_allocation_ids: list[str] = []
    allocation_id = ledger.get("qualification_source_eip_allocation_id")
    if isinstance(allocation_id, str) and exact_probe_exists(
        [
            "ec2",
            "describe-addresses",
            "--region",
            region,
            "--allocation-ids",
            allocation_id,
        ],
        absent_markers=("InvalidAllocationID.NotFound",),
        label="qualification source EIP",
    ):
        elastic_ip_allocation_ids.append(allocation_id)
    tagged_resource_arns: list[str] = []
    for item in tagged.get("ResourceTagMappingList", []):
        arn = item["ResourceARN"]
        connect_match = re.fullmatch(
            rf"arn:aws[-a-z0-9]*:connect:{re.escape(region)}:"
            rf"{re.escape(ledger['account_id'])}:instance/([A-Za-z0-9-]+)"
            r"(?:/.*)?",
            arn,
        )
        if connect_match:
            probe = command(
                [
                    "aws",
                    "connect",
                    "describe-instance",
                    "--region",
                    region,
                    "--instance-id",
                    connect_match.group(1),
                    "--no-cli-pager",
                ],
                check=False,
            )
            if probe.returncode != 0 and "ResourceNotFoundException" in (
                probe.stderr or ""
            ):
                continue
        instance_match = re.fullmatch(
            rf"arn:aws[-a-z0-9]*:ec2:{re.escape(region)}:"
            rf"{re.escape(ledger['account_id'])}:instance/(i-[0-9a-f]+)",
            arn,
        )
        if instance_match and ec2_instance_is_tombstone(
            region, instance_match.group(1)
        ):
            continue
        nat_gateway_match = re.fullmatch(
            rf"arn:aws[-a-z0-9]*:ec2:{re.escape(region)}:"
            rf"{re.escape(ledger['account_id'])}:natgateway/(nat-[0-9a-f]+)",
            arn,
        )
        if nat_gateway_match and ec2_nat_gateway_is_tombstone(
            region, nat_gateway_match.group(1)
        ):
            continue
        endpoint_match = re.fullmatch(
            rf"arn:aws[-a-z0-9]*:ec2:{re.escape(region)}:"
            rf"{re.escape(ledger['account_id'])}:vpc-endpoint/(vpce-[0-9a-f]+)",
            arn,
        )
        if endpoint_match:
            probe = command(
                [
                    "aws",
                    "ec2",
                    "describe-vpc-endpoints",
                    "--region",
                    region,
                    "--vpc-endpoint-ids",
                    endpoint_match.group(1),
                    "--no-cli-pager",
                ],
                check=False,
            )
            if probe.returncode != 0 and "InvalidVpcEndpointId.NotFound" in (
                probe.stderr or ""
            ):
                continue
        subnet_match = re.fullmatch(
            rf"arn:aws[-a-z0-9]*:ec2:{re.escape(region)}:"
            rf"{re.escape(ledger['account_id'])}:subnet/(subnet-[0-9a-f]+)",
            arn,
        )
        if subnet_match:
            probe = command(
                [
                    "aws",
                    "ec2",
                    "describe-subnets",
                    "--region",
                    region,
                    "--subnet-ids",
                    subnet_match.group(1),
                    "--no-cli-pager",
                ],
                check=False,
            )
            if probe.returncode != 0 and "InvalidSubnetID.NotFound" in (
                probe.stderr or ""
            ):
                continue
        volume_match = re.fullmatch(
            rf"arn:aws[-a-z0-9]*:ec2:{re.escape(region)}:"
            rf"{re.escape(ledger['account_id'])}:volume/(vol-[0-9a-f]+)",
            arn,
        )
        if volume_match:
            probe = command(
                [
                    "aws",
                    "ec2",
                    "describe-volumes",
                    "--region",
                    region,
                    "--volume-ids",
                    volume_match.group(1),
                    "--no-cli-pager",
                ],
                check=False,
            )
            if probe.returncode != 0 and "InvalidVolume.NotFound" in (
                probe.stderr or ""
            ):
                continue
        tagged_resource_arns.append(arn)
    active_codebuild_build_ids = inventory_headless_build_ids(ledger)
    vapi_bindings = bound_vapi_resource_ids(ledger)
    application_attempted = application_execution_was_attempted(ledger)
    vapi_mode = ledger.get("vapi_teardown_mode")
    vapi_proven_absent = cached_vapi_absence_proof_is_valid(
        ledger_path(execution_id), ledger
    )
    if not vapi_bindings and application_attempted:
        if vapi_mode == "not_created":
            vapi_resource_ids: list[dict[str, str]] = []
        elif vapi_mode == "owner_scan" and vapi_proven_absent:
            vapi_resource_ids = []
        else:
            raise LiveTestError(
                "an attempted application has no completed Vapi teardown proof"
            )
    else:
        vapi_resource_ids = [] if vapi_proven_absent else vapi_bindings
    return {
        "checked_at": utc_now(),
        "tagged_resource_arns": tagged_resource_arns,
        "active_stack_names": names,
        "review_stack_ids": review_stack_ids,
        "connect_log_group_names": connect_log_group_names,
        "iam_role_names": role_names,
        "iam_policy_arns": policy_arns,
        "demo_site_bucket_names": [demo_bucket] if demo_bucket_exists else [],
        "artifact_bucket_names": artifact_bucket_names,
        "ecr_repository_names": ecr_repository_names,
        "cloudfront_distribution_ids": cloudfront_distributions,
        "cloudfront_cache_policy_ids": cloudfront_cache_policies,
        "cloudfront_response_headers_policy_ids": cloudfront_response_headers_policies,
        "cloudfront_origin_access_control_ids": cloudfront_origin_access_controls,
        "private_tls_secret_arns": private_tls_secret_arns,
        "temporary_secret_arns": temporary_secret_arns,
        "connect_instance_arns": connect_instance_arns,
        "elastic_ip_allocation_ids": elastic_ip_allocation_ids,
        "active_codebuild_build_ids": active_codebuild_build_ids,
        "vapi_resource_ids": vapi_resource_ids,
    }


def inventory_has_leftovers(value: dict[str, Any]) -> bool:
    return any(
        value.get(key)
        for key in (
            "tagged_resource_arns",
            "active_stack_names",
            "review_stack_ids",
            "connect_log_group_names",
            "iam_role_names",
            "iam_policy_arns",
            "demo_site_bucket_names",
            "artifact_bucket_names",
            "ecr_repository_names",
            "cloudfront_distribution_ids",
            "cloudfront_cache_policy_ids",
            "cloudfront_response_headers_policy_ids",
            "cloudfront_origin_access_control_ids",
            "private_tls_secret_arns",
            "temporary_secret_arns",
            "connect_instance_arns",
            "elastic_ip_allocation_ids",
            "active_codebuild_build_ids",
            "vapi_resource_ids",
        )
    )


def recovery_review_directory(execution_id: str) -> Path:
    if EXECUTION_PATTERN.fullmatch(execution_id) is None:
        raise LiveTestError("execution ID cannot address a recovery review")
    return live_state_root() / ".recovery-reviews" / execution_id


def recovery_exact_string_map(
    items: Any, *, key_field: str, value_field: str, label: str
) -> dict[str, str]:
    if not isinstance(items, list):
        raise LiveTestError(f"{label} is not a list")
    result: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            raise LiveTestError(f"{label} contains a malformed entry")
        key = item.get(key_field)
        value = item.get(value_field)
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or key in result
        ):
            raise LiveTestError(f"{label} contains an invalid or duplicate key")
        result[key] = value
    return result


def recovery_stack_creation_time(value: Any) -> str:
    if not isinstance(value, str):
        raise LiveTestError("recovery bootstrap creation time is invalid")
    try:
        created = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LiveTestError("recovery bootstrap creation time is invalid") from error
    if created.tzinfo is None:
        raise LiveTestError("recovery bootstrap creation time has no timezone")
    created = created.astimezone(dt.timezone.utc)
    age = dt.datetime.now(dt.timezone.utc) - created
    if age < -dt.timedelta(minutes=5) or age > RECOVERY_STACK_HISTORY_MAX_AGE:
        raise LiveTestError(
            "recovery bootstrap is outside the complete CloudFormation history window"
        )
    return created.isoformat().replace("+00:00", "Z")


def recovery_paginated_items(
    arguments: list[str],
    *,
    list_key: str,
    response_token: str,
    request_token: str,
    environment: dict[str, str] | None = None,
    max_pages: int = 1_000,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    for _page in range(max_pages):
        page_arguments = [*arguments, "--no-paginate"]
        if token is not None:
            page_arguments.extend([request_token, token])
        response = aws_json(page_arguments, env=environment)
        page_items = response.get(list_key) if isinstance(response, dict) else None
        if not isinstance(page_items, list) or any(
            not isinstance(item, dict) for item in page_items
        ):
            raise LiveTestError(f"recovery inventory page {list_key} is invalid")
        items.extend(page_items)
        if len(items) > MAX_RECOVERY_INVENTORY_ITEMS:
            raise LiveTestError("recovery inventory exceeds its item boundary")
        next_token = response.get(response_token)
        if next_token in {None, ""}:
            return items
        if (
            not isinstance(next_token, str)
            or len(next_token) > 16_384
            or next_token in seen
        ):
            raise LiveTestError("recovery inventory pagination token is invalid")
        seen.add(next_token)
        token = next_token
    raise LiveTestError("recovery inventory exceeded its page boundary")


def recovery_paginated_strings(
    arguments: list[str],
    *,
    list_key: str,
    response_token: str,
    request_token: str,
    max_pages: int = 1_000,
) -> list[str]:
    items: list[str] = []
    token: str | None = None
    seen: set[str] = set()
    for _page in range(max_pages):
        page_arguments = [*arguments, "--no-paginate"]
        if token is not None:
            page_arguments.extend([request_token, token])
        response = aws_json(page_arguments)
        page_items = response.get(list_key) if isinstance(response, dict) else None
        if not isinstance(page_items, list) or any(
            not isinstance(item, str) for item in page_items
        ):
            raise LiveTestError(f"recovery inventory page {list_key} is invalid")
        items.extend(page_items)
        if len(items) > MAX_RECOVERY_INVENTORY_ITEMS:
            raise LiveTestError("recovery inventory exceeds its item boundary")
        next_token = response.get(response_token)
        if next_token in {None, ""}:
            return items
        if (
            not isinstance(next_token, str)
            or len(next_token) > 16_384
            or next_token in seen
        ):
            raise LiveTestError("recovery inventory pagination token is invalid")
        seen.add(next_token)
        token = next_token
    raise LiveTestError("recovery inventory exceeded its page boundary")


def recovery_paginated_nested_items(
    arguments: list[str],
    *,
    container_key: str,
    max_pages: int = 1_000,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    marker: str | None = None
    seen: set[str] = set()
    for _page in range(max_pages):
        page_arguments = [*arguments, "--no-paginate"]
        if marker is not None:
            page_arguments.extend(["--marker", marker])
        response = aws_json(page_arguments)
        container = response.get(container_key) if isinstance(response, dict) else None
        if not isinstance(container, dict):
            raise LiveTestError(f"recovery global inventory {container_key} is invalid")
        page_items = container.get("Items", [])
        if not isinstance(page_items, list) or any(
            not isinstance(item, dict) for item in page_items
        ):
            raise LiveTestError(
                f"recovery global inventory {container_key} items are invalid"
            )
        quantity = container.get("Quantity")
        if (
            not isinstance(quantity, int)
            or isinstance(quantity, bool)
            or quantity != len(page_items)
        ):
            raise LiveTestError(
                f"recovery global inventory {container_key} quantity changed"
            )
        items.extend(page_items)
        if len(items) > MAX_RECOVERY_INVENTORY_ITEMS:
            raise LiveTestError("recovery global inventory exceeds its item boundary")
        next_marker = container.get("NextMarker")
        truncated = container.get("IsTruncated")
        if truncated not in {True, False, None}:
            raise LiveTestError("recovery global truncation flag is invalid")
        if next_marker in {None, ""}:
            if truncated is True:
                raise LiveTestError("recovery global pagination marker is missing")
            return items
        if truncated is False:
            raise LiveTestError("recovery global pagination state is inconsistent")
        if not isinstance(next_marker, str) or not next_marker or next_marker in seen:
            raise LiveTestError("recovery global pagination did not advance")
        seen.add(next_marker)
        marker = next_marker
    raise LiveTestError("recovery global inventory exceeded its page boundary")


def recovery_identity_binding(account_id: str, region: str) -> dict[str, str]:
    if re.fullmatch(r"[0-9]{12}", account_id) is None:
        raise LiveTestError("recovery account ID must contain exactly 12 digits")
    if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", region) is None:
        raise LiveTestError("recovery region is invalid")
    caller = identity()
    if caller.get("Account") != account_id:
        raise LiveTestError("active AWS account differs from the recovery authority")
    arn = caller.get("Arn", "")
    match = re.fullmatch(
        rf"arn:(aws(?:-[a-z0-9]+)*):(?:iam|sts)::{re.escape(account_id)}:.+",
        arn,
    )
    if match is None:
        raise LiveTestError("active AWS partition or caller ARN is invalid")
    regions = aws_json(
        [
            "ec2",
            "describe-regions",
            "--region",
            region,
            "--region-names",
            region,
        ]
    )
    observed_regions = regions.get("Regions") if isinstance(regions, dict) else None
    if (
        not isinstance(observed_regions, list)
        or len(observed_regions) != 1
        or observed_regions[0].get("RegionName") != region
    ):
        raise LiveTestError("AWS did not bind the exact recovery region")
    principal = durable_trusted_principal(caller)
    return {
        "account_id": account_id,
        "partition": match.group(1),
        "region": region,
        "caller_arn": arn,
        "durable_principal_arn": principal,
    }


def bind_active_ledger_identity(ledger: dict[str, Any]) -> dict[str, str]:
    binding = recovery_identity_binding(ledger["account_id"], ledger["region"])
    if binding["partition"] != ledger.get("partition"):
        raise LiveTestError("active AWS partition differs from the ledger authority")
    if ledger.get("recovery_mode") == "teardown_only" and binding[
        "durable_principal_arn"
    ] != ledger.get("recovery_authorizer_principal_arn"):
        raise LiveTestError("active AWS principal differs from the recovery authorizer")
    return binding


def recovery_stack_history(region: str) -> list[dict[str, Any]]:
    statuses = (
        "CREATE_IN_PROGRESS",
        "CREATE_FAILED",
        "CREATE_COMPLETE",
        "ROLLBACK_IN_PROGRESS",
        "ROLLBACK_FAILED",
        "ROLLBACK_COMPLETE",
        "DELETE_IN_PROGRESS",
        "DELETE_FAILED",
        "DELETE_COMPLETE",
        "UPDATE_IN_PROGRESS",
        "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_IN_PROGRESS",
        "UPDATE_ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_ROLLBACK_COMPLETE",
        "REVIEW_IN_PROGRESS",
        "IMPORT_IN_PROGRESS",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_IN_PROGRESS",
        "IMPORT_ROLLBACK_FAILED",
        "IMPORT_ROLLBACK_COMPLETE",
    )
    return recovery_paginated_items(
        [
            "cloudformation",
            "list-stacks",
            "--region",
            region,
            "--stack-status-filter",
            *statuses,
        ],
        list_key="StackSummaries",
        response_token="NextToken",
        request_token="--next-token",
    )


def recovery_s3_contents(bucket: str, account_id: str, region: str) -> dict[str, Any]:
    versions: list[dict[str, str]] = []
    key_marker: str | None = None
    version_marker: str | None = None
    seen: set[tuple[str | None, str | None]] = set()
    for _page in range(1_000):
        arguments = [
            "s3api",
            "list-object-versions",
            "--region",
            region,
            "--bucket",
            bucket,
            "--max-keys",
            "1000",
            "--expected-bucket-owner",
            account_id,
            "--no-paginate",
        ]
        if key_marker is not None:
            arguments.extend(["--key-marker", key_marker])
        if version_marker is not None:
            arguments.extend(["--version-id-marker", version_marker])
        response = aws_json(arguments)
        if not isinstance(response, dict):
            raise LiveTestError("recovery S3 version inventory is invalid")
        for kind in ("Versions", "DeleteMarkers"):
            values = response.get(kind, [])
            if not isinstance(values, list):
                raise LiveTestError("recovery S3 version page is invalid")
            for item in values:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("Key"), str)
                    or not isinstance(item.get("VersionId"), str)
                ):
                    raise LiveTestError("recovery S3 version entry is invalid")
                versions.append(
                    {
                        "kind": kind,
                        "key": item["Key"],
                        "version_id": item["VersionId"],
                    }
                )
                if len(versions) > MAX_RECOVERY_INVENTORY_ITEMS:
                    raise LiveTestError("recovery S3 inventory is too large")
        if response.get("IsTruncated") is not True:
            if response.get("IsTruncated") not in {False, None}:
                raise LiveTestError("recovery S3 truncation flag is invalid")
            break
        next_pair = (
            response.get("NextKeyMarker"),
            response.get("NextVersionIdMarker"),
        )
        if not isinstance(next_pair[0], str) or not next_pair[0] or next_pair in seen:
            raise LiveTestError("recovery S3 version pagination did not advance")
        seen.add(next_pair)
        key_marker, version_marker = next_pair
    else:
        raise LiveTestError("recovery S3 version inventory exceeded its page bound")

    uploads: list[dict[str, Any]] = []
    upload_key_marker: str | None = None
    upload_id_marker: str | None = None
    upload_markers: set[tuple[str, str]] = set()
    for _page in range(1_000):
        upload_arguments = [
            "s3api",
            "list-multipart-uploads",
            "--region",
            region,
            "--bucket",
            bucket,
            "--max-uploads",
            "1000",
            "--expected-bucket-owner",
            account_id,
            "--no-paginate",
        ]
        if upload_key_marker is not None:
            upload_arguments.extend(["--key-marker", upload_key_marker])
        if upload_id_marker is not None:
            upload_arguments.extend(["--upload-id-marker", upload_id_marker])
        upload_page = aws_json(upload_arguments)
        page_uploads = (
            upload_page.get("Uploads", []) if isinstance(upload_page, dict) else None
        )
        if not isinstance(page_uploads, list) or any(
            not isinstance(item, dict) for item in page_uploads
        ):
            raise LiveTestError("recovery multipart upload page is invalid")
        uploads.extend(page_uploads)
        if len(uploads) > MAX_RECOVERY_INVENTORY_ITEMS:
            raise LiveTestError("recovery multipart inventory is too large")
        if upload_page.get("IsTruncated") is not True:
            if upload_page.get("IsTruncated") not in {False, None}:
                raise LiveTestError("recovery multipart truncation flag is invalid")
            break
        next_markers = (
            upload_page.get("NextKeyMarker"),
            upload_page.get("NextUploadIdMarker"),
        )
        if (
            not all(isinstance(value, str) and value for value in next_markers)
            or next_markers in upload_markers
        ):
            raise LiveTestError("recovery multipart pagination did not advance")
        upload_markers.add(next_markers)
        upload_key_marker, upload_id_marker = next_markers
    else:
        raise LiveTestError("recovery multipart inventory exceeded its page bound")
    upload_rows = [
        {"key": item.get("Key"), "upload_id": item.get("UploadId")} for item in uploads
    ]
    if any(
        not isinstance(item["key"], str) or not isinstance(item["upload_id"], str)
        for item in upload_rows
    ):
        raise LiveTestError("recovery multipart upload inventory is invalid")
    return {
        "version_count": len(versions),
        "versions_sha256": canonical_json_sha256(
            sorted(
                versions,
                key=lambda item: (item["key"], item["version_id"], item["kind"]),
            )
        ),
        "multipart_uploads": sorted(
            upload_rows, key=lambda item: (item["key"], item["upload_id"])
        ),
    }


def recovery_artifact_bucket(
    execution_id: str, account_id: str, region: str
) -> dict[str, Any]:
    bucket = f"bridgefu-recipe-{account_id}-{region}-{execution_id}"
    exists = exact_probe_exists(
        [
            "s3api",
            "head-bucket",
            "--region",
            region,
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            account_id,
        ],
        absent_markers=("(404)", "Not Found", "NoSuchBucket"),
        label="lost-ledger artifact bucket",
    )
    if not exists:
        return {"name": bucket, "exists": False}
    tags = aws_json(
        [
            "s3api",
            "get-bucket-tagging",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            account_id,
        ]
    )
    tag_set = tags.get("TagSet") if isinstance(tags, dict) else None
    observed_tags = recovery_exact_string_map(
        tag_set,
        key_field="Key",
        value_field="Value",
        label="recovery artifact bucket tags",
    )
    require_ownership_tags(tag_set, execution_id)
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": execution_id,
        "BridgefuRecipe": RECIPE,
    }
    if observed_tags != expected_tags:
        raise LiveTestError("recovery artifact bucket tags are not exact")
    location = aws_json(
        [
            "s3api",
            "get-bucket-location",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            account_id,
        ]
    )
    raw_location = (
        location.get("LocationConstraint") if isinstance(location, dict) else None
    )
    observed_region = (
        "us-east-1"
        if raw_location is None
        else "eu-west-1" if raw_location == "EU" else raw_location
    )
    if observed_region != region:
        raise LiveTestError("recovery artifact bucket region changed")
    versioning = aws_json(
        [
            "s3api",
            "get-bucket-versioning",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            account_id,
        ]
    )
    if not isinstance(versioning, dict) or versioning.get("Status") != "Enabled":
        raise LiveTestError("recovery artifact bucket is not versioned")
    public = aws_json(
        [
            "s3api",
            "get-public-access-block",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            account_id,
        ]
    )
    expected_public = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    if (
        not isinstance(public, dict)
        or public.get("PublicAccessBlockConfiguration") != expected_public
    ):
        raise LiveTestError("recovery artifact bucket public-access block changed")
    encryption = aws_json(
        [
            "s3api",
            "get-bucket-encryption",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            account_id,
        ]
    )
    rules = (
        encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules")
        if isinstance(encryption, dict)
        else None
    )
    expected_encryption_rule = {
        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
        "BucketKeyEnabled": True,
        "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
    }
    if rules != [expected_encryption_rule]:
        raise LiveTestError("recovery artifact bucket encryption changed")
    contents = recovery_s3_contents(bucket, account_id, region)
    if contents["multipart_uploads"]:
        raise LiveTestError(
            "recovery artifact bucket has active multipart uploads; abort them first"
        )
    return {
        "name": bucket,
        "exists": True,
        "tags": observed_tags,
        "contents": contents,
    }


def recovery_ecr_repository(
    execution_id: str, account_id: str, partition: str, region: str
) -> dict[str, Any]:
    name = f"bridgefu-test/{execution_id}"
    exists = exact_probe_exists(
        [
            "ecr",
            "describe-repositories",
            "--region",
            region,
            "--registry-id",
            account_id,
            "--repository-names",
            name,
        ],
        absent_markers=("RepositoryNotFoundException",),
        label="lost-ledger ECR repository",
    )
    if not exists:
        return {"name": name, "exists": False}
    response = aws_json(
        [
            "ecr",
            "describe-repositories",
            "--region",
            region,
            "--registry-id",
            account_id,
            "--repository-names",
            name,
        ]
    )
    repositories = response.get("repositories") if isinstance(response, dict) else None
    expected_arn = f"arn:{partition}:ecr:{region}:{account_id}:repository/{name}"
    if (
        not isinstance(repositories, list)
        or len(repositories) != 1
        or repositories[0].get("registryId") != account_id
        or repositories[0].get("repositoryName") != name
        or repositories[0].get("repositoryArn") != expected_arn
    ):
        raise LiveTestError("recovery ECR repository identity changed")
    repository = repositories[0]
    if (
        repository.get("imageTagMutability") != "IMMUTABLE"
        or repository.get("imageScanningConfiguration") != {"scanOnPush": True}
        or repository.get("encryptionConfiguration", {}).get("encryptionType")
        != "AES256"
    ):
        raise LiveTestError("recovery ECR repository configuration changed")
    tags = aws_json(
        [
            "ecr",
            "list-tags-for-resource",
            "--region",
            region,
            "--resource-arn",
            expected_arn,
        ]
    )
    tag_set = tags.get("tags") if isinstance(tags, dict) else None
    observed_tags = recovery_exact_string_map(
        tag_set,
        key_field="Key",
        value_field="Value",
        label="recovery ECR tags",
    )
    require_ownership_tags(tag_set, execution_id)
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": execution_id,
        "BridgefuRecipe": RECIPE,
    }
    if observed_tags != expected_tags:
        raise LiveTestError("recovery ECR tags are not exact")
    images = recovery_paginated_items(
        [
            "ecr",
            "describe-images",
            "--region",
            region,
            "--registry-id",
            account_id,
            "--repository-name",
            name,
            "--max-results",
            "1000",
        ],
        list_key="imageDetails",
        response_token="nextToken",
        request_token="--next-token",
    )
    image_authority = [
        {
            "digest": item.get("imageDigest"),
            "tags": sorted(item.get("imageTags", [])),
        }
        for item in images
    ]
    if any(
        not isinstance(item["digest"], str)
        or any(not isinstance(tag, str) for tag in item["tags"])
        for item in image_authority
    ):
        raise LiveTestError("recovery ECR image inventory is invalid")
    return {
        "name": name,
        "arn": expected_arn,
        "exists": True,
        "tags": observed_tags,
        "image_count": len(image_authority),
        "images_sha256": canonical_json_sha256(
            sorted(image_authority, key=lambda item: item["digest"])
        ),
    }


def recovery_global_absence(
    execution_id: str, account_id: str, region: str
) -> dict[str, Any]:
    demo_bucket = f"bfu-{account_id}-{region}-{execution_id}-site"
    if exact_probe_exists(
        [
            "s3api",
            "head-bucket",
            "--region",
            region,
            "--bucket",
            demo_bucket,
            "--expected-bucket-owner",
            account_id,
        ],
        absent_markers=("(404)", "Not Found", "NoSuchBucket"),
        label="lost-ledger demo-site bucket",
    ):
        raise LiveTestError("recovery found the execution demo-site bucket")

    hosted_zones = recovery_paginated_items(
        ["route53", "list-hosted-zones"],
        list_key="HostedZones",
        response_token="NextMarker",
        request_token="--marker",
    )
    matching_zones = [
        item
        for item in hosted_zones
        if item.get("CallerReference") == execution_id
        or execution_id in str(item.get("Config", {}).get("Comment", ""))
    ]
    if matching_zones:
        raise LiveTestError("recovery found an execution Route 53 hosted zone")

    distributions = recovery_paginated_nested_items(
        ["cloudfront", "list-distributions"],
        container_key="DistributionList",
    )
    distribution_comment = f"Bridgefu {execution_id} nonproduction recipe test page"
    if any(
        item.get("Comment") == distribution_comment
        or execution_id in str(item.get("Comment", ""))
        for item in distributions
    ):
        raise LiveTestError("recovery found an execution CloudFront distribution")

    cache_policies = recovery_paginated_nested_items(
        ["cloudfront", "list-cache-policies", "--type", "custom"],
        container_key="CachePolicyList",
    )
    cache_name = f"bridgefu-{execution_id}-demo-no-cache"
    if any(
        item.get("CachePolicy", {}).get("CachePolicyConfig", {}).get("Name")
        == cache_name
        for item in cache_policies
    ):
        raise LiveTestError("recovery found an execution CloudFront cache policy")

    response_policies = recovery_paginated_nested_items(
        ["cloudfront", "list-response-headers-policies", "--type", "custom"],
        container_key="ResponseHeadersPolicyList",
    )
    response_name = f"bridgefu-{execution_id}-demo-security"
    if any(
        item.get("ResponseHeadersPolicy", {})
        .get("ResponseHeadersPolicyConfig", {})
        .get("Name")
        == response_name
        for item in response_policies
    ):
        raise LiveTestError(
            "recovery found an execution CloudFront response-headers policy"
        )

    origin_controls = recovery_paginated_nested_items(
        ["cloudfront", "list-origin-access-controls"],
        container_key="OriginAccessControlList",
    )
    origin_name = f"bridgefu-{execution_id}-demo-site"
    if any(
        item.get("OriginAccessControlConfig", {}).get("Name") == origin_name
        for item in origin_controls
    ):
        raise LiveTestError(
            "recovery found an execution CloudFront origin access control"
        )
    return {
        "demo_site_bucket": True,
        "route53_hosted_zone": True,
        "cloudfront_distribution": True,
        "cloudfront_cache_policy": True,
        "cloudfront_response_headers_policy": True,
        "cloudfront_origin_access_control": True,
    }


def recovery_iam_attachment_contract(
    *,
    execution_id: str,
    bootstrap_stack_id: str,
    bootstrap_stack_name: str,
    expected_role_names: list[str],
    expected_policy_arns: list[str],
    expected_physical_ids: dict[str, str],
    qualification_runner_enabled: bool,
) -> dict[str, Any]:
    deployment_role = expected_physical_ids["DeploymentRole"]
    execution_role = expected_physical_ids["CloudFormationExecutionRole"]
    qualification_role = expected_physical_ids["QualificationRole"]
    runner_role = expected_physical_ids["QualificationRunnerRole"]
    policy_by_logical_id = {
        logical_id: physical_id
        for logical_id, physical_id in expected_physical_ids.items()
        if RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id] == "AWS::IAM::ManagedPolicy"
    }
    execution_attached = [
        policy_by_logical_id["DeploymentControlPolicy"],
        policy_by_logical_id["DeploymentArtifactPolicy"],
        policy_by_logical_id["DeploymentApplicationPolicy"],
        policy_by_logical_id["DeploymentComputePolicy"],
        policy_by_logical_id["DeploymentDataPolicy"],
        policy_by_logical_id["DeploymentDemoPolicy"],
    ]
    if qualification_runner_enabled:
        execution_attached.append(
            policy_by_logical_id["DeploymentQualificationRunnerPolicy"]
        )
    expected_attached = {
        deployment_role: sorted(
            [
                policy_by_logical_id["DeploymentControlPolicy"],
                policy_by_logical_id["DeploymentArtifactPolicy"],
            ]
        ),
        execution_role: sorted(execution_attached),
        qualification_role: [],
        runner_role: [],
    }
    expected_inline = {
        deployment_role: [],
        execution_role: [],
        qualification_role: ["BridgefuRecipeQualification"],
        runner_role: ["BridgefuQualificationRunner"],
    }
    stack_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": execution_id,
        "BridgefuRecipe": RECIPE,
    }
    explicit_bootstrap_tags = {
        "Project": PROJECT,
        "ManagedBy": "bridgefu-test-bootstrap",
        "BridgefuExecutionId": execution_id,
    }

    def validate_cloudformation_tags(
        observed_tags: dict[str, str],
        *,
        logical_id: str,
        allowed_user_tag_maps: tuple[dict[str, str], ...],
        label: str,
    ) -> None:
        user_tags = {
            key: value
            for key, value in observed_tags.items()
            if not key.startswith("aws:")
        }
        system_tags = {
            key: value for key, value in observed_tags.items() if key.startswith("aws:")
        }
        # AWS::IAM::Role declares three explicit resource tags. Depending on
        # CloudFormation's stack-tag propagation path, BridgefuRecipe can also
        # be present. Those are the only accepted user-tag variants.
        if user_tags not in allowed_user_tag_maps:
            raise LiveTestError(f"{label} user tags changed")
        expected_system_tags = {
            "aws:cloudformation:stack-name": bootstrap_stack_name,
            "aws:cloudformation:stack-id": bootstrap_stack_id,
            "aws:cloudformation:logical-id": logical_id,
        }
        # CloudFormation system tags are not uniformly returned by IAM's tag
        # APIs. If present, require the complete exact binding; otherwise accept
        # only their complete absence.
        if system_tags not in ({}, expected_system_tags):
            raise LiveTestError(f"{label} CloudFormation tags changed")

    role_logical_id_by_name = {
        physical_id: logical_id
        for logical_id, physical_id in expected_physical_ids.items()
        if RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id] == "AWS::IAM::Role"
    }
    role_contract: dict[str, Any] = {}
    for role_name in expected_role_names:
        attached = recovery_paginated_items(
            [
                "iam",
                "list-attached-role-policies",
                "--role-name",
                role_name,
                "--max-items",
                "1000",
            ],
            list_key="AttachedPolicies",
            response_token="Marker",
            request_token="--marker",
        )
        raw_attached_arns = [item.get("PolicyArn") for item in attached]
        if any(not isinstance(item, str) for item in raw_attached_arns):
            raise LiveTestError("recovery IAM role attachment inventory is invalid")
        attached_arns = sorted(raw_attached_arns)
        inline = sorted(
            recovery_paginated_strings(
                [
                    "iam",
                    "list-role-policies",
                    "--role-name",
                    role_name,
                    "--max-items",
                    "1000",
                ],
                list_key="PolicyNames",
                response_token="Marker",
                request_token="--marker",
            )
        )
        profiles = recovery_paginated_items(
            [
                "iam",
                "list-instance-profiles-for-role",
                "--role-name",
                role_name,
                "--max-items",
                "1000",
            ],
            list_key="InstanceProfiles",
            response_token="Marker",
            request_token="--marker",
        )
        role_tags = recovery_paginated_items(
            [
                "iam",
                "list-role-tags",
                "--role-name",
                role_name,
                "--max-items",
                "1000",
            ],
            list_key="Tags",
            response_token="Marker",
            request_token="--marker",
        )
        observed_role_tags = recovery_exact_string_map(
            role_tags,
            key_field="Key",
            value_field="Value",
            label="recovery IAM role tags",
        )
        merged_bootstrap_tags = {
            **stack_tags,
            "ManagedBy": "bridgefu-test-bootstrap",
        }
        validate_cloudformation_tags(
            observed_role_tags,
            logical_id=role_logical_id_by_name[role_name],
            allowed_user_tag_maps=(
                explicit_bootstrap_tags,
                merged_bootstrap_tags,
            ),
            label="recovery IAM role",
        )
        if (
            attached_arns != expected_attached[role_name]
            or inline != expected_inline[role_name]
            or profiles
        ):
            raise LiveTestError("recovery IAM role attachment contract changed")
        role_contract[role_name] = {
            "attached_policy_arns": attached_arns,
            "inline_policy_names": inline,
            "instance_profile_arns": [],
            "tags": observed_role_tags,
        }

    expected_roles_by_policy = {
        policy_by_logical_id["DeploymentControlPolicy"]: sorted(
            [deployment_role, execution_role]
        ),
        policy_by_logical_id["DeploymentArtifactPolicy"]: sorted(
            [deployment_role, execution_role]
        ),
        policy_by_logical_id["DeploymentApplicationPolicy"]: [execution_role],
        policy_by_logical_id["DeploymentComputePolicy"]: [execution_role],
        policy_by_logical_id["DeploymentDataPolicy"]: [execution_role],
        policy_by_logical_id["DeploymentDemoPolicy"]: [execution_role],
        policy_by_logical_id["DeploymentQualificationRunnerPolicy"]: (
            [execution_role] if qualification_runner_enabled else []
        ),
    }
    policy_contract: dict[str, Any] = {}
    for policy_arn in expected_policy_arns:
        roles = recovery_paginated_items(
            [
                "iam",
                "list-entities-for-policy",
                "--policy-arn",
                policy_arn,
                "--entity-filter",
                "Role",
                "--max-items",
                "1000",
            ],
            list_key="PolicyRoles",
            response_token="Marker",
            request_token="--marker",
        )
        raw_role_names = [item.get("RoleName") for item in roles]
        if any(not isinstance(item, str) for item in raw_role_names):
            raise LiveTestError("recovery IAM managed-policy role list is invalid")
        role_names = sorted(raw_role_names)
        if role_names != expected_roles_by_policy[policy_arn]:
            raise LiveTestError("recovery IAM managed-policy role binding changed")
        for entity_filter, list_key in (
            ("User", "PolicyUsers"),
            ("Group", "PolicyGroups"),
        ):
            entities = recovery_paginated_items(
                [
                    "iam",
                    "list-entities-for-policy",
                    "--policy-arn",
                    policy_arn,
                    "--entity-filter",
                    entity_filter,
                    "--max-items",
                    "1000",
                ],
                list_key=list_key,
                response_token="Marker",
                request_token="--marker",
            )
            if entities:
                raise LiveTestError(
                    "recovery IAM managed policy has an unexpected principal"
                )
        policy_contract[policy_arn] = {
            "role_names": role_names,
            "user_names": [],
            "group_names": [],
            "template_tag_contract": "not_declared",
        }
    return {"roles": role_contract, "policies": policy_contract}


def recovery_lost_ledger_inventory(
    *,
    execution_id: str,
    account_id: str,
    region: str,
    bootstrap_stack_id: str,
    expect_demo_site: bool,
) -> dict[str, Any]:
    identity_binding = recovery_identity_binding(account_id, region)
    partition = identity_binding["partition"]
    base_name = f"bridgefu-{execution_id}"
    bootstrap_name = f"{base_name}-bootstrap"
    qualification_name = f"{base_name}-qualification"
    expected_stack_id = re.compile(
        rf"arn:{re.escape(partition)}:cloudformation:{re.escape(region)}:"
        rf"{re.escape(account_id)}:stack/{re.escape(bootstrap_name)}/"
        r"[0-9a-fA-F-]{36}"
    )
    if expected_stack_id.fullmatch(bootstrap_stack_id) is None:
        raise LiveTestError("bootstrap stack ID is outside the recovery authority")
    stack_response = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            region,
            "--stack-name",
            bootstrap_stack_id,
        ]
    )
    stacks = stack_response.get("Stacks") if isinstance(stack_response, dict) else None
    if not isinstance(stacks, list) or len(stacks) != 1:
        raise LiveTestError("recovery bootstrap stack is unavailable")
    stack = stacks[0]
    stable_bootstrap_statuses = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
    bootstrap_status = stack.get("StackStatus")
    if (
        stack.get("StackId") != bootstrap_stack_id
        or stack.get("StackName") != bootstrap_name
        or bootstrap_status not in stable_bootstrap_statuses
        or stack.get("RoleARN") is not None
        or stack.get("EnableTerminationProtection") not in {False, None}
    ):
        raise LiveTestError("recovery bootstrap stack state is not exact")
    creation_time = recovery_stack_creation_time(stack.get("CreationTime"))
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": execution_id,
        "BridgefuRecipe": RECIPE,
    }
    observed_tags = recovery_exact_string_map(
        stack.get("Tags"),
        key_field="Key",
        value_field="Value",
        label="recovery bootstrap stack tags",
    )
    if observed_tags != expected_tags:
        raise LiveTestError("recovery bootstrap stack tags are not exact")
    observed_parameters = recovery_exact_string_map(
        stack.get("Parameters"),
        key_field="ParameterKey",
        value_field="ParameterValue",
        label="recovery bootstrap stack parameters",
    )
    deployed_trusted_principal = observed_parameters.get("TrustedPrincipalArn")
    if (
        not isinstance(deployed_trusted_principal, str)
        or re.fullmatch(
            rf"arn:{re.escape(partition)}:iam::{re.escape(account_id)}:"
            r"(?:root|user/[A-Za-z0-9+=,.@_/-]+|role/[A-Za-z0-9+=,.@_/-]+)",
            deployed_trusted_principal,
        )
        is None
    ):
        raise LiveTestError("recovery bootstrap trusted principal is invalid")
    runner_parameter = observed_parameters.get("EnableQualificationRunner")
    if runner_parameter not in {"true", "false"}:
        raise LiveTestError("recovery bootstrap runner parameter is invalid")
    # The deployed template condition is Disposable OR the explicit runner flag.
    # Lost-ledger recovery requires ConnectMode=Disposable, so the policy is
    # attached even for the initial `EnableQualificationRunner=false` bootstrap.
    qualification_runner_enabled = True
    expected_parameters = {
        "ExecutionId": execution_id,
        "TrustedPrincipalArn": deployed_trusted_principal,
        "GitHubOidcProviderArn": "none",
        "GitHubRepository": "eisenzopf/bridgefu",
        "GitHubEnvironment": "none",
        "ConnectInstanceArn": (
            f"arn:{partition}:connect:{region}:{account_id}:instance/unused"
        ),
        "ConnectMode": "Disposable",
        "EnableQualificationRunner": runner_parameter,
        "ArtifactBucketName": (f"bridgefu-recipe-{account_id}-{region}-{execution_id}"),
        "EcrRepositoryName": f"bridgefu-test/{execution_id}",
        "ArtifactAccessMode": "EphemeralManage",
        "PublicHostedZoneId": "none",
        "EnableDemoSite": "true" if expect_demo_site else "false",
    }
    if observed_parameters != expected_parameters:
        raise LiveTestError("recovery bootstrap stack parameters are not exact")
    template = aws_json(
        [
            "cloudformation",
            "get-template",
            "--region",
            region,
            "--stack-name",
            bootstrap_stack_id,
            "--template-stage",
            "Original",
        ]
    )
    template_body = template.get("TemplateBody") if isinstance(template, dict) else None
    expected_template = (
        root_dir()
        / "recipes"
        / "vapi-amazon-connect-screen-pop"
        / "cloudformation"
        / "test-deployment-role.yaml"
    )
    deployed_template = cloudformation_document(template_body)
    deployed_template_sha256 = canonical_template_sha256(deployed_template)
    current_template_sha256 = canonical_template_sha256(expected_template)
    deployed_parameters = deployed_template.get("Parameters")
    if not isinstance(deployed_parameters, dict):
        raise LiveTestError("recovery bootstrap template parameters are invalid")
    deployed_parameter_keys = set(deployed_parameters)
    if deployed_parameter_keys != set(expected_parameters):
        raise LiveTestError("recovery bootstrap template parameter contract changed")
    deployed_resources = deployed_template.get("Resources")
    if not isinstance(deployed_resources, dict):
        raise LiveTestError("recovery bootstrap template resources are invalid")
    deployed_resource_types = {
        logical_id: resource.get("Type")
        for logical_id, resource in deployed_resources.items()
        if isinstance(resource, dict)
    }
    if (
        len(deployed_resource_types) != len(deployed_resources)
        or deployed_resource_types != RECOVERY_BOOTSTRAP_RESOURCE_TYPES
    ):
        raise LiveTestError("recovery bootstrap deployed resource contract is unsafe")
    outputs_by_key = recovery_exact_string_map(
        stack.get("Outputs"),
        key_field="OutputKey",
        value_field="OutputValue",
        label="recovery bootstrap stack outputs",
    )
    expected_outputs = {
        "DeploymentRoleArn": (
            f"arn:{partition}:iam::{account_id}:role/{base_name}-deployer"
        ),
        "CloudFormationExecutionRoleArn": (
            f"arn:{partition}:iam::{account_id}:role/{base_name}-cloudformation"
        ),
        "DeploymentRoleSessionName": base_name,
        "QualificationRoleArn": (
            f"arn:{partition}:iam::{account_id}:role/{base_name}-qualifier"
        ),
        "QualificationRoleSessionName": f"{base_name}-qualification",
        "QualificationRunnerRoleArn": (
            f"arn:{partition}:iam::{account_id}:role/{base_name}-runner"
        ),
    }
    if set(outputs_by_key) != {
        *expected_outputs,
        "QualificationSourceEipAllocationId",
        "QualificationSourceEipPublicIp",
    } or any(
        outputs_by_key.get(key) != value for key, value in expected_outputs.items()
    ):
        raise LiveTestError("recovery bootstrap role outputs changed")
    deployment_role = aws_json(
        ["iam", "get-role", "--role-name", f"{base_name}-deployer"]
    )
    role = deployment_role.get("Role") if isinstance(deployment_role, dict) else None
    trust = role.get("AssumeRolePolicyDocument") if isinstance(role, dict) else None
    statements = trust.get("Statement") if isinstance(trust, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    expected_trust = {
        "Effect": "Allow",
        "Principal": {"AWS": deployed_trusted_principal},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:RoleSessionName": base_name}},
    }
    if (
        not isinstance(role, dict)
        or role.get("RoleName") != f"{base_name}-deployer"
        or role.get("Arn") != expected_outputs["DeploymentRoleArn"]
        or role.get("MaxSessionDuration") != 43_200
        or statements != [expected_trust]
    ):
        raise LiveTestError("recovery deployment-role trust contract changed")
    allocation_id = outputs_by_key.get("QualificationSourceEipAllocationId")
    source_ip = outputs_by_key.get("QualificationSourceEipPublicIp")
    try:
        source_cidr = str(ipaddress.ip_network(f"{source_ip}/32", strict=True))
    except ValueError as error:
        raise LiveTestError("recovery bootstrap EIP output is invalid") from error
    if (
        not isinstance(allocation_id, str)
        or re.fullmatch(r"eipalloc-[0-9a-f]+", allocation_id) is None
        or not ipaddress.ip_network(source_cidr).network_address.is_global
    ):
        raise LiveTestError("recovery bootstrap EIP binding is invalid")

    resources = recovery_paginated_items(
        [
            "cloudformation",
            "list-stack-resources",
            "--region",
            region,
            "--stack-name",
            bootstrap_stack_id,
        ],
        list_key="StackResourceSummaries",
        response_token="NextToken",
        request_token="--next-token",
    )
    resource_authority = sorted(
        [
            {
                "logical_id": item.get("LogicalResourceId"),
                "physical_id": item.get("PhysicalResourceId"),
                "resource_type": item.get("ResourceType"),
                "status": item.get("ResourceStatus"),
            }
            for item in resources
        ],
        key=lambda item: str(item["logical_id"]),
    )
    if any(
        not isinstance(item["logical_id"], str)
        or not isinstance(item["physical_id"], str)
        or not item["physical_id"]
        or not isinstance(item["resource_type"], str)
        or item["status"] not in stable_bootstrap_statuses
        for item in resource_authority
    ):
        raise LiveTestError("recovery bootstrap resource inventory is incomplete")
    observed_resource_types = {
        item["logical_id"]: item["resource_type"] for item in resource_authority
    }
    expected_physical_ids = {
        "DeploymentRole": f"{base_name}-deployer",
        "CloudFormationExecutionRole": f"{base_name}-cloudformation",
        "QualificationRole": f"{base_name}-qualifier",
        "QualificationRunnerRole": f"{base_name}-runner",
        "DeploymentControlPolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-control"
        ),
        "DeploymentArtifactPolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-artifacts"
        ),
        "DeploymentApplicationPolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-application"
        ),
        "DeploymentComputePolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-compute"
        ),
        "DeploymentDataPolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-data"
        ),
        "DeploymentDemoPolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-demo"
        ),
        "DeploymentQualificationRunnerPolicy": (
            f"arn:{partition}:iam::{account_id}:policy/{base_name}-deployer-runner"
        ),
        # AWS::EC2::EIP uses its public IP as the CloudFormation physical/Ref
        # identity. AllocationId is a separate GetAtt value validated below.
        "QualificationSourceEip": source_ip,
    }
    observed_physical_ids = {
        item["logical_id"]: item["physical_id"] for item in resource_authority
    }
    if (
        observed_resource_types != RECOVERY_BOOTSTRAP_RESOURCE_TYPES
        or observed_physical_ids != expected_physical_ids
    ):
        raise LiveTestError(
            "recovery bootstrap resources differ from its deployed Original template"
        )
    addresses = aws_json(
        [
            "ec2",
            "describe-addresses",
            "--region",
            region,
            "--allocation-ids",
            allocation_id,
        ]
    )
    address_rows = addresses.get("Addresses") if isinstance(addresses, dict) else None
    if not isinstance(address_rows, list) or len(address_rows) != 1:
        raise LiveTestError("recovery qualification EIP is unavailable")
    address = address_rows[0]
    address_tags = recovery_exact_string_map(
        address.get("Tags"),
        key_field="Key",
        value_field="Value",
        label="recovery qualification EIP tags",
    )
    explicit_address_tags = {
        "Project": PROJECT,
        "ManagedBy": "bridgefu-test-bootstrap",
        "BridgefuExecutionId": execution_id,
    }
    propagated_address_tags = {
        **explicit_address_tags,
        "BridgefuRecipe": RECIPE,
    }
    address_user_tags = {
        key: value for key, value in address_tags.items() if not key.startswith("aws:")
    }
    address_system_tags = {
        key: value for key, value in address_tags.items() if key.startswith("aws:")
    }
    expected_address_system_tags = {
        "aws:cloudformation:stack-name": bootstrap_name,
        "aws:cloudformation:stack-id": bootstrap_stack_id,
        "aws:cloudformation:logical-id": "QualificationSourceEip",
    }
    if (
        address.get("AllocationId") != allocation_id
        or address.get("PublicIp") != source_ip
        or address.get("Domain") != "vpc"
        or any(
            address.get(field)
            for field in (
                "AssociationId",
                "InstanceId",
                "NetworkInterfaceId",
                "PrivateIpAddress",
            )
        )
        or address_user_tags not in (explicit_address_tags, propagated_address_tags)
        or address_system_tags not in ({}, expected_address_system_tags)
    ):
        raise LiveTestError("recovery qualification EIP binding changed")
    change_sets = recovery_paginated_items(
        [
            "cloudformation",
            "list-change-sets",
            "--region",
            region,
            "--stack-name",
            bootstrap_stack_id,
        ],
        list_key="Summaries",
        response_token="NextToken",
        request_token="--next-token",
    )
    if change_sets:
        raise LiveTestError("recovery bootstrap still has CloudFormation change sets")
    history = recovery_stack_history(region)
    relevant_history = [
        {
            "name": item.get("StackName"),
            "id": item.get("StackId"),
            "status": item.get("StackStatus"),
        }
        for item in history
        if item.get("StackName") in {base_name, qualification_name, bootstrap_name}
    ]
    if any(
        item["name"] in {base_name, qualification_name} for item in relevant_history
    ):
        raise LiveTestError(
            "application or qualification stack history forbids lost-ledger adoption"
        )
    bootstrap_history = [
        item for item in relevant_history if item["name"] == bootstrap_name
    ]
    if bootstrap_history != [
        {"name": bootstrap_name, "id": bootstrap_stack_id, "status": bootstrap_status}
    ]:
        raise LiveTestError("recovery bootstrap stack history is ambiguous")

    tagged = recovery_paginated_items(
        [
            "resourcegroupstaggingapi",
            "get-resources",
            "--region",
            region,
            "--resources-per-page",
            "100",
            "--tag-filters",
            f"Key=BridgefuExecutionId,Values={execution_id}",
        ],
        list_key="ResourceTagMappingList",
        response_token="PaginationToken",
        request_token="--pagination-token",
    )
    tagged_authority: list[dict[str, Any]] = []
    for item in tagged:
        arn = item.get("ResourceARN")
        raw_tags = item.get("Tags")
        if not isinstance(arn, str) or not isinstance(raw_tags, list):
            raise LiveTestError("recovery tagged-resource inventory is invalid")
        tags = recovery_exact_string_map(
            raw_tags,
            key_field="Key",
            value_field="Value",
            label="recovery tagged-resource tags",
        )
        tagged_authority.append({"arn": arn, "tags": tags})

    artifact = recovery_artifact_bucket(execution_id, account_id, region)
    repository = recovery_ecr_repository(execution_id, account_id, partition, region)
    allowed_arns = {
        bootstrap_stack_id,
        f"arn:{partition}:ec2:{region}:{account_id}:elastic-ip/{allocation_id}",
        *(
            f"arn:{partition}:iam::{account_id}:role/{physical_id}"
            for logical_id, physical_id in expected_physical_ids.items()
            if RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id] == "AWS::IAM::Role"
        ),
        *(
            physical_id
            for logical_id, physical_id in expected_physical_ids.items()
            if RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id]
            == "AWS::IAM::ManagedPolicy"
        ),
    }
    if artifact["exists"]:
        allowed_arns.add(f"arn:{partition}:s3:::{artifact['name']}")
    if repository["exists"]:
        allowed_arns.add(repository["arn"])
    bootstrap_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": execution_id,
        "BridgefuRecipe": RECIPE,
    }
    eip_tags = {**bootstrap_tags, "ManagedBy": "bridgefu-test-bootstrap"}
    expected_tag_variants: dict[str, tuple[dict[str, str], ...]] = {
        arn: (bootstrap_tags,) for arn in allowed_arns
    }
    expected_tag_variants[
        f"arn:{partition}:ec2:{region}:{account_id}:elastic-ip/{allocation_id}"
    ] = (
        explicit_address_tags,
        eip_tags,
        {**explicit_address_tags, **expected_address_system_tags},
        {**eip_tags, **expected_address_system_tags},
    )
    for logical_id, physical_id in expected_physical_ids.items():
        resource_type = RECOVERY_BOOTSTRAP_RESOURCE_TYPES[logical_id]
        if resource_type == "AWS::IAM::Role":
            arn = f"arn:{partition}:iam::{account_id}:role/{physical_id}"
            role_system_tags = {
                "aws:cloudformation:stack-name": bootstrap_name,
                "aws:cloudformation:stack-id": bootstrap_stack_id,
                "aws:cloudformation:logical-id": logical_id,
            }
            explicit_role_tags = explicit_address_tags
            propagated_role_tags = eip_tags
            expected_tag_variants[arn] = (
                explicit_role_tags,
                propagated_role_tags,
                {**explicit_role_tags, **role_system_tags},
                {**propagated_role_tags, **role_system_tags},
            )
        elif resource_type == "AWS::IAM::ManagedPolicy":
            policy_system_tags = {
                "aws:cloudformation:stack-name": bootstrap_name,
                "aws:cloudformation:stack-id": bootstrap_stack_id,
                "aws:cloudformation:logical-id": logical_id,
            }
            expected_tag_variants[physical_id] = (
                bootstrap_tags,
                {**bootstrap_tags, **policy_system_tags},
            )
    if artifact["exists"]:
        expected_tag_variants[f"arn:{partition}:s3:::{artifact['name']}"] = (
            artifact["tags"],
        )
    if repository["exists"]:
        expected_tag_variants[repository["arn"]] = (repository["tags"],)
    for item in tagged_authority:
        arn = item["arn"]
        if arn not in allowed_arns or item["tags"] not in expected_tag_variants[arn]:
            raise LiveTestError(
                "recovery tag inventory contains a non-bootstrap or retagged resource"
            )

    roles = recovery_paginated_items(
        ["iam", "list-roles", "--max-items", "1000"],
        list_key="Roles",
        response_token="Marker",
        request_token="--marker",
    )
    policies = recovery_paginated_items(
        ["iam", "list-policies", "--scope", "Local", "--max-items", "1000"],
        list_key="Policies",
        response_token="Marker",
        request_token="--marker",
    )
    matching_roles = sorted(
        item.get("RoleName")
        for item in roles
        if execution_id in str(item.get("RoleName", ""))
    )
    matching_policies = sorted(
        item.get("Arn")
        for item in policies
        if execution_id in str(item.get("PolicyName", ""))
    )
    expected_role_names = sorted(
        item["physical_id"]
        for item in resource_authority
        if item["resource_type"] == "AWS::IAM::Role"
    )
    expected_policy_arns = sorted(
        item["physical_id"]
        for item in resource_authority
        if item["resource_type"] == "AWS::IAM::ManagedPolicy"
    )
    if (
        matching_roles != expected_role_names
        or matching_policies != expected_policy_arns
    ):
        raise LiveTestError("recovery IAM name inventory differs from bootstrap")
    iam_attachments = recovery_iam_attachment_contract(
        execution_id=execution_id,
        bootstrap_stack_id=bootstrap_stack_id,
        bootstrap_stack_name=bootstrap_name,
        expected_role_names=expected_role_names,
        expected_policy_arns=expected_policy_arns,
        expected_physical_ids=expected_physical_ids,
        qualification_runner_enabled=qualification_runner_enabled,
    )

    connect = recovery_paginated_items(
        ["connect", "list-instances", "--region", region, "--max-results", "100"],
        list_key="InstanceSummaryList",
        response_token="NextToken",
        request_token="--next-token",
    )
    connect_alias = f"{execution_id}-connect"
    matching_connect = [
        item for item in connect if item.get("InstanceAlias") == connect_alias
    ]
    if matching_connect:
        raise LiveTestError("recovery found a disposable Connect instance")
    log_name = f"/aws/connect/{execution_id}-connect"
    logs = recovery_paginated_items(
        [
            "logs",
            "describe-log-groups",
            "--region",
            region,
            "--log-group-name-prefix",
            log_name,
            "--limit",
            "50",
        ],
        list_key="logGroups",
        response_token="nextToken",
        request_token="--next-token",
    )
    if any(item.get("logGroupName") == log_name for item in logs):
        raise LiveTestError("recovery found the disposable Connect log group")
    secret_prefix = f"bridgefu-{execution_id}-"
    secrets_inventory = recovery_paginated_items(
        [
            "secretsmanager",
            "list-secrets",
            "--region",
            region,
            "--include-planned-deletion",
            "--max-results",
            "100",
            "--filters",
            f"Key=name,Values={secret_prefix}",
        ],
        list_key="SecretList",
        response_token="NextToken",
        request_token="--next-token",
    )
    matching_secrets = [
        item
        for item in secrets_inventory
        if str(item.get("Name", "")).startswith(secret_prefix)
    ]
    if matching_secrets:
        raise LiveTestError("recovery found execution Secrets Manager resources")
    project_name = f"{base_name}-qualification"
    projects = aws_json(
        [
            "codebuild",
            "batch-get-projects",
            "--region",
            region,
            "--names",
            project_name,
        ]
    )
    if (
        not isinstance(projects, dict)
        or projects.get("projects") != []
        or projects.get("projectsNotFound") != [project_name]
    ):
        raise LiveTestError("recovery CodeBuild project absence is not exact")
    global_absence = recovery_global_absence(execution_id, account_id, region)

    return {
        "schema_version": 1,
        "complete": True,
        "authority_mode": "teardown_only",
        "execution_id": execution_id,
        "identity": identity_binding,
        "expected_names": {
            "application_stack": base_name,
            "qualification_stack": qualification_name,
            "bootstrap_stack": bootstrap_name,
            "artifact_bucket": artifact["name"],
            "ecr_repository": repository["name"],
            "codebuild_project": project_name,
            "connect_instance_alias": connect_alias,
            "connect_log_group": log_name,
            "secret_prefix": secret_prefix,
        },
        "bootstrap": {
            "name": bootstrap_name,
            "stack_id": bootstrap_stack_id,
            "status": bootstrap_status,
            "creation_time": creation_time,
            "tags": observed_tags,
            "parameters": observed_parameters,
            "outputs": outputs_by_key,
            "deployed_template_sha256": deployed_template_sha256,
            "current_template_sha256": current_template_sha256,
            "matches_current_template": (
                deployed_template_sha256 == current_template_sha256
            ),
            "resources": resource_authority,
            "change_sets": [],
        },
        "cloudformation_history": relevant_history,
        "tagged_resources": sorted(tagged_authority, key=lambda item: item["arn"]),
        "iam": {
            "roles": matching_roles,
            "policies": matching_policies,
            "attachments": iam_attachments,
        },
        "artifact_bucket": artifact,
        "ecr_repository": repository,
        "absence": {
            "application_stack_history": True,
            "qualification_stack_history": True,
            "connect_instance": True,
            "connect_log_group": True,
            "execution_secrets_including_pending_deletion": True,
            "codebuild_project": True,
            **global_absence,
            "vapi_external_resources": "not_created_cloudformation_history",
        },
        "coverage": {
            "cloudformation_stacks_and_change_sets": "direct_paginated",
            "resource_tags": "direct_paginated",
            "iam_roles_and_policies": "direct_paginated",
            "s3_versions_delete_markers_and_multipart": "direct_paginated",
            "ecr_repository_and_images": "direct_paginated",
            "connect_instances_and_logs": "direct_paginated",
            "secrets_including_planned_deletion": "direct_paginated",
            "codebuild_project": "direct_exact",
            "route53_and_cloudfront_globals": "direct_paginated",
            "demo_site_bucket": "direct_exact",
            "tag_supported_allowed_targets": "resource_tags_paginated",
        },
        "qualification_source": {
            "allocation_id": allocation_id,
            "cidr": source_cidr,
        },
    }


def recovery_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise LiveTestError(f"{label} is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LiveTestError(f"{label} is invalid") from error
    if parsed.tzinfo is None:
        raise LiveTestError(f"{label} has no timezone")
    return parsed.astimezone(dt.timezone.utc)


def recovery_iso(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise LiveTestError("recovery timestamp has no timezone")
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def recovery_controller_sha256() -> str:
    return hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


def recovery_teardown_authority_projection(
    inventory: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(inventory, dict) or inventory.get("complete") is not True:
        raise LiveTestError("lost-ledger recovery inventory is incomplete")
    authority = copy.deepcopy(inventory)
    identity_authority = authority.get("identity")
    bootstrap_authority = authority.get("bootstrap")
    if not isinstance(identity_authority, dict) or not isinstance(
        bootstrap_authority, dict
    ):
        raise LiveTestError("lost-ledger recovery authority has an invalid shape")
    identity_authority.pop("caller_arn", None)
    bootstrap_authority.pop("current_template_sha256", None)
    bootstrap_authority.pop("matches_current_template", None)
    return authority


def retired_execution_marker_path(execution_id: str) -> Path:
    if EXECUTION_PATTERN.fullmatch(execution_id) is None:
        raise LiveTestError("execution ID cannot address a retired-ID marker")
    return live_state_root() / ".retired-executions" / f"{execution_id}.json"


def read_retired_execution_marker(execution_id: str) -> dict[str, Any] | None:
    path = retired_execution_marker_path(execution_id)
    if not os.path.lexists(path):
        return None
    try:
        value = json.loads(
            private_file_bytes(
                path,
                maximum_bytes=256 * 1024,
                label="retired execution-ID marker",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveTestError("retired execution-ID marker is unreadable") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "marker_kind",
            "execution_id",
            "retired_at",
            "recovery_review_sha256",
            "recovery_authority_sha256",
        }
        or value.get("schema_version") != 1
        or value.get("marker_kind") != "lost_ledger_teardown_only"
        or value.get("execution_id") != execution_id
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("recovery_review_sha256", "")))
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("recovery_authority_sha256", ""))
        )
        is None
    ):
        raise LiveTestError("retired execution-ID marker is invalid")
    recovery_timestamp(value.get("retired_at"), "retired execution timestamp")
    return value


def retained_zero_proof_is_valid(execution_id: str, ledger: dict[str, Any]) -> bool:
    if ledger.get("status") != "destroyed":
        return False
    execution_directory = ledger_path(execution_id).parent
    try:
        proof = json.loads(
            private_file_bytes(
                execution_directory / "teardown-zero-proof.json",
                maximum_bytes=MAX_STATE_JSON_BYTES,
                label="retained teardown zero proof",
            ).decode("utf-8")
        )
        final_inventory = json.loads(
            private_file_bytes(
                execution_directory / "teardown-inventory.json",
                maximum_bytes=MAX_STATE_JSON_BYTES,
                label="retained teardown inventory",
            ).decode("utf-8")
        )
    except (LiveTestError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    observations = proof.get("observations") if isinstance(proof, dict) else None
    if (
        not isinstance(proof, dict)
        or set(proof)
        != {
            "schema_version",
            "execution_id",
            "required_observations",
            "minimum_span_seconds",
            "observations",
            "proven_at",
        }
        or proof.get("schema_version") != 1
        or proof.get("execution_id") != execution_id
        or proof.get("required_observations") != 3
        or proof.get("minimum_span_seconds") != 60
        or not isinstance(observations, list)
        or len(observations) != 3
        or not isinstance(final_inventory, dict)
        or set(final_inventory) != TEARDOWN_INVENTORY_KEYS
        or inventory_has_leftovers(final_inventory)
        or any(
            not isinstance(item, dict)
            or set(item) != TEARDOWN_INVENTORY_KEYS
            or inventory_has_leftovers(item)
            for item in observations
        )
    ):
        return False
    projections = []
    timestamps = []
    for item in observations:
        projection = copy.deepcopy(item)
        checked_at = projection.pop("checked_at", None)
        try:
            timestamps.append(recovery_timestamp(checked_at, "zero observation time"))
        except LiveTestError:
            return False
        projections.append(projection)
    final_projection = copy.deepcopy(final_inventory)
    final_projection.pop("checked_at", None)
    try:
        proven_at = recovery_timestamp(proof.get("proven_at"), "zero proof time")
    except LiveTestError:
        return False
    if (
        projections[0] != projections[1]
        or projections[1] != projections[2]
        or final_inventory != observations[2]
        or final_projection != projections[2]
        or timestamps != sorted(timestamps)
        or timestamps[2] - timestamps[0] < dt.timedelta(seconds=60)
        or proven_at < timestamps[2]
    ):
        return False
    return True


def unresolved_recovery_review_exists(execution_id: str) -> bool:
    now = dt.datetime.now(dt.timezone.utc)
    for path in recovery_review_entries(execution_id):
        try:
            raw = private_file_bytes(
                path,
                maximum_bytes=MAX_STATE_JSON_BYTES,
                label="lost-ledger recovery review",
            )
            if hashlib.sha256(raw).hexdigest() != path.stem.removeprefix("review-"):
                raise LiveTestError("recovery review file digest changed")
            review = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LiveTestError("recovery review is unreadable") from error
        if not isinstance(review, dict) or review.get("execution_id") != execution_id:
            raise LiveTestError("recovery review identity changed")
        expires = recovery_timestamp(review.get("expires_at"), "recovery review expiry")
        if now <= expires:
            return True
    return False


def assert_no_unresolved_local_live_state_for_init(execution_id: str) -> None:
    state_root = ensure_live_state_root()
    descriptor = open_private_directory(state_root)
    os.close(descriptor)
    resolved: set[str] = set()
    allowed_internal = {".locks", ".recovery-reviews", ".retired-executions"}
    with os.scandir(state_root) as children:
        for child in children:
            if child.name in allowed_internal:
                if not child.is_dir(follow_symlinks=False):
                    raise LiveTestError("durable live-state internal entry is unsafe")
                internal_descriptor = open_private_directory(Path(child.path))
                os.close(internal_descriptor)
                continue
            if EXECUTION_PATTERN.fullmatch(child.name) is None or not child.is_dir(
                follow_symlinks=False
            ):
                raise LiveTestError("durable live-state root contains an unsafe entry")
            path, ledger = load_ledger(child.name)
            if path.parent != Path(child.path):
                raise LiveTestError("durable execution path changed during init gate")
            if not retained_zero_proof_is_valid(child.name, ledger):
                raise LiveTestError(
                    f"unresolved live execution {child.name} blocks fresh initialization"
                )
            resolved.add(child.name)

    reviews_root = state_root / ".recovery-reviews"
    if os.path.lexists(reviews_root):
        review_descriptor = open_private_directory(reviews_root)
        os.close(review_descriptor)
        with os.scandir(reviews_root) as children:
            for child in children:
                if EXECUTION_PATTERN.fullmatch(child.name) is None or not child.is_dir(
                    follow_symlinks=False
                ):
                    raise LiveTestError("recovery review root contains an unsafe entry")
                if child.name not in resolved and unresolved_recovery_review_exists(
                    child.name
                ):
                    raise LiveTestError(
                        f"unresolved recovery review {child.name} blocks fresh initialization"
                    )

    retired_root = state_root / ".retired-executions"
    if os.path.lexists(retired_root):
        retired_descriptor = open_private_directory(retired_root)
        os.close(retired_descriptor)
        with os.scandir(retired_root) as children:
            for child in children:
                match = re.fullmatch(r"(bft-[a-z0-9-]{4,20})\.json", child.name)
                if match is None or not child.is_file(follow_symlinks=False):
                    raise LiveTestError(
                        "retired execution root contains an unsafe entry"
                    )
                retired_id = match.group(1)
                read_retired_execution_marker(retired_id)
                if retired_id not in resolved:
                    raise LiveTestError(
                        f"retired execution {retired_id} has no retained zero proof"
                    )
    if execution_id in resolved:
        raise LiveTestError("execution ID is retired; use a fresh execution ID")
    legacy_root = root_dir().joinpath(*LEGACY_LIVE_STATE_PARTS)
    if os.path.lexists(legacy_root):
        if legacy_root.is_symlink() or not legacy_root.is_dir():
            raise LiveTestError("legacy live-state root is unsafe")
        with os.scandir(legacy_root) as children:
            for child in children:
                if EXECUTION_PATTERN.fullmatch(child.name) is None or not child.is_dir(
                    follow_symlinks=False
                ):
                    raise LiveTestError(
                        "legacy live-state root contains an unsafe entry"
                    )
                legacy_ledger = Path(child.path) / "ledger.json"
                if os.path.lexists(legacy_ledger) or child.name not in resolved:
                    raise LiveTestError(
                        f"unresolved legacy execution {child.name} blocks fresh initialization"
                    )


def assert_no_account_live_state_for_init(
    execution_id: str, account_id: str, partition: str, region: str
) -> None:
    tagged_resources: list[dict[str, Any]] = []
    for managed_by in (
        MANAGED_BY,
        "bridgefu-test-bootstrap",
        "bridgefu-cloudformation",
    ):
        tagged_resources.extend(
            recovery_paginated_items(
                [
                    "resourcegroupstaggingapi",
                    "get-resources",
                    "--region",
                    region,
                    "--resources-per-page",
                    "100",
                    "--tag-filters",
                    f"Key=Project,Values={PROJECT}",
                    f"Key=ManagedBy,Values={managed_by}",
                ],
                list_key="ResourceTagMappingList",
                response_token="PaginationToken",
                request_token="--pagination-token",
            )
        )
    if tagged_resources:
        raise LiveTestError(
            "AWS account still contains Bridgefu test-owned resources; prove zero "
            "state before starting a fresh execution"
        )

    stack_name_pattern = re.compile(
        r"^bridgefu-bft-[a-z0-9-]{4,20}(?:-bootstrap|-qualification)?$"
    )
    stack_history = recovery_stack_history(region)
    requested_stack_names = {
        f"bridgefu-{execution_id}",
        f"bridgefu-{execution_id}-qualification",
        f"bridgefu-{execution_id}-bootstrap",
    }
    requested_history = [
        item
        for item in stack_history
        if item.get("StackName") in requested_stack_names
        and str(item.get("StackId", "")).startswith(
            f"arn:{partition}:cloudformation:{region}:{account_id}:stack/"
        )
    ]
    if requested_history:
        raise LiveTestError(
            "execution ID appears in CloudFormation history; use a fresh execution ID"
        )
    active_stacks = [
        item
        for item in stack_history
        if item.get("StackStatus") != "DELETE_COMPLETE"
        and isinstance(item.get("StackName"), str)
        and stack_name_pattern.fullmatch(item["StackName"])
        and str(item.get("StackId", "")).startswith(
            f"arn:{partition}:cloudformation:{region}:{account_id}:stack/"
        )
    ]
    if active_stacks:
        raise LiveTestError(
            "AWS account still contains a Bridgefu test CloudFormation stack"
        )

    buckets = aws_json(["s3api", "list-buckets"])
    bucket_rows = buckets.get("Buckets") if isinstance(buckets, dict) else None
    if not isinstance(bucket_rows, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("Name"), str)
        for item in bucket_rows
    ):
        raise LiveTestError("AWS bucket inventory is invalid")
    artifact_pattern = re.compile(
        rf"^bridgefu-recipe-{re.escape(account_id)}-{re.escape(region)}-"
        r"bft-[a-z0-9-]{4,20}$"
    )
    demo_pattern = re.compile(
        rf"^bfu-{re.escape(account_id)}-{re.escape(region)}-"
        r"bft-[a-z0-9-]{4,20}-site$"
    )
    if any(
        artifact_pattern.fullmatch(item["Name"]) or demo_pattern.fullmatch(item["Name"])
        for item in bucket_rows
    ):
        raise LiveTestError("AWS account still contains a Bridgefu test S3 bucket")

    repositories = recovery_paginated_items(
        [
            "ecr",
            "describe-repositories",
            "--region",
            region,
            "--registry-id",
            account_id,
            "--max-results",
            "1000",
        ],
        list_key="repositories",
        response_token="nextToken",
        request_token="--next-token",
    )
    if any(
        re.fullmatch(
            r"bridgefu-test/bft-[a-z0-9-]{4,20}", str(item.get("repositoryName", ""))
        )
        and str(item.get("repositoryArn", "")).startswith(
            f"arn:{partition}:ecr:{region}:{account_id}:repository/"
        )
        for item in repositories
    ):
        raise LiveTestError("AWS account still contains a Bridgefu test ECR repository")

    roles = recovery_paginated_items(
        ["iam", "list-roles", "--max-items", "1000"],
        list_key="Roles",
        response_token="Marker",
        request_token="--marker",
    )
    policies = recovery_paginated_items(
        ["iam", "list-policies", "--scope", "Local", "--max-items", "1000"],
        list_key="Policies",
        response_token="Marker",
        request_token="--marker",
    )
    role_pattern = re.compile(
        r"^bridgefu-bft-[a-z0-9-]{4,20}-(?:deployer|cloudformation|qualifier|runner)$"
    )
    policy_pattern = re.compile(r"^bridgefu-bft-[a-z0-9-]{4,20}-deployer-.+$")
    if any(
        role_pattern.fullmatch(str(item.get("RoleName", ""))) for item in roles
    ) or any(
        policy_pattern.fullmatch(str(item.get("PolicyName", ""))) for item in policies
    ):
        raise LiveTestError("AWS account still contains Bridgefu test bootstrap IAM")


def assert_lost_ledger_state_is_absent(
    execution_id: str, *, allow_matching_retired_marker: bool
) -> dict[str, Any] | None:
    destination = ledger_path(execution_id)
    legacy = legacy_ledger_path(execution_id)
    if os.path.lexists(destination.parent):
        raise LiveTestError(
            "lost-ledger recovery refuses an existing durable execution directory"
        )
    if os.path.lexists(legacy) or os.path.lexists(legacy.parent):
        raise LiveTestError("lost-ledger recovery refuses existing legacy live state")
    marker = read_retired_execution_marker(execution_id)
    if marker is not None and not allow_matching_retired_marker:
        raise LiveTestError("execution ID is already permanently retired")
    return marker


def recovery_review_entries(execution_id: str) -> list[Path]:
    directory = recovery_review_directory(execution_id)
    if not directory.exists():
        return []
    descriptor = open_private_directory(directory)
    os.close(descriptor)
    entries: list[Path] = []
    with os.scandir(directory) as children:
        for child in children:
            details = child.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or details.st_nlink != 1
                or details.st_mode & 0o077
                or re.fullmatch(r"review-[0-9a-f]{64}\.json", child.name) is None
            ):
                raise LiveTestError(
                    "recovery review directory contains an unsafe entry"
                )
            entries.append(Path(child.path))
    if len(entries) > MAX_RECOVERY_REVIEW_FILES:
        raise LiveTestError("recovery review file limit exceeded")
    return sorted(entries)


def write_recovery_review(
    execution_id: str, review: dict[str, Any]
) -> tuple[Path, str]:
    encoded = (json.dumps(review, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_STATE_JSON_BYTES:
        raise LiveTestError("recovery review exceeds its byte boundary")
    digest = hashlib.sha256(encoded).hexdigest()
    directory = recovery_review_directory(execution_id)
    ensure_live_state_root()
    ensure_private_directory(directory.parent)
    ensure_private_directory(directory)
    entries = recovery_review_entries(execution_id)
    path = directory / f"review-{digest}.json"
    if path in entries:
        existing_raw = private_file_bytes(
            path,
            maximum_bytes=MAX_STATE_JSON_BYTES,
            label="lost-ledger recovery review",
        )
        existing = json.loads(existing_raw.decode("utf-8"))
        if existing != review or hashlib.sha256(existing_raw).hexdigest() != digest:
            raise LiveTestError("existing recovery review differs from its digest")
        return path, digest
    if len(entries) >= MAX_RECOVERY_REVIEW_FILES:
        raise LiveTestError("recovery review file limit exceeded")
    immutable_private_json(path, review)
    installed_raw = private_file_bytes(
        path,
        maximum_bytes=MAX_STATE_JSON_BYTES,
        label="lost-ledger recovery review",
    )
    if hashlib.sha256(installed_raw).hexdigest() != digest:
        raise LiveTestError("recovery review durable readback changed")
    return path, digest


def read_recovery_review(execution_id: str, digest: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise LiveTestError(
            "--review-sha256 must contain exactly 64 lowercase hex digits"
        )
    entries = recovery_review_entries(execution_id)
    path = recovery_review_directory(execution_id) / f"review-{digest}.json"
    if path not in entries:
        raise LiveTestError("the exact immutable recovery review does not exist")
    try:
        raw = private_file_bytes(
            path,
            maximum_bytes=MAX_STATE_JSON_BYTES,
            label="lost-ledger recovery review",
        )
        review = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveTestError("lost-ledger recovery review is unreadable") from error
    if not isinstance(review, dict) or hashlib.sha256(raw).hexdigest() != digest:
        raise LiveTestError("lost-ledger recovery review digest changed")
    expected_fields = {
        "schema_version",
        "review_kind",
        "execution_id",
        "account_id",
        "region",
        "bootstrap_stack_id",
        "expect_demo_site",
        "reviewed_at",
        "expires_at",
        "controller_sha256",
        "inventory_sha256",
        "teardown_authority_sha256",
        "inventory",
        "teardown_authority",
    }
    if (
        set(review) != expected_fields
        or review.get("schema_version") != 1
        or review.get("review_kind") != "bootstrap_only_teardown_recovery"
        or review.get("execution_id") != execution_id
        or not isinstance(review.get("expect_demo_site"), bool)
        or review.get("controller_sha256") != recovery_controller_sha256()
        or review.get("inventory_sha256")
        != canonical_json_sha256(review.get("inventory"))
        or review.get("teardown_authority_sha256")
        != canonical_json_sha256(review.get("teardown_authority"))
        or review.get("teardown_authority")
        != recovery_teardown_authority_projection(review.get("inventory"))
    ):
        raise LiveTestError("lost-ledger recovery review contract changed")
    reviewed_at = recovery_timestamp(
        review.get("reviewed_at"), "recovery review timestamp"
    )
    expires_at = recovery_timestamp(review.get("expires_at"), "recovery review expiry")
    now = dt.datetime.now(dt.timezone.utc)
    if (
        expires_at - reviewed_at != dt.timedelta(seconds=RECOVERY_REVIEW_TTL_SECONDS)
        or reviewed_at > now + dt.timedelta(minutes=5)
        or now > expires_at
    ):
        raise LiveTestError("lost-ledger recovery review is expired or time-invalid")
    return review


def validate_recovery_confirmations(args: argparse.Namespace, *, review: bool) -> None:
    if args.confirm_account != args.account_id:
        raise LiveTestError("--confirm-account must exactly equal --account-id")
    if args.confirm_region != args.region:
        raise LiveTestError("--confirm-region must exactly equal --region")
    if review:
        if args.confirm_execution != args.execution_id:
            raise LiveTestError(
                "--confirm-execution must exactly equal the execution ID"
            )
    elif args.confirm != args.execution_id:
        raise LiveTestError("--confirm must exactly equal the execution ID")


def recover_lost_ledger_review(args: argparse.Namespace) -> None:
    validate_recovery_confirmations(args, review=True)
    assert_lost_ledger_state_is_absent(
        args.execution_id, allow_matching_retired_marker=False
    )
    inventory = recovery_lost_ledger_inventory(
        execution_id=args.execution_id,
        account_id=args.account_id,
        region=args.region,
        bootstrap_stack_id=args.bootstrap_stack_id,
        expect_demo_site=args.expect_demo_site == "true",
    )
    authority = recovery_teardown_authority_projection(inventory)
    reviewed_at = dt.datetime.now(dt.timezone.utc)
    review = {
        "schema_version": 1,
        "review_kind": "bootstrap_only_teardown_recovery",
        "execution_id": args.execution_id,
        "account_id": args.account_id,
        "region": args.region,
        "bootstrap_stack_id": args.bootstrap_stack_id,
        "expect_demo_site": args.expect_demo_site == "true",
        "reviewed_at": recovery_iso(reviewed_at),
        "expires_at": recovery_iso(
            reviewed_at + dt.timedelta(seconds=RECOVERY_REVIEW_TTL_SECONDS)
        ),
        "controller_sha256": recovery_controller_sha256(),
        "inventory_sha256": canonical_json_sha256(inventory),
        "teardown_authority_sha256": canonical_json_sha256(authority),
        "inventory": inventory,
        "teardown_authority": authority,
    }
    path, digest = write_recovery_review(args.execution_id, review)
    print(
        json.dumps(
            {
                "review_path": os.fspath(path),
                "review_sha256": digest,
                "expires_at": review["expires_at"],
                "aws_effect": "read_only",
                "next_action": "recover-lost-ledger-execute performs local adoption only",
            },
            indent=2,
            sort_keys=True,
        )
    )


def recovered_ledger_from_review(
    review: dict[str, Any], inventory: dict[str, Any], review_sha256: str
) -> dict[str, Any]:
    authority = recovery_teardown_authority_projection(inventory)
    identity_binding = inventory["identity"]
    bootstrap = inventory["bootstrap"]
    outputs = bootstrap["outputs"]
    parameters = bootstrap["parameters"]
    expected_names = inventory["expected_names"]
    created_resources: list[dict[str, str]] = []
    if inventory["artifact_bucket"]["exists"]:
        created_resources.append(
            {"type": "s3_bucket", "id": inventory["artifact_bucket"]["name"]}
        )
    if inventory["ecr_repository"]["exists"]:
        created_resources.append(
            {
                "type": "ecr_repository",
                "id": inventory["ecr_repository"]["name"],
            }
        )
    recovered_at = review["reviewed_at"]
    ledger = {
        "schema_version": 1,
        "execution_id": inventory["execution_id"],
        "project": PROJECT,
        "managed_by": MANAGED_BY,
        "recipe": RECIPE,
        "created_at": recovered_at,
        "qualification_deadline_at": recovered_at,
        "cost_ceiling_type": "teardown_only_recovery",
        "status": "recovery_teardown_only",
        "recovery_adoption_status": "recovery_teardown_only",
        "recovery_mode": "teardown_only",
        "region": identity_binding["region"],
        "partition": identity_binding["partition"],
        "account_id": identity_binding["account_id"],
        "trusted_principal_arn": parameters["TrustedPrincipalArn"],
        "original_trusted_principal_arn": parameters["TrustedPrincipalArn"],
        "initial_caller_session_arn": identity_binding["caller_arn"],
        "recovery_authorizer_principal_arn": identity_binding["durable_principal_arn"],
        "recovery_authorizer_session_arn": identity_binding["caller_arn"],
        "root_bootstrap_exception": False,
        "connect_instance_arn": parameters["ConnectInstanceArn"],
        "target_flow_arn": parameters["ConnectInstanceArn"] + "/contact-flow/unused",
        "connect_mode": "disposable",
        "public_hosted_zone_id": "none",
        "public_hosted_zone_name": "none",
        "dns_mode": "ip_only",
        "sip_hostname": "unused.bridgefu.invalid",
        "sip_security": "sip_rtp",
        "runtime_profile": "starter",
        "enable_demo_site": parameters["EnableDemoSite"] == "true",
        "demo_site_bucket": (
            f"bfu-{identity_binding['account_id']}-{identity_binding['region']}-"
            f"{inventory['execution_id']}-site"
        ),
        "max_usd": 0.0,
        "cost_estimate": {"conservative_total": 0.0},
        "artifact_bucket": inventory["artifact_bucket"]["name"],
        "artifact_bucket_authority": inventory["artifact_bucket"],
        "ecr_repository": inventory["ecr_repository"]["name"],
        "ecr_repository_authority": inventory["ecr_repository"],
        "stack_name": expected_names["application_stack"],
        "application_stack_name": expected_names["application_stack"],
        "qualification_stack_name": expected_names["qualification_stack"],
        "bootstrap_stack_name": expected_names["bootstrap_stack"],
        "bootstrap_stack_id": bootstrap["stack_id"],
        "bootstrap_status_at_adoption": bootstrap["status"],
        "bootstrap_deployed_template_sha256": bootstrap["deployed_template_sha256"],
        "bootstrap_resource_authority": bootstrap["resources"],
        "bootstrap_managed_policy_arns": inventory["iam"]["policies"],
        "deployment_role_arn": outputs["DeploymentRoleArn"],
        "cloudformation_execution_role_arn": outputs["CloudFormationExecutionRoleArn"],
        "qualification_role_arn": outputs["QualificationRoleArn"],
        "qualification_runner_role_arn": outputs["QualificationRunnerRoleArn"],
        "qualification_source_eip_allocation_id": inventory["qualification_source"][
            "allocation_id"
        ],
        "qualification_source_cidr": inventory["qualification_source"]["cidr"],
        "vapi_teardown_mode": "not_created",
        "vapi_not_created_reason": "application_not_executed",
        "created_resources": created_resources,
        "recovery_review_sha256": review_sha256,
        "recovery_reviewed_at": review["reviewed_at"],
        "deployed_teardown_authority": authority,
        "deployed_teardown_authority_sha256": canonical_json_sha256(authority),
        "events": [
            {
                "at": recovered_at,
                "event": "lost_ledger_teardown_authority_adopted",
                "review_sha256": review_sha256,
            }
        ],
        "state_revision": 1,
        "previous_ledger_sha256": None,
    }
    return ledger


def install_recovered_ledger(
    ledger: dict[str, Any], authority: dict[str, Any], review_sha256: str
) -> Path:
    execution_id = ledger["execution_id"]
    destination = ledger_path(execution_id)
    state_root = ensure_live_state_root()
    authority_sha256 = canonical_json_sha256(authority)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{execution_id}-recovery-", dir=state_root)
    )
    os.chmod(temporary, 0o700)
    try:
        immutable_private_json(temporary / "recovery-authority.json", authority)
        atomic_json(temporary / "ledger.json", ledger)
        atomic_json(
            temporary / "lost-ledger-adoption-evidence.json",
            {
                "schema_version": 1,
                "execution_id": execution_id,
                "adopted_at": ledger["created_at"],
                "scope": "bootstrap_only_teardown_only",
                "review_sha256": review_sha256,
                "recovery_authority_sha256": authority_sha256,
                "deployed_teardown_authority_sha256": ledger[
                    "deployed_teardown_authority_sha256"
                ],
                "aws_mutations": [],
            },
        )
        if os.path.lexists(destination.parent):
            raise LiveTestError("durable execution state appeared during recovery")
        temporary.rename(destination.parent)
        root_descriptor = open_private_directory(state_root)
        try:
            os.fsync(root_descriptor)
        finally:
            os.close(root_descriptor)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    installed = validate_durable_ledger(destination, execution_id)
    if installed != ledger:
        raise LiveTestError("installed lost-ledger authority changed on readback")
    ensure_retired_marker_for_ledger(installed, review_sha256, authority_sha256)
    return destination


def ensure_retired_marker_for_ledger(
    ledger: dict[str, Any], review_sha256: str, authority_sha256: str
) -> None:
    marker = {
        "schema_version": 1,
        "marker_kind": "lost_ledger_teardown_only",
        "execution_id": ledger["execution_id"],
        "retired_at": ledger["created_at"],
        "recovery_review_sha256": review_sha256,
        "recovery_authority_sha256": authority_sha256,
    }
    existing = read_retired_execution_marker(ledger["execution_id"])
    if existing is None:
        marker_path = retired_execution_marker_path(ledger["execution_id"])
        ensure_private_directory(marker_path.parent)
        immutable_private_json(marker_path, marker)
    elif existing != marker:
        raise LiveTestError(
            "retired execution-ID marker differs from recovery authority"
        )


def recover_lost_ledger_execute(args: argparse.Namespace) -> None:
    validate_recovery_confirmations(args, review=False)
    destination = ledger_path(args.execution_id)
    if os.path.lexists(destination):
        path, installed = load_ledger(args.execution_id)
        if (
            installed.get("recovery_mode") != "teardown_only"
            or installed.get("recovery_review_sha256") != args.review_sha256
            or installed.get("account_id") != args.account_id
            or installed.get("region") != args.region
        ):
            raise LiveTestError("existing ledger cannot resume this recovery adoption")
        ensure_retired_marker_for_ledger(
            installed,
            args.review_sha256,
            installed["recovery_authority_sha256"],
        )
        print(path)
        return
    marker = assert_lost_ledger_state_is_absent(
        args.execution_id, allow_matching_retired_marker=True
    )
    review = read_recovery_review(args.execution_id, args.review_sha256)
    if (
        review.get("account_id") != args.account_id
        or review.get("region") != args.region
    ):
        raise LiveTestError("recovery execute target differs from its review")
    inventory = recovery_lost_ledger_inventory(
        execution_id=args.execution_id,
        account_id=args.account_id,
        region=args.region,
        bootstrap_stack_id=review["bootstrap_stack_id"],
        expect_demo_site=review["expect_demo_site"],
    )
    authority_projection = recovery_teardown_authority_projection(inventory)
    if (
        authority_projection != review["teardown_authority"]
        or canonical_json_sha256(authority_projection)
        != review["teardown_authority_sha256"]
    ):
        raise LiveTestError("AWS teardown authority changed after recovery review")
    ledger = recovered_ledger_from_review(review, inventory, args.review_sha256)
    authority = lost_ledger_recovery_authority(ledger)
    ledger["recovery_authority_sha256"] = canonical_json_sha256(authority)
    if marker is not None:
        raise LiveTestError("retired execution-ID marker cannot resume this adoption")
    path = install_recovered_ledger(ledger, authority, args.review_sha256)
    print(
        json.dumps(
            {
                "ledger_path": os.fspath(path),
                "authority": "bootstrap_only_teardown_only",
                "aws_mutations": [],
                "next_actions": [
                    (
                        "python3 scripts/aws-recipe-live-test.py --execution-id "
                        f"{args.execution_id} inventory"
                    ),
                    (
                        "python3 scripts/aws-recipe-live-test.py --execution-id "
                        f"{args.execution_id} destroy "
                        f"--confirm {args.execution_id}"
                    ),
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


def require_owned_stack_for_deletion(
    ledger: dict[str, Any],
    environment: dict[str, str] | None,
    stack_name: str,
    expected_stack_id: str | None,
) -> None:
    if not isinstance(expected_stack_id, str) or not expected_stack_id.startswith(
        "arn:"
    ):
        raise LiveTestError("stack deletion has no exact ledger-bound stack ID")
    response = aws_json(
        [
            "cloudformation",
            "describe-stacks",
            "--region",
            ledger["region"],
            "--stack-name",
            expected_stack_id,
        ],
        env=environment,
    )
    stacks = response.get("Stacks") if isinstance(response, dict) else None
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or stacks[0].get("StackName") != stack_name
        or stacks[0].get("StackId") != expected_stack_id
    ):
        raise LiveTestError("stack deletion target differs from the exact ledger stack")
    require_ownership_tags(stacks[0].get("Tags", []), ledger["execution_id"])


def require_owned_bucket_for_deletion(
    ledger: dict[str, Any], environment: dict[str, str]
) -> None:
    bucket = ledger.get("artifact_bucket")
    if not isinstance(bucket, str) or not created_resource(ledger, "s3_bucket", bucket):
        raise LiveTestError("artifact bucket is not recorded as execution-owned")
    tags = aws_json(
        [
            "s3api",
            "get-bucket-tagging",
            "--region",
            ledger["region"],
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            ledger["account_id"],
        ],
        env=environment,
    )
    if not isinstance(tags, dict) or not isinstance(tags.get("TagSet"), list):
        raise LiveTestError("artifact bucket ownership tags are unavailable")
    require_ownership_tags(tags["TagSet"], ledger["execution_id"])


def require_owned_ecr_for_deletion(
    ledger: dict[str, Any], environment: dict[str, str]
) -> None:
    repository_name = ledger.get("ecr_repository")
    if not isinstance(repository_name, str) or not created_resource(
        ledger, "ecr_repository", repository_name
    ):
        raise LiveTestError("ECR repository is not recorded as execution-owned")
    response = aws_json(
        [
            "ecr",
            "describe-repositories",
            "--region",
            ledger["region"],
            "--registry-id",
            ledger["account_id"],
            "--repository-names",
            repository_name,
        ],
        env=environment,
    )
    repositories = response.get("repositories") if isinstance(response, dict) else None
    expected_arn = (
        f"arn:{ledger['partition']}:ecr:{ledger['region']}:"
        f"{ledger['account_id']}:repository/{repository_name}"
    )
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise LiveTestError("ECR deletion target is not exact")
    repository = repositories[0]
    if (
        repository.get("registryId") != ledger["account_id"]
        or repository.get("repositoryName") != repository_name
        or repository.get("repositoryArn") != expected_arn
    ):
        raise LiveTestError("ECR deletion target name changed")
    tags = aws_json(
        [
            "ecr",
            "list-tags-for-resource",
            "--region",
            ledger["region"],
            "--resource-arn",
            repository["repositoryArn"],
        ],
        env=environment,
    )
    if not isinstance(tags, dict) or not isinstance(tags.get("tags"), list):
        raise LiveTestError("ECR ownership tags are unavailable")
    require_ownership_tags(tags["tags"], ledger["execution_id"])


def owned_connect_log_group_exists(
    ledger: dict[str, Any], environment: dict[str, str] | None
) -> bool:
    name = f"/aws/connect/{ledger['execution_id']}-connect"
    response = aws_json(
        [
            "logs",
            "describe-log-groups",
            "--region",
            ledger["region"],
            "--log-group-name-prefix",
            name,
        ],
        env=environment,
    )
    groups = response.get("logGroups") if isinstance(response, dict) else None
    if not isinstance(groups, list):
        raise LiveTestError("Connect log-group inventory is unavailable")
    exact = [group for group in groups if group.get("logGroupName") == name]
    if not exact:
        return False
    if len(exact) != 1:
        raise LiveTestError("Connect log-group deletion target is ambiguous")
    arn = exact[0].get("logGroupArn") or exact[0].get("arn")
    if not isinstance(arn, str):
        raise LiveTestError("Connect log group has no exact ARN")
    arn = arn.removesuffix(":*")
    tags = aws_json(
        [
            "logs",
            "list-tags-for-resource",
            "--region",
            ledger["region"],
            "--resource-arn",
            arn,
        ],
        env=environment,
    )
    observed = tags.get("tags") if isinstance(tags, dict) else None
    if not isinstance(observed, dict):
        raise LiveTestError("Connect log-group ownership tags are unavailable")
    expected = {
        "Project": PROJECT,
        "ManagedBy": "bridgefu-cloudformation",
        "BridgefuExecutionId": ledger["execution_id"],
        "BridgefuRecipe": RECIPE,
    }
    if any(observed.get(key) != value for key, value in expected.items()):
        raise LiveTestError("Connect log-group ownership tags changed")
    return True


def prove_teardown_zero_state(
    path: Path,
    ledger: dict[str, Any],
    *,
    success_event: str,
    incomplete_event: str,
) -> None:
    bind_active_ledger_identity(ledger)
    application_review_stack_id = ledger.get("review_stack_id")
    application_deployed_stack_id = ledger.get("stack_id")
    qualification_review_stack_id = ledger.get("qualification_review_stack_id")
    qualification_deployed_stack_id = ledger.get("qualification_stack_id")
    if (
        application_review_stack_id is not None
        and application_deployed_stack_id is not None
        and application_review_stack_id != application_deployed_stack_id
    ):
        raise LiveTestError("application teardown proof has conflicting stack IDs")
    if (
        qualification_review_stack_id is not None
        and qualification_deployed_stack_id is not None
        and qualification_review_stack_id != qualification_deployed_stack_id
    ):
        raise LiveTestError("qualification teardown proof has conflicting stack IDs")
    stack_bindings = [
        (
            ledger["stack_name"],
            application_deployed_stack_id or application_review_stack_id,
        ),
        (
            ledger["qualification_stack_name"],
            qualification_deployed_stack_id or qualification_review_stack_id,
        ),
        (ledger["bootstrap_stack_name"], ledger.get("bootstrap_stack_id")),
    ]
    final_inventory: dict[str, Any] = {}
    zero_observations: list[dict[str, Any]] = []
    last_projection: dict[str, Any] | None = None
    first_zero_at: float | None = None
    proof_started = time.monotonic()
    # Secrets Manager force deletion is asynchronous. Keep the proof bounded,
    # resumable, and long enough to prove three stable zero observations across
    # at least one minute rather than treating one eventually-consistent read as
    # authoritative absence.
    for _attempt in range(180):
        for stack_name, stack_id in stack_bindings:
            assert_absent_stack(stack_name, ledger["region"])
            if stack_id is not None:
                exact_stack_id = require_stack_id_for_name(
                    ledger, stack_id, stack_name, "teardown proof"
                )
                exact_status = stack_status_if_exists(exact_stack_id, ledger["region"])
                if exact_status not in {None, "DELETE_COMPLETE"}:
                    raise LiveTestError("exact teardown stack ID still exists")
        final_inventory = inventory_for_execution(ledger)
        if (
            not isinstance(final_inventory, dict)
            or set(final_inventory) != TEARDOWN_INVENTORY_KEYS
        ):
            raise LiveTestError("teardown inventory schema is not exact")
        projection = copy.deepcopy(final_inventory)
        projection.pop("checked_at", None)
        now = time.monotonic()
        if not inventory_has_leftovers(final_inventory):
            if projection != last_projection:
                zero_observations = []
                first_zero_at = now
            zero_observations.append(final_inventory)
            last_projection = projection
            if (
                len(zero_observations) >= 3
                and first_zero_at is not None
                and now - first_zero_at >= 60
            ):
                break
        else:
            zero_observations = []
            last_projection = None
            first_zero_at = None
        if now - proof_started >= 15 * 60:
            break
        time.sleep(30 if zero_observations else 5)
    atomic_json(path.parent / "teardown-inventory.json", final_inventory)
    zero_proof = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "required_observations": 3,
        "minimum_span_seconds": 60,
        "observations": zero_observations[-3:],
        "proven_at": utc_now(),
    }
    atomic_json(path.parent / "teardown-zero-proof.json", zero_proof)
    if (
        inventory_has_leftovers(final_inventory)
        or len(zero_observations) < 3
        or first_zero_at is None
        or time.monotonic() - first_zero_at < 60
    ):
        ledger["status"] = "teardown_incomplete"
        record(path, ledger, incomplete_event)
        raise LiveTestError(
            "final inventory did not prove three stable zero observations"
        )
    ledger["status"] = "destroyed"
    ledger["destroyed_at"] = utc_now()
    record(path, ledger, success_event)
    print(path.parent / "teardown-inventory.json")


def recovered_direct_environment(ledger: dict[str, Any]) -> dict[str, str]:
    environment = os.environ.copy()
    environment["AWS_REGION"] = ledger["region"]
    environment["AWS_DEFAULT_REGION"] = ledger["region"]
    return environment


def revalidate_recovered_teardown_authority(ledger: dict[str, Any]) -> dict[str, Any]:
    binding = bind_active_ledger_identity(ledger)
    if binding["durable_principal_arn"] != ledger.get(
        "recovery_authorizer_principal_arn"
    ):
        raise LiveTestError("active AWS principal differs from the recovery authorizer")
    inventory = recovery_lost_ledger_inventory(
        execution_id=ledger["execution_id"],
        account_id=ledger["account_id"],
        region=ledger["region"],
        bootstrap_stack_id=ledger["bootstrap_stack_id"],
        expect_demo_site=bool(ledger.get("enable_demo_site")),
    )
    authority = recovery_teardown_authority_projection(inventory)
    if authority != ledger.get("deployed_teardown_authority") or canonical_json_sha256(
        authority
    ) != ledger.get("deployed_teardown_authority_sha256"):
        raise LiveTestError(
            "current AWS resources differ from the recovered teardown authority"
        )
    return inventory


def recovered_destroy_intent_is_valid(path: Path, ledger: dict[str, Any]) -> bool:
    intent_path = path.parent / "recovered-destroy-intent.json"
    if not os.path.lexists(intent_path):
        return False
    try:
        intent = json.loads(
            private_file_bytes(
                intent_path,
                maximum_bytes=256 * 1024,
                label="recovered destroy intent",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveTestError("recovered destroy intent is unreadable") from error
    if (
        not isinstance(intent, dict)
        or set(intent)
        != {
            "schema_version",
            "intent_kind",
            "execution_id",
            "authorized_at",
            "recovery_review_sha256",
            "recovery_authority_sha256",
            "deployed_teardown_authority_sha256",
            "recovery_authorizer_principal_arn",
        }
        or intent.get("schema_version") != 1
        or intent.get("intent_kind") != "recovered_teardown_first_mutation"
        or intent.get("execution_id") != ledger.get("execution_id")
        or intent.get("recovery_review_sha256") != ledger.get("recovery_review_sha256")
        or intent.get("recovery_authority_sha256")
        != ledger.get("recovery_authority_sha256")
        or intent.get("deployed_teardown_authority_sha256")
        != ledger.get("deployed_teardown_authority_sha256")
        or intent.get("recovery_authorizer_principal_arn")
        != ledger.get("recovery_authorizer_principal_arn")
    ):
        raise LiveTestError("recovered destroy intent differs from ledger authority")
    recovery_timestamp(intent.get("authorized_at"), "recovered destroy intent time")
    return True


def write_recovered_destroy_intent(path: Path, ledger: dict[str, Any]) -> None:
    intent = {
        "schema_version": 1,
        "intent_kind": "recovered_teardown_first_mutation",
        "execution_id": ledger["execution_id"],
        "authorized_at": utc_now(),
        "recovery_review_sha256": ledger["recovery_review_sha256"],
        "recovery_authority_sha256": ledger["recovery_authority_sha256"],
        "deployed_teardown_authority_sha256": ledger[
            "deployed_teardown_authority_sha256"
        ],
        "recovery_authorizer_principal_arn": ledger[
            "recovery_authorizer_principal_arn"
        ],
    }
    immutable_private_json(path.parent / "recovered-destroy-intent.json", intent)


def destroy_recovered_teardown_only(path: Path, ledger: dict[str, Any]) -> None:
    binding = bind_active_ledger_identity(ledger)
    if binding["durable_principal_arn"] != ledger.get(
        "recovery_authorizer_principal_arn"
    ):
        raise LiveTestError("active AWS principal differs from the recovery authorizer")
    if ledger["status"] == "destroyed":
        prove_teardown_zero_state(
            path,
            ledger,
            success_event="recovered_teardown_reaudit_proven",
            incomplete_event="recovered_teardown_reaudit_incomplete",
        )
        return
    if not recovered_destroy_intent_is_valid(path, ledger):
        revalidate_recovered_teardown_authority(ledger)
        write_recovered_destroy_intent(path, ledger)
        ledger["status"] = "destroying"
        record(path, ledger, "recovered_teardown_authority_revalidated")

    environment = recovered_direct_environment(ledger)
    bootstrap_stack_id = ledger["bootstrap_stack_id"]
    bootstrap_status = stack_status_if_exists(
        bootstrap_stack_id, ledger["region"], environment
    )
    if bootstrap_status in {None, "DELETE_COMPLETE"}:
        prove_teardown_zero_state(
            path,
            ledger,
            success_event="recovered_teardown_reconciled",
            incomplete_event="recovered_teardown_incomplete",
        )
        return
    if bootstrap_status == "DELETE_FAILED":
        raise LiveTestError("recovered bootstrap stack deletion failed")
    if bootstrap_status == "DELETE_IN_PROGRESS":
        require_owned_stack_for_deletion(
            ledger,
            environment,
            ledger["bootstrap_stack_name"],
            bootstrap_stack_id,
        )
        aws_wait(
            [
                "cloudformation",
                "wait",
                "stack-delete-complete",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_stack_id,
            ],
            env=environment,
        )
        prove_teardown_zero_state(
            path,
            ledger,
            success_event="recovered_teardown_wait_reconciled",
            incomplete_event="recovered_teardown_incomplete",
        )
        return
    if bootstrap_status not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise LiveTestError("recovered bootstrap stack is not stable for deletion")

    repository_name = ledger["ecr_repository"]
    repository_exists = exact_probe_exists(
        [
            "ecr",
            "describe-repositories",
            "--region",
            ledger["region"],
            "--registry-id",
            ledger["account_id"],
            "--repository-names",
            repository_name,
        ],
        absent_markers=("RepositoryNotFoundException",),
        label="recovered ECR repository",
        environment=environment,
    )
    if repository_exists:
        require_owned_ecr_for_deletion(ledger, environment)
        exact_delete(
            [
                "ecr",
                "delete-repository",
                "--region",
                ledger["region"],
                "--registry-id",
                ledger["account_id"],
                "--repository-name",
                repository_name,
                "--force",
            ],
            environment=environment,
            absent_markers=("RepositoryNotFoundException",),
            label="recovered ECR repository",
        )
    record(path, ledger, "recovered_ecr_repository_deleted")

    bucket = ledger["artifact_bucket"]
    bucket_exists = exact_probe_exists(
        [
            "s3api",
            "head-bucket",
            "--region",
            ledger["region"],
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            ledger["account_id"],
        ],
        absent_markers=("(404)", "Not Found", "NoSuchBucket"),
        label="recovered artifact bucket",
        environment=environment,
    )
    if bucket_exists:
        require_owned_bucket_for_deletion(ledger, environment)
        empty_versioned_bucket(ledger, environment)
        exact_delete(
            [
                "s3api",
                "delete-bucket",
                "--region",
                ledger["region"],
                "--bucket",
                bucket,
                "--expected-bucket-owner",
                ledger["account_id"],
            ],
            environment=environment,
            absent_markers=("NoSuchBucket", "(404)", "Not Found"),
            label="recovered artifact bucket",
        )
    record(path, ledger, "recovered_artifact_bucket_deleted")

    require_owned_stack_for_deletion(
        ledger,
        environment,
        ledger["bootstrap_stack_name"],
        bootstrap_stack_id,
    )
    aws_json(
        [
            "cloudformation",
            "delete-stack",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
        ],
        env=environment,
    )
    record(path, ledger, "recovered_bootstrap_stack_delete_requested")
    aws_wait(
        [
            "cloudformation",
            "wait",
            "stack-delete-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_stack_id,
        ],
        env=environment,
    )
    ledger["status"] = "destroying_base_finalize"
    record(path, ledger, "recovered_bootstrap_stack_deleted")
    prove_teardown_zero_state(
        path,
        ledger,
        success_event="recovered_teardown_proven",
        incomplete_event="recovered_teardown_incomplete",
    )


def destroy(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    bind_active_ledger_identity(ledger)
    if ledger.get("recovery_mode") == "teardown_only":
        destroy_recovered_teardown_only(path, ledger)
        return
    if ledger["status"] == "destroyed":
        final_inventory = inventory_for_execution(ledger)
        atomic_json(path.parent / "teardown-inventory.json", final_inventory)
        if inventory_has_leftovers(final_inventory):
            ledger["status"] = "teardown_incomplete"
            record(path, ledger, "destroyed_ledger_reaudit_failed")
            raise LiveTestError(
                "destroyed ledger still owns resources; use exact administrator cleanup"
            )
        print(path.parent / "teardown-inventory.json")
        return
    recorded_bootstrap_stack_id = ledger.get("bootstrap_stack_id")
    bootstrap_identifier = ledger["bootstrap_stack_name"]
    if recorded_bootstrap_stack_id is not None:
        _bootstrap_name, bootstrap_identifier = exact_bootstrap_stack_identity(ledger)
    bootstrap_status = bound_stack_status_or_reject_replacement(
        ledger,
        None,
        ledger["bootstrap_stack_name"],
        recorded_bootstrap_stack_id,
        "bootstrap teardown",
    )
    if bootstrap_status is None:
        prove_teardown_zero_state(
            path,
            ledger,
            success_event="teardown_reconciled_after_bootstrap_delete",
            incomplete_event="teardown_reconcile_incomplete",
        )
        return
    if recorded_bootstrap_stack_id is None:
        raise LiveTestError("bootstrap stack exists without an exact ledger-bound ID")
    if bootstrap_status == "DELETE_FAILED":
        raise LiveTestError(
            "bootstrap stack deletion failed; inspect exact stack events"
        )
    if "deployment_role_arn" not in ledger:
        raise LiveTestError(
            "bootstrap role is missing; manual root cleanup is required"
        )
    env = assume_env(ledger, "deployment")
    application_review_stack_id = ledger.get("review_stack_id")
    application_deployed_stack_id = ledger.get("stack_id")
    if (
        application_review_stack_id is not None
        and application_deployed_stack_id is not None
        and application_review_stack_id != application_deployed_stack_id
    ):
        raise LiveTestError("application stack ID differs from its review authority")
    expected_application_stack_id = (
        application_deployed_stack_id or application_review_stack_id
    )
    application_identifier = (
        require_stack_id_for_name(
            ledger,
            expected_application_stack_id,
            ledger["stack_name"],
            "application teardown",
        )
        if expected_application_stack_id is not None
        else ledger["stack_name"]
    )
    application_status = bound_stack_status_or_reject_replacement(
        ledger,
        env,
        ledger["stack_name"],
        expected_application_stack_id,
        "application teardown",
    )
    application_exists = application_status is not None
    application_attempted = application_execution_was_attempted(ledger)
    if application_exists:
        if expected_application_stack_id is None:
            raise LiveTestError("application stack exists without an exact bound ID")
        application_description = stack_description(ledger, env, application_identifier)
        described_application_status = application_description.get("StackStatus")
        if (
            not isinstance(described_application_status, str)
            or described_application_status != application_status
        ):
            raise LiveTestError("application stack has no authoritative status")
        if (
            application_status == "REVIEW_IN_PROGRESS"
            and not application_execution_acceptance_was_recorded(ledger)
        ):
            root_stack_id = ledger.get("review_stack_id")
            if not isinstance(root_stack_id, str):
                raise LiveTestError("application review has no exact stack ID")
            authoritatively_unexecuted = (
                application_review_is_authoritatively_unexecuted(
                    ledger, env, root_stack_id
                )
            )
            application_description = stack_description(
                ledger, env, application_identifier
            )
            application_status = application_description.get("StackStatus")
            if not isinstance(application_status, str):
                raise LiveTestError("application stack has no authoritative status")
            application_attempted = not (
                authoritatively_unexecuted
                and application_status == "REVIEW_IN_PROGRESS"
            )
        if (
            application_status.endswith("_IN_PROGRESS")
            and application_status != "DELETE_IN_PROGRESS"
            and (application_status != "REVIEW_IN_PROGRESS" or application_attempted)
        ):
            try:
                aws_wait(
                    [
                        "cloudformation",
                        "wait",
                        "stack-create-complete",
                        "--region",
                        ledger["region"],
                        "--stack-name",
                        application_identifier,
                    ],
                    env=env,
                )
            except LiveTestError:
                # CREATE_FAILED is an expected waiter failure.  The exact
                # follow-up status, not the waiter exit code, is authoritative.
                pass
            env = assume_env(ledger, "deployment")
            application_description = stack_description(
                ledger, env, application_identifier
            )
            application_status = application_description.get("StackStatus")
            if not isinstance(application_status, str) or (
                application_status.endswith("_IN_PROGRESS")
                and application_status != "DELETE_IN_PROGRESS"
                and (
                    application_status != "REVIEW_IN_PROGRESS" or application_attempted
                )
            ):
                raise LiveTestError(
                    "application creation is still in progress; rerun teardown after it settles"
                )
        if application_status != "REVIEW_IN_PROGRESS":
            application_attempted = True
        require_owned_stack_for_deletion(
            ledger,
            env,
            ledger["stack_name"],
            expected_application_stack_id,
        )
    qualification_expected_stack_id: str | None = None
    if ledger.get("connect_mode") == "disposable":
        qualification_review_stack_id = ledger.get("qualification_review_stack_id")
        qualification_deployed_stack_id = ledger.get("qualification_stack_id")
        if (
            qualification_review_stack_id is not None
            and qualification_deployed_stack_id is not None
            and qualification_review_stack_id != qualification_deployed_stack_id
        ):
            raise LiveTestError(
                "qualification stack ID differs from its review authority"
            )
        qualification_expected_stack_id = (
            qualification_deployed_stack_id or qualification_review_stack_id
        )
        qualification_status = bound_stack_status_or_reject_replacement(
            ledger,
            env,
            ledger["qualification_stack_name"],
            qualification_expected_stack_id,
            "qualification teardown",
        )
        if qualification_status is not None and qualification_expected_stack_id is None:
            raise LiveTestError("qualification stack exists without an exact bound ID")
    stop_headless_build_before_teardown(path, ledger)
    if bootstrap_status == "DELETE_IN_PROGRESS":
        require_owned_stack_for_deletion(
            ledger,
            None,
            ledger["bootstrap_stack_name"],
            ledger.get("bootstrap_stack_id"),
        )
        aws_wait(
            [
                "cloudformation",
                "wait",
                "stack-delete-complete",
                "--region",
                ledger["region"],
                "--stack-name",
                bootstrap_identifier,
            ]
        )
        prove_teardown_zero_state(
            path,
            ledger,
            success_event="teardown_reconciled_after_bootstrap_wait",
            incomplete_event="teardown_reconcile_incomplete",
        )
        return
    vapi_teardown_mode = recover_vapi_teardown_contract(
        path,
        ledger,
        env,
        application_exists=application_exists,
        application_attempted=application_attempted,
    )
    if application_attempted and vapi_teardown_mode not in {
        "not_created",
        "owner_scan",
        "bound_ids",
    }:
        raise LiveTestError("attempted application teardown has no Vapi contract")
    stack_deletions = [
        (
            ledger["stack_name"],
            "recipe_stack",
            expected_application_stack_id,
        ),
    ]
    if ledger.get("connect_mode") == "disposable":
        stack_deletions.append(
            (
                ledger["qualification_stack_name"],
                "qualification_runner_stack",
                qualification_expected_stack_id,
            )
        )
    for stack_name, event_prefix, expected_stack_id in stack_deletions:
        stack_identifier = stack_name
        if expected_stack_id is not None:
            stack_identifier = require_stack_id_for_name(
                ledger, expected_stack_id, stack_name, "stack teardown"
            )
        stack_status = bound_stack_status_or_reject_replacement(
            ledger,
            env,
            stack_name,
            expected_stack_id,
            "stack teardown",
        )
        if stack_status is None:
            continue
        require_owned_stack_for_deletion(ledger, env, stack_name, expected_stack_id)
        if stack_status != "DELETE_IN_PROGRESS":
            aws_json(
                [
                    "cloudformation",
                    "delete-stack",
                    "--region",
                    ledger["region"],
                    "--stack-name",
                    stack_identifier,
                ],
                env=env,
            )
            ledger["status"] = "destroying"
            record(path, ledger, f"{event_prefix}_delete_requested")
        else:
            record(path, ledger, f"{event_prefix}_delete_reconciled")
        aws_wait(
            [
                "cloudformation",
                "wait",
                "stack-delete-complete",
                "--region",
                ledger["region"],
                "--stack-name",
                stack_identifier,
            ],
            env=env,
        )
        record(path, ledger, f"{event_prefix}_deleted")
    prove_vapi_teardown_contract(path, ledger, env)
    if ledger.get("vapi_api_key_secret_arn"):
        request_secret_force_delete(
            ledger,
            env,
            ledger["vapi_api_key_secret_arn"],
            label="temporary Vapi API-key secret",
        )
        record(path, ledger, "temporary_vapi_secret_delete_requested")
    if ledger.get("vapi_public_key_secret_arn"):
        request_secret_force_delete(
            ledger,
            env,
            ledger["vapi_public_key_secret_arn"],
            label="temporary Vapi public-key secret",
        )
        record(path, ledger, "temporary_vapi_public_key_secret_delete_requested")
    if ledger.get("private_tls_secret_arn"):
        request_secret_force_delete(
            ledger,
            env,
            ledger["private_tls_secret_arn"],
            label="HA private TLS secret",
        )
        record(path, ledger, "ha_private_tls_secret_delete_requested")
    if ledger.get("ecr_repository"):
        repository_exists = exact_probe_exists(
            [
                "ecr",
                "describe-repositories",
                "--region",
                ledger["region"],
                "--registry-id",
                ledger["account_id"],
                "--repository-names",
                ledger["ecr_repository"],
            ],
            absent_markers=("RepositoryNotFoundException",),
            label="ephemeral ECR repository",
            environment=env,
        )
        if repository_exists:
            require_owned_ecr_for_deletion(ledger, env)
            exact_delete(
                [
                    "ecr",
                    "delete-repository",
                    "--region",
                    ledger["region"],
                    "--registry-id",
                    ledger["account_id"],
                    "--repository-name",
                    ledger["ecr_repository"],
                    "--force",
                ],
                environment=env,
                absent_markers=("RepositoryNotFoundException",),
                label="ephemeral ECR repository",
            )
        record(path, ledger, "ecr_repository_deleted")
    if ledger.get("artifact_bucket"):
        bucket_exists = exact_probe_exists(
            [
                "s3api",
                "head-bucket",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--expected-bucket-owner",
                ledger["account_id"],
            ],
            absent_markers=("(404)", "Not Found", "NoSuchBucket"),
            label="ephemeral artifact bucket",
            environment=env,
        )
        if bucket_exists:
            require_owned_bucket_for_deletion(ledger, env)
            empty_versioned_bucket(ledger, env)
            exact_delete(
                [
                    "s3api",
                    "delete-bucket",
                    "--region",
                    ledger["region"],
                    "--bucket",
                    ledger["artifact_bucket"],
                    "--expected-bucket-owner",
                    ledger["account_id"],
                ],
                environment=env,
                absent_markers=("NoSuchBucket", "(404)", "Not Found"),
                label="ephemeral artifact bucket",
            )
        record(path, ledger, "artifact_bucket_deleted")
    if ledger.get("dns_mode") == "temporary_delegated_zone" and ledger.get(
        "public_hosted_zone_id"
    ) not in {None, "none"}:
        exact_delete(
            [
                "route53",
                "delete-hosted-zone",
                "--id",
                ledger["public_hosted_zone_id"],
            ],
            environment=env,
            absent_markers=("NoSuchHostedZone",),
            label="temporary delegated hosted zone",
        )
        record(path, ledger, "temporary_delegated_zone_deleted")
    if ledger.get("connect_mode") == "disposable":
        if owned_connect_log_group_exists(ledger, env):
            exact_delete(
                [
                    "logs",
                    "delete-log-group",
                    "--region",
                    ledger["region"],
                    "--log-group-name",
                    f"/aws/connect/{ledger['execution_id']}-connect",
                ],
                environment=env,
                absent_markers=("ResourceNotFoundException",),
                label="disposable Connect log group",
            )
        record(path, ledger, "connect_log_group_delete_requested")
    require_owned_stack_for_deletion(
        ledger,
        None,
        ledger["bootstrap_stack_name"],
        ledger.get("bootstrap_stack_id"),
    )
    aws_json(
        [
            "cloudformation",
            "delete-stack",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_identifier,
        ]
    )
    record(path, ledger, "bootstrap_stack_delete_requested")
    aws_wait(
        [
            "cloudformation",
            "wait",
            "stack-delete-complete",
            "--region",
            ledger["region"],
            "--stack-name",
            bootstrap_identifier,
        ]
    )
    ledger["status"] = "destroying_base_finalize"
    record(path, ledger, "bootstrap_stack_deleted")
    prove_teardown_zero_state(
        path,
        ledger,
        success_event="teardown_proven",
        incomplete_event="teardown_incomplete",
    )


def destroy_finalize(args: argparse.Namespace) -> None:
    """Prove zero state after an authorized administrator finished cleanup."""
    path, ledger = load_ledger(args.execution_id)
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    bind_active_ledger_identity(ledger)
    if ledger.get(
        "recovery_mode"
    ) == "teardown_only" and not recovered_destroy_intent_is_valid(path, ledger):
        raise LiveTestError(
            "recovered destroy-finalize requires a prior durable destroy intent; "
            "run destroy first"
        )
    prove_teardown_zero_state(
        path,
        ledger,
        success_event="administrator_teardown_proven",
        incomplete_event="administrator_teardown_incomplete",
    )


def inventory(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    result = inventory_for_execution(ledger)
    atomic_json(path.parent / "current-inventory.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))


def review_stack_is_owned_by_ledger(
    ledger: dict[str, Any], description: dict[str, Any]
) -> bool:
    """Bind an empty nested preview shell to one exact historical execution."""
    execution_id = ledger["execution_id"]
    root_name = ledger["stack_name"]
    region = ledger["region"]
    account_id = ledger["account_id"]
    stack_name = description.get("StackName")
    stack_id = description.get("StackId")
    root_id = description.get("RootId")
    parent_id = description.get("ParentId")
    if not all(
        isinstance(value, str) and value
        for value in (stack_name, stack_id, root_id, parent_id)
    ):
        return False
    if execution_id not in root_name or not stack_name.startswith(f"{root_name}-"):
        return False
    arn_prefix = (
        rf"arn:aws(?:-[a-z0-9-]+)?:cloudformation:{re.escape(region)}:"
        rf"{re.escape(account_id)}:stack/"
    )
    uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    if not re.fullmatch(arn_prefix + re.escape(stack_name) + rf"/{uuid}", stack_id):
        return False
    if not re.fullmatch(arn_prefix + re.escape(root_name) + rf"/{uuid}", root_id):
        return False
    expected_root_id = ledger.get("review_stack_id") or ledger.get("stack_id")
    if not isinstance(expected_root_id, str) or root_id != expected_root_id:
        return False
    parent_name = parent_id.split(":stack/", 1)[-1].split("/", 1)[0]
    if parent_name != root_name and not parent_name.startswith(f"{root_name}-"):
        return False
    try:
        created = dt.datetime.fromisoformat(
            str(description["CreationTime"]).replace("Z", "+00:00")
        )
        ledger_created = dt.datetime.fromisoformat(
            str(ledger["created_at"]).replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError):
        return False
    destroyed_at = ledger.get("destroyed_at")
    if destroyed_at is None:
        return ledger_created <= created
    try:
        ledger_destroyed = dt.datetime.fromisoformat(
            str(destroyed_at).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return False
    return ledger_created <= created <= ledger_destroyed


def top_level_review_stack_is_owned_by_ledger(
    ledger: dict[str, Any], description: dict[str, Any]
) -> bool:
    """Bind a tagged top-level preview shell to its exact recorded stack ID."""
    stack_name = description.get("StackName")
    if stack_name == ledger.get("stack_name"):
        expected_stack_id = ledger.get("review_stack_id")
    elif stack_name == ledger.get("qualification_stack_name"):
        expected_stack_id = ledger.get("qualification_review_stack_id")
    else:
        return False
    if (
        not isinstance(expected_stack_id, str)
        or description.get("StackId") != expected_stack_id
        or description.get("RootId")
        or description.get("ParentId")
    ):
        return False
    raw_tags = description.get("Tags")
    if not isinstance(raw_tags, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("Key"), str)
        or not isinstance(item.get("Value"), str)
        for item in raw_tags
    ):
        return False
    tags = {item["Key"]: item["Value"] for item in raw_tags}
    expected_tags = {
        "Project": PROJECT,
        "ManagedBy": MANAGED_BY,
        "BridgefuExecutionId": ledger["execution_id"],
        "BridgefuRecipe": RECIPE,
    }
    return all(tags.get(key) == value for key, value in expected_tags.items())


def cleanup_orphans(args: argparse.Namespace) -> None:
    """Delete only empty, exactly owned preview shells and Connect log groups."""
    path, ledger = load_ledger(args.execution_id)
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    if ledger.get("status") not in {"destroyed", "teardown_incomplete"}:
        raise LiveTestError("orphan cleanup requires a completed teardown ledger")
    execution_id = ledger["execution_id"]
    region = ledger["region"]
    inventory_before = inventory_for_execution(ledger)
    deleted_review_stacks: list[str] = []
    deleted_log_groups: list[str] = []

    verified: list[tuple[str, str | None]] = []
    for stack_id in inventory_before.get("review_stack_ids", []):
        description = aws_json(
            [
                "cloudformation",
                "describe-stacks",
                "--region",
                region,
                "--stack-name",
                stack_id,
            ]
        )["Stacks"][0]
        if description.get("StackStatus") != "REVIEW_IN_PROGRESS":
            raise LiveTestError("preview stack status changed during cleanup")
        top_level_owner = top_level_review_stack_is_owned_by_ledger(ledger, description)
        nested_owner = review_stack_is_owned_by_ledger(ledger, description)
        if not top_level_owner and not nested_owner:
            raise LiveTestError(
                "refusing to delete a preview stack without exact tags or ledger ancestry"
            )
        resources = aws_json(
            [
                "cloudformation",
                "list-stack-resources",
                "--region",
                region,
                "--stack-name",
                stack_id,
            ]
        ).get("StackResourceSummaries", [])
        if resources:
            raise LiveTestError(
                "refusing to delete a preview stack that contains resources"
            )
        parent_id = description.get("ParentId")
        verified.append((stack_id, parent_id if isinstance(parent_id, str) else None))

    # Orphaned nested change sets cannot be deleted independently after their
    # root review is gone. CloudFormation does permit deleting their empty
    # REVIEW_IN_PROGRESS stack shells, so remove the deepest children first.
    verified_ids = {stack_id for stack_id, _parent_id in verified}

    def preview_depth(item: tuple[str, str | None]) -> int:
        depth = 0
        parent_id = item[1]
        seen: set[str] = set()
        parent_by_id = dict(verified)
        while parent_id in verified_ids and parent_id not in seen:
            seen.add(parent_id)
            depth += 1
            parent_id = parent_by_id.get(parent_id)
        return depth

    stacks_by_depth: dict[int, list[str]] = {}
    for item in verified:
        stacks_by_depth.setdefault(preview_depth(item), []).append(item[0])
    for depth in sorted(stacks_by_depth, reverse=True):
        stack_ids = sorted(stacks_by_depth[depth])
        # Siblings have no dependency on one another. Request their deletions
        # together, prove every one is gone, then move to their parents.
        for stack_id in stack_ids:
            aws_json(
                [
                    "cloudformation",
                    "delete-stack",
                    "--region",
                    region,
                    "--stack-name",
                    stack_id,
                ]
            )
        for stack_id in stack_ids:
            aws_wait(
                [
                    "cloudformation",
                    "wait",
                    "stack-delete-complete",
                    "--region",
                    region,
                    "--stack-name",
                    stack_id,
                ]
            )
            deleted_review_stacks.append(stack_id)

    for log_group in inventory_before.get("connect_log_group_names", []):
        if (
            log_group != f"/aws/connect/{execution_id}-connect"
            or not owned_connect_log_group_exists(ledger, None)
        ):
            raise LiveTestError(
                "refusing to delete a Connect log group without exact ownership tags"
            )
        groups = aws_json(
            [
                "logs",
                "describe-log-groups",
                "--region",
                region,
                "--log-group-name-prefix",
                log_group,
            ]
        ).get("logGroups", [])
        exact = [item for item in groups if item.get("logGroupName") == log_group]
        if len(exact) != 1 or exact[0].get("storedBytes", 0) != 0:
            raise LiveTestError(
                "refusing to delete a Connect log group unless it is exact and empty"
            )
        aws_json(
            [
                "logs",
                "delete-log-group",
                "--region",
                region,
                "--log-group-name",
                log_group,
            ]
        )
        deleted_log_groups.append(log_group)

    final_inventory: dict[str, Any] = {}
    for attempt in range(3):
        final_inventory = inventory_for_execution(ledger)
        if not final_inventory.get("review_stack_ids") and not final_inventory.get(
            "connect_log_group_names"
        ):
            break
        if attempt < 2:
            time.sleep(2)
    evidence = {
        "schema_version": 1,
        "execution_id": execution_id,
        "cleaned_at": utc_now(),
        "deleted_review_stack_ids": deleted_review_stacks,
        "deleted_connect_log_groups": deleted_log_groups,
        "final_inventory": final_inventory,
    }
    atomic_json(path.parent / "orphan-cleanup-evidence.json", evidence)
    if final_inventory.get("review_stack_ids") or final_inventory.get(
        "connect_log_group_names"
    ):
        raise LiveTestError("orphan cleanup did not reach zero preview/log state")
    record(path, ledger, "orphan_cleanup_proven")
    print(path.parent / "orphan-cleanup-evidence.json")


def headless_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LiveTestError(f"{label} is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LiveTestError(f"{label} is invalid") from error
    if parsed.tzinfo is None:
        raise LiveTestError(f"{label} has no timezone")
    return parsed.astimezone(dt.timezone.utc)


def headless_scenarios(ledger: dict[str, Any], suite: str) -> list[str]:
    secure = ledger.get("sip_security") != "sip_rtp"
    if suite == "smoke":
        return [
            "sips-srtp-pcmu" if secure else "sip-rtp-pcmu",
            "vapi-web-transfer",
        ]
    if suite == "full":
        return [
            "sips-srtp-pcmu" if secure else "sip-rtp-pcmu",
            "sips-srtp-pcma" if secure else "sip-rtp-pcma",
            "vapi-web-transfer",
        ]
    raise LiveTestError("headless qualification suite is invalid")


def headless_idempotency_token(
    execution_id: str, suite: str, source_tree_sha256: str, run_id: str
) -> str:
    material = "\0".join(
        ("bridgefu-headless-v1", execution_id, suite, source_tree_sha256, run_id)
    )
    return hashlib.sha256(material.encode()).hexdigest()


def headless_build_id_is_valid(ledger: dict[str, Any], value: Any) -> bool:
    project_name = ledger.get("qualification_project_name")
    return (
        isinstance(project_name, str)
        and isinstance(value, str)
        and re.fullmatch(
            rf"{re.escape(project_name)}:"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value,
        )
        is not None
    )


def headless_state_fields(phase: str) -> set[str]:
    if phase not in HEADLESS_RUN_PHASES:
        raise LiveTestError("headless run phase is invalid")
    fields = {
        "schema_version",
        "execution_id",
        "suite",
        "run_id",
        "input_key",
        "evidence_key",
        "idempotency_token",
        "source_tree_sha256",
        "phase",
        "input_path",
        "input_sha256",
        "started_at",
        "deadline_at",
    }
    if HEADLESS_RUN_PHASES.index(phase) >= HEADLESS_RUN_PHASES.index("input_published"):
        fields.add("input_version")
    if HEADLESS_RUN_PHASES.index(phase) >= HEADLESS_RUN_PHASES.index("build_started"):
        fields.add("build_id")
    if HEADLESS_RUN_PHASES.index(phase) >= HEADLESS_RUN_PHASES.index("terminal"):
        fields.update(("terminal_status", "terminal_at"))
    if phase == "verified":
        fields.update(
            ("proof_path", "proof_sha256", "evidence_sha256", "evidence_version")
        )
    return fields


def validate_headless_run_state(
    ledger: dict[str, Any], state: Any, *, historical: bool = False
) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise LiveTestError("headless run state is invalid")
    phase = state.get("phase")
    if phase not in HEADLESS_RUN_PHASES or set(state) != headless_state_fields(phase):
        raise LiveTestError("headless run state shape is invalid")
    execution_id = ledger.get("execution_id")
    suite = state.get("suite")
    run_id = state.get("run_id")
    source_digest = state.get("source_tree_sha256")
    if (
        state.get("schema_version") != 1
        or state.get("execution_id") != execution_id
        or suite not in {"smoke", "full"}
        or not isinstance(run_id, str)
        or re.fullmatch(rf"{suite}-[0-9]{{9,12}}", run_id) is None
        or not isinstance(source_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_digest) is None
        or source_digest != ledger.get("publication_source_tree_sha256")
        or state.get("input_key")
        != f"qualification/{execution_id}/runs/{run_id}/input.json"
        or state.get("evidence_key")
        != f"qualification/{execution_id}/runs/{run_id}/evidence.tar.gz"
        or state.get("idempotency_token")
        != headless_idempotency_token(execution_id, suite, source_digest, run_id)
        or not isinstance(state.get("input_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", state["input_sha256"]) is None
    ):
        raise LiveTestError("headless run state does not match this deployment")
    expected_input_path = ledger_path(execution_id).parent / (
        f"{run_id}-runner-input.private.json"
    )
    if Path(state.get("input_path", "")) != expected_input_path:
        raise LiveTestError("headless runner input path is not execution-owned")
    started = headless_timestamp(state.get("started_at"), "headless start time")
    deadline = headless_timestamp(state.get("deadline_at"), "headless deadline")
    qualification_deadline = headless_timestamp(
        ledger.get("qualification_deadline_at"), "qualification deadline"
    )
    if (
        deadline <= started
        or deadline - started > dt.timedelta(seconds=HEADLESS_BUILD_TIMEOUT_SECONDS)
        or deadline > qualification_deadline
    ):
        raise LiveTestError("headless deadline exceeds its authorization")
    if historical and phase != "verified":
        raise LiveTestError("headless history contains an unfinished run")
    if "input_version" in state and (
        not isinstance(state["input_version"], str) or not state["input_version"]
    ):
        raise LiveTestError("headless runner input version is invalid")
    if "build_id" in state:
        if not headless_build_id_is_valid(ledger, state["build_id"]):
            raise LiveTestError("headless build ID is not bound to the runner project")
    if "terminal_status" in state:
        if state["terminal_status"] not in CODEBUILD_TERMINAL_STATUSES:
            raise LiveTestError("headless terminal build status is invalid")
        terminal_at = headless_timestamp(
            state.get("terminal_at"), "headless terminal time"
        )
        if terminal_at < started:
            raise LiveTestError("headless terminal time predates its run")
    if phase == "verified":
        expected_proof = (
            ledger_path(execution_id).parent / f"{run_id}-headless-proof.json"
        )
        if (
            Path(state.get("proof_path", "")) != expected_proof
            or not isinstance(state.get("evidence_version"), str)
            or not state["evidence_version"]
            or not all(
                isinstance(state.get(field), str)
                and re.fullmatch(r"[0-9a-f]{64}", state[field]) is not None
                for field in ("proof_sha256", "evidence_sha256")
            )
        ):
            raise LiveTestError("headless proof state is invalid")
    return state


def headless_run_history(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    value = ledger.get("headless_run_history", [])
    if (
        not isinstance(value, list)
        or len(value) > MAX_HEADLESS_RUN_HISTORY
        or any(not isinstance(item, dict) for item in value)
    ):
        raise LiveTestError("headless run history is invalid")
    history = [
        validate_headless_run_state(ledger, item, historical=True) for item in value
    ]
    run_ids = [item["run_id"] for item in history]
    if len(run_ids) != len(set(run_ids)):
        raise LiveTestError("headless run history contains duplicate runs")
    return history


def known_headless_build_ids(ledger: dict[str, Any]) -> list[str]:
    build_ids: list[str] = []
    history = headless_run_history(ledger)
    current = ledger.get("headless_run")
    states = list(history)
    if current is not None:
        states.append(validate_headless_run_state(ledger, current))
    for state in states:
        build_id = state.get("build_id")
        if isinstance(build_id, str) and build_id not in build_ids:
            build_ids.append(build_id)
    for field in ("headless_build_id", "headless_last_terminal_build_id"):
        build_id = ledger.get(field)
        if build_id is None:
            continue
        if not headless_build_id_is_valid(ledger, build_id):
            raise LiveTestError("legacy headless build ID is invalid")
        if build_id not in build_ids:
            build_ids.append(build_id)
    if len(build_ids) > MAX_HEADLESS_RUN_HISTORY + 2:
        raise LiveTestError("headless build inventory exceeds its bound")
    return build_ids


def create_headless_run_state(
    path: Path,
    ledger: dict[str, Any],
    suite: str,
    remaining_seconds: int,
) -> dict[str, Any]:
    source_digest = ledger.get("publication_source_tree_sha256")
    if (
        not isinstance(source_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_digest) is None
    ):
        raise LiveTestError("published source digest is invalid")
    now = dt.datetime.now(dt.timezone.utc)
    qualification_deadline = headless_timestamp(
        ledger.get("qualification_deadline_at"), "qualification deadline"
    )
    deadline = min(
        now + dt.timedelta(seconds=HEADLESS_BUILD_TIMEOUT_SECONDS),
        qualification_deadline,
        now + dt.timedelta(seconds=remaining_seconds),
    )
    if suite == "full" and remaining_seconds < HEADLESS_BUILD_TIMEOUT_SECONDS:
        raise LiveTestError(
            "full headless qualification requires 180 minutes remaining before start"
        )
    run_id = f"{suite}-{int(now.timestamp())}"
    input_key = f"qualification/{ledger['execution_id']}/runs/{run_id}/input.json"
    evidence_key = (
        f"qualification/{ledger['execution_id']}/runs/{run_id}/evidence.tar.gz"
    )
    input_path = path.parent / f"{run_id}-runner-input.private.json"
    recovery_authority = json.loads(
        private_file_bytes(
            path.parent / "recovery-authority.json",
            maximum_bytes=256 * 1024,
            label="recovery authority",
        ).decode("utf-8")
    )
    if canonical_json_sha256(recovery_authority) != ledger.get(
        "recovery_authority_sha256"
    ):
        raise LiveTestError("headless runner recovery authority changed")
    runner_input = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "suite": suite,
        "scenarios": headless_scenarios(ledger, suite),
        "connect_url": ledger["connect_login_url"],
        "agent_credential_secret_arn": ledger["agent_credential_secret_arn"],
        "vapi_public_key_secret_arn": ledger["vapi_public_key_secret_arn"],
        "ledger": json.loads(json.dumps(ledger)),
        "recovery_authority": recovery_authority,
        "evidence_bucket": ledger["artifact_bucket"],
        "evidence_key": evidence_key,
    }
    atomic_json(input_path, runner_input)
    state = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "suite": suite,
        "run_id": run_id,
        "input_key": input_key,
        "evidence_key": evidence_key,
        "idempotency_token": headless_idempotency_token(
            ledger["execution_id"], suite, source_digest, run_id
        ),
        "source_tree_sha256": source_digest,
        "phase": "prepared",
        "input_path": os.fspath(input_path),
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "started_at": now.isoformat().replace("+00:00", "Z"),
        "deadline_at": deadline.isoformat().replace("+00:00", "Z"),
    }
    ledger["headless_run"] = state
    record(path, ledger, "headless_run_prepared", suite=suite, run_id=run_id)
    return validate_headless_run_state(ledger, state)


def adopt_headless_run(
    path: Path,
    ledger: dict[str, Any],
    suite: str,
    remaining_seconds: int,
) -> dict[str, Any]:
    history = headless_run_history(ledger)
    current_value = ledger.get("headless_run")
    if current_value is None:
        if ledger.get("headless_build_id"):
            raise LiveTestError(
                "legacy headless build state cannot be safely resumed; teardown the "
                "recorded build before starting another run"
            )
        return create_headless_run_state(path, ledger, suite, remaining_seconds)
    current = validate_headless_run_state(ledger, current_value)
    if current["suite"] == suite:
        return current
    if current["phase"] != "verified":
        raise LiveTestError(
            "a different headless suite is unfinished; resume it before another run"
        )
    if len(history) >= MAX_HEADLESS_RUN_HISTORY:
        raise LiveTestError("headless run history is full")
    ledger["headless_run_history"] = [*history, dict(current)]
    ledger.pop("headless_run")
    ledger.setdefault("events", []).append(
        {
            "at": utc_now(),
            "event": "headless_run_archived",
            "suite": current["suite"],
            "run_id": current["run_id"],
        }
    )
    return create_headless_run_state(path, ledger, suite, remaining_seconds)


def load_headless_runner_input(ledger: dict[str, Any], state: dict[str, Any]) -> Path:
    input_path = Path(state["input_path"])
    try:
        details = input_path.lstat()
    except OSError as error:
        raise LiveTestError("persisted headless runner input is unavailable") from error
    if (
        input_path.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_mode & 0o077
        or details.st_size > 2_000_000
        or hashlib.sha256(input_path.read_bytes()).hexdigest() != state["input_sha256"]
    ):
        raise LiveTestError("persisted headless runner input changed")
    try:
        value = json.loads(input_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise LiveTestError("persisted headless runner input is invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("execution_id") != ledger["execution_id"]
        or value.get("suite") != state["suite"]
        or value.get("scenarios") != headless_scenarios(ledger, state["suite"])
        or value.get("evidence_bucket") != ledger["artifact_bucket"]
        or value.get("evidence_key") != state["evidence_key"]
        or value.get("ledger", {}).get("publication_source_tree_sha256")
        != state["source_tree_sha256"]
    ):
        raise LiveTestError("persisted headless runner input binding changed")
    return input_path


def headless_input_object(
    ledger: dict[str, Any],
    state: dict[str, Any],
    environment: dict[str, str],
    *,
    version_id: str | None = None,
) -> dict[str, Any] | None:
    arguments = [
        "s3api",
        "head-object",
        "--region",
        ledger["region"],
        "--bucket",
        ledger["artifact_bucket"],
        "--key",
        state["input_key"],
    ]
    if version_id is not None:
        arguments.extend(("--version-id", version_id))
    head = aws_json(arguments, env=environment, check=False)
    if head is None:
        return None
    input_path = load_headless_runner_input(ledger, state)
    metadata = head.get("Metadata")
    observed_version = head.get("VersionId")
    if (
        not isinstance(head, dict)
        or head.get("ContentLength") != input_path.stat().st_size
        or not isinstance(metadata, dict)
        or metadata.get("sha256") != state["input_sha256"]
        or metadata.get("execution-id") != ledger["execution_id"]
        or metadata.get("run-id") != state["run_id"]
        or not isinstance(observed_version, str)
        or not observed_version
        or (version_id is not None and observed_version != version_id)
    ):
        raise LiveTestError("headless runner input object changed")
    return head


def publish_headless_input(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any],
    credentials: RefreshableRoleEnvironment,
) -> None:
    input_path = load_headless_runner_input(ledger, state)
    if state["phase"] == "prepared":
        head = headless_input_object(ledger, state, credentials.get())
        if head is None:
            uploaded = aws_json(
                [
                    "s3api",
                    "put-object",
                    "--region",
                    ledger["region"],
                    "--bucket",
                    ledger["artifact_bucket"],
                    "--key",
                    state["input_key"],
                    "--body",
                    os.fspath(input_path),
                    "--server-side-encryption",
                    "AES256",
                    "--metadata",
                    (
                        f"sha256={state['input_sha256']},"
                        f"execution-id={ledger['execution_id']},"
                        f"run-id={state['run_id']}"
                    ),
                    "--tagging",
                    (
                        f"Project={PROJECT}&ManagedBy={MANAGED_BY}&"
                        f"BridgefuExecutionId={ledger['execution_id']}"
                    ),
                ],
                env=credentials.get(),
            )
            if not isinstance(uploaded, dict):
                raise LiveTestError("runner input upload returned an invalid result")
            version = uploaded.get("VersionId")
        else:
            version = head["VersionId"]
        if not isinstance(version, str) or not version:
            raise LiveTestError(
                "runner input was not stored as an immutable object version"
            )
        state["phase"] = "input_published"
        state["input_version"] = version
        record(
            path,
            ledger,
            "headless_input_published",
            suite=state["suite"],
            run_id=state["run_id"],
        )
    if (
        headless_input_object(
            ledger, state, credentials.get(), version_id=state["input_version"]
        )
        is None
    ):
        raise LiveTestError("immutable headless runner input object is unavailable")


def exact_headless_build(
    ledger: dict[str, Any], build_id: str, environment: dict[str, str] | None
) -> dict[str, Any]:
    response = aws_json(
        [
            "codebuild",
            "batch-get-builds",
            "--region",
            ledger["region"],
            "--ids",
            build_id,
        ],
        env=environment,
    )
    if (
        not isinstance(response, dict)
        or response.get("buildsNotFound", []) != []
        or not isinstance(response.get("builds"), list)
        or len(response["builds"]) != 1
    ):
        raise LiveTestError("exact headless CodeBuild run is unavailable")
    build = response["builds"][0]
    if (
        not isinstance(build, dict)
        or build.get("id") != build_id
        or not headless_build_id_is_valid(ledger, build_id)
        or build.get("projectName") != ledger.get("qualification_project_name")
        or build.get("buildStatus") not in CODEBUILD_STATUSES
    ):
        raise LiveTestError("headless CodeBuild run violates its ledger binding")
    return build


def codebuild_start_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def list_headless_project_builds(
    ledger: dict[str, Any], environment: dict[str, str] | None
) -> list[dict[str, Any]]:
    response = aws_json(
        [
            "codebuild",
            "list-builds-for-project",
            "--region",
            ledger["region"],
            "--project-name",
            ledger["qualification_project_name"],
            "--sort-order",
            "DESCENDING",
        ],
        env=environment,
    )
    if (
        not isinstance(response, dict)
        or response.get("nextToken") is not None
        or not isinstance(response.get("ids"), list)
        or len(response["ids"]) > 100
        or len(response["ids"]) != len(set(response["ids"]))
        or any(not isinstance(item, str) for item in response["ids"])
    ):
        raise LiveTestError("headless project build listing is invalid or unbounded")
    if not response["ids"]:
        return []
    details = aws_json(
        [
            "codebuild",
            "batch-get-builds",
            "--region",
            ledger["region"],
            "--ids",
            *response["ids"],
        ],
        env=environment,
    )
    if (
        not isinstance(details, dict)
        or details.get("buildsNotFound", []) != []
        or not isinstance(details.get("builds"), list)
        or len(details["builds"]) != len(response["ids"])
    ):
        raise LiveTestError("headless project build details are incomplete")
    by_id: dict[str, dict[str, Any]] = {}
    for build in details["builds"]:
        if (
            not isinstance(build, dict)
            or not headless_build_id_is_valid(ledger, build.get("id"))
            or build.get("id") not in response["ids"]
            or build.get("id") in by_id
            or build.get("projectName") != ledger.get("qualification_project_name")
            or build.get("buildStatus") not in CODEBUILD_STATUSES
        ):
            raise LiveTestError("headless project build details violate their binding")
        by_id[build["id"]] = build
    return [by_id[build_id] for build_id in response["ids"]]


def build_matches_headless_input(
    build: dict[str, Any], ledger: dict[str, Any], state: dict[str, Any]
) -> bool:
    variables = build.get("environment", {}).get("environmentVariables")
    if not isinstance(variables, list):
        return False
    by_name: dict[str, dict[str, Any]] = {}
    for item in variables:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or item["name"] in by_name
        ):
            return False
        by_name[item["name"]] = item
    expected = {
        "BRIDGEFU_RUNNER_INPUT_BUCKET": ledger["artifact_bucket"],
        "BRIDGEFU_RUNNER_INPUT_KEY": state["input_key"],
        "BRIDGEFU_RUNNER_INPUT_VERSION": state["input_version"],
    }
    return all(
        by_name.get(name, {}).get("value") == value
        and by_name[name].get("type") == "PLAINTEXT"
        for name, value in expected.items()
    )


def discover_headless_build(
    ledger: dict[str, Any],
    state: dict[str, Any],
    environment: dict[str, str],
) -> dict[str, Any] | None:
    """Adopt a build after a crash outside CodeBuild's five-minute token window."""
    builds = list_headless_project_builds(ledger, environment)
    matches = [
        build for build in builds if build_matches_headless_input(build, ledger, state)
    ]
    if len(matches) > 1:
        raise LiveTestError("multiple CodeBuild runs match one headless runner input")
    if matches:
        return matches[0]
    known_ids = set(known_headless_build_ids(ledger))
    state_started = headless_timestamp(state["started_at"], "headless start time")
    plausible = [
        build
        for build in builds
        if build["id"] not in known_ids
        and (
            codebuild_start_time(build.get("startTime")) is None
            or codebuild_start_time(build.get("startTime")) >= state_started
        )
    ]
    if plausible:
        raise LiveTestError(
            "an unbound CodeBuild run may belong to this headless start; refusing "
            "to create a duplicate"
        )
    return None


def persist_adopted_headless_build(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any],
    build: dict[str, Any],
) -> None:
    state["phase"] = "build_started"
    state["build_id"] = build["id"]
    ledger["headless_build_id"] = build["id"]
    record(
        path,
        ledger,
        "headless_qualification_adopted",
        suite=state["suite"],
        run_id=state["run_id"],
        build_id=build["id"],
    )
    validate_headless_run_state(ledger, state)


def start_headless_build(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any],
    credentials: RefreshableRoleEnvironment,
) -> None:
    if state["phase"] != "input_published":
        return
    existing = discover_headless_build(ledger, state, credentials.get())
    if existing is not None:
        persist_adopted_headless_build(path, ledger, state, existing)
        return
    response = aws_json(
        [
            "codebuild",
            "start-build",
            "--region",
            ledger["region"],
            "--project-name",
            ledger["qualification_project_name"],
            "--idempotency-token",
            state["idempotency_token"],
            "--environment-variables-override",
            (
                "name=BRIDGEFU_RUNNER_INPUT_BUCKET,"
                f"value={ledger['artifact_bucket']},type=PLAINTEXT"
            ),
            (
                "name=BRIDGEFU_RUNNER_INPUT_KEY,"
                f"value={state['input_key']},type=PLAINTEXT"
            ),
            (
                "name=BRIDGEFU_RUNNER_INPUT_VERSION,"
                f"value={state['input_version']},type=PLAINTEXT"
            ),
        ],
        env=credentials.get(),
    )
    build = response.get("build") if isinstance(response, dict) else None
    if (
        not isinstance(build, dict)
        or build.get("projectName") != ledger.get("qualification_project_name")
        or build.get("buildStatus") not in CODEBUILD_STATUSES
        or not headless_build_id_is_valid(ledger, build.get("id"))
    ):
        raise LiveTestError("CodeBuild start response violates the run binding")
    state["phase"] = "build_started"
    state["build_id"] = build["id"]
    ledger["headless_build_id"] = build["id"]
    record(
        path,
        ledger,
        "headless_qualification_started",
        suite=state["suite"],
        run_id=state["run_id"],
        build_id=build["id"],
    )
    validate_headless_run_state(ledger, state)


def mark_headless_build_terminal(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any] | None,
    build_id: str,
    status: str,
) -> None:
    if status not in CODEBUILD_TERMINAL_STATUSES:
        raise LiveTestError("cannot record a nonterminal CodeBuild run as terminal")
    terminal_at = utc_now()
    if state is not None and state.get("build_id") == build_id:
        if state.get("phase") in {"build_started", "terminal"}:
            state["phase"] = "terminal"
            state["terminal_status"] = status
            state["terminal_at"] = state.get("terminal_at", terminal_at)
        elif (
            state.get("phase") == "verified" and state.get("terminal_status") != status
        ):
            raise LiveTestError("verified headless terminal status changed")
    ledger["headless_last_terminal_build_id"] = build_id
    ledger["headless_last_terminal_build_status"] = status
    ledger["headless_last_terminal_at"] = (
        state.get("terminal_at", terminal_at) if state is not None else terminal_at
    )
    record(
        path,
        ledger,
        "headless_qualification_terminal",
        build_id=build_id,
        build_status=status,
    )


def request_headless_build_stop(
    path: Path,
    ledger: dict[str, Any],
    build_id: str,
    credentials: RefreshableRoleEnvironment,
) -> None:
    response = aws_json(
        [
            "codebuild",
            "stop-build",
            "--region",
            ledger["region"],
            "--id",
            build_id,
        ],
        env=credentials.get(),
    )
    build = response.get("build") if isinstance(response, dict) else None
    if (
        not isinstance(build, dict)
        or build.get("id") != build_id
        or build.get("projectName") != ledger.get("qualification_project_name")
    ):
        raise LiveTestError("CodeBuild stop response violates the run binding")
    record(path, ledger, "headless_build_stop_requested", build_id=build_id)


def wait_for_stopped_headless_build(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any] | None,
    build_id: str,
    credentials: RefreshableRoleEnvironment,
) -> dict[str, Any]:
    stop_deadline = time.monotonic() + HEADLESS_STOP_TIMEOUT_SECONDS
    while True:
        build = exact_headless_build(ledger, build_id, credentials.get())
        if build["buildStatus"] in CODEBUILD_TERMINAL_STATUSES:
            mark_headless_build_terminal(
                path, ledger, state, build_id, build["buildStatus"]
            )
            return build
        remaining = stop_deadline - time.monotonic()
        if remaining <= 0:
            raise LiveTestError(
                "CodeBuild did not become terminal; refusing stack teardown"
            )
        time.sleep(min(HEADLESS_POLL_SECONDS, remaining))


def wait_headless_build(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any],
    credentials: RefreshableRoleEnvironment,
) -> dict[str, Any]:
    build_id = state["build_id"]
    if state["phase"] in {"terminal", "verified"}:
        build = exact_headless_build(ledger, build_id, credentials.get())
        if build["buildStatus"] != state["terminal_status"]:
            raise LiveTestError("persisted headless terminal status changed")
        return build
    deadline = headless_timestamp(state["deadline_at"], "headless deadline")
    while True:
        build = exact_headless_build(ledger, build_id, credentials.get())
        status = build["buildStatus"]
        if status in CODEBUILD_TERMINAL_STATUSES:
            mark_headless_build_terminal(path, ledger, state, build_id, status)
            return build
        now = dt.datetime.now(dt.timezone.utc)
        remaining = (deadline - now).total_seconds()
        if remaining <= 0:
            request_headless_build_stop(path, ledger, build_id, credentials)
            return wait_for_stopped_headless_build(
                path, ledger, state, build_id, credentials
            )
        time.sleep(min(HEADLESS_POLL_SECONDS, remaining))


def stop_headless_build_before_teardown(path: Path, ledger: dict[str, Any]) -> None:
    headless_run_history(ledger)
    state_value = ledger.get("headless_run")
    state = (
        validate_headless_run_state(ledger, state_value)
        if state_value is not None
        else None
    )
    project_name = ledger.get("qualification_project_name")
    if project_name is None:
        if state is not None or ledger.get("headless_build_id"):
            raise LiveTestError("headless build state has no qualification project")
        return
    credentials = RefreshableRoleEnvironment(ledger, "qualification")
    if state is not None and state["phase"] == "input_published":
        discovered = discover_headless_build(ledger, state, credentials.get())
        if discovered is not None:
            persist_adopted_headless_build(path, ledger, state, discovered)
    pending: dict[str, dict[str, Any] | None] = {}
    for build in list_headless_project_builds(ledger, credentials.get()):
        if build["buildStatus"] not in CODEBUILD_TERMINAL_STATUSES:
            pending[build["id"]] = (
                state
                if state is not None and state.get("build_id") == build["id"]
                else None
            )
    if (
        state is not None
        and state.get("build_id")
        and state["phase"] == "build_started"
    ):
        pending[state["build_id"]] = state
    terminal_ids = {
        item["build_id"]
        for item in [*headless_run_history(ledger), *([state] if state else [])]
        if item.get("phase") in {"terminal", "verified"}
        and isinstance(item.get("build_id"), str)
    }
    legacy = ledger.get("headless_build_id")
    if isinstance(legacy, str) and legacy not in terminal_ids:
        pending.setdefault(legacy, None)
    if not pending:
        return
    for build_id, current_state in pending.items():
        build = exact_headless_build(ledger, build_id, credentials.get())
        if build["buildStatus"] not in CODEBUILD_TERMINAL_STATUSES:
            request_headless_build_stop(path, ledger, build_id, credentials)
            build = wait_for_stopped_headless_build(
                path, ledger, current_state, build_id, credentials
            )
        else:
            mark_headless_build_terminal(
                path,
                ledger,
                current_state,
                build_id,
                build["buildStatus"],
            )


def existing_headless_proof(ledger: dict[str, Any], state: dict[str, Any]) -> Path:
    if state["phase"] != "verified":
        raise LiveTestError("headless run has not been verified")
    proof_path = Path(state["proof_path"])
    try:
        details = proof_path.lstat()
    except OSError as error:
        raise LiveTestError("verified headless proof is unavailable") from error
    if (
        proof_path.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_size <= 0
        or details.st_size > 1024 * 1024
        or hashlib.sha256(proof_path.read_bytes()).hexdigest() != state["proof_sha256"]
    ):
        raise LiveTestError("verified headless proof changed")
    try:
        proof = json.loads(proof_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise LiveTestError("verified headless proof is invalid") from error
    if (
        not isinstance(proof, dict)
        or proof.get("execution_id") != ledger["execution_id"]
        or proof.get("suite") != state["suite"]
        or proof.get("run_id") != state["run_id"]
        or proof.get("build_id") != state["build_id"]
        or proof.get("build_status") != state["terminal_status"]
        or proof.get("evidence_sha256") != state["evidence_sha256"]
    ):
        raise LiveTestError("verified headless proof binding changed")
    return proof_path


def download_headless_evidence(
    path: Path,
    ledger: dict[str, Any],
    state: dict[str, Any],
    credentials: RefreshableRoleEnvironment,
) -> tuple[Path, str, str]:
    head = aws_json(
        [
            "s3api",
            "head-object",
            "--region",
            ledger["region"],
            "--bucket",
            ledger["artifact_bucket"],
            "--key",
            state["evidence_key"],
        ],
        env=credentials.get(),
    )
    if not isinstance(head, dict):
        raise LiveTestError("headless evidence object is unavailable")
    content_length = head.get("ContentLength")
    metadata = head.get("Metadata")
    expected_digest = metadata.get("sha256") if isinstance(metadata, dict) else None
    evidence_version = head.get("VersionId")
    if (
        not isinstance(content_length, int)
        or not (0 < content_length <= MAX_HEADLESS_ARCHIVE_BYTES)
        or not isinstance(expected_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        or metadata.get("execution-id") != ledger["execution_id"]
        or metadata.get("build-id") != state["build_id"]
        or not isinstance(evidence_version, str)
        or not evidence_version
    ):
        raise LiveTestError("headless evidence object violates its byte/hash binding")
    archive = path.parent / f"{state['run_id']}-evidence.tar.gz"
    if archive.exists() or archive.is_symlink():
        details = archive.lstat()
        if archive.is_symlink() or not stat.S_ISREG(details.st_mode):
            raise LiveTestError("headless evidence archive path is unsafe")
        if (
            details.st_size == content_length
            and hashlib.sha256(archive.read_bytes()).hexdigest() == expected_digest
        ):
            return archive, expected_digest, evidence_version
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{state['run_id']}-evidence-", suffix=".tmp"
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    os.chmod(temporary, 0o600)
    try:
        aws_json(
            [
                "s3api",
                "get-object",
                "--region",
                ledger["region"],
                "--bucket",
                ledger["artifact_bucket"],
                "--key",
                state["evidence_key"],
                "--version-id",
                evidence_version,
                os.fspath(temporary),
            ],
            env=credentials.get(),
        )
        if (
            temporary.stat().st_size != content_length
            or hashlib.sha256(temporary.read_bytes()).hexdigest() != expected_digest
        ):
            raise LiveTestError("downloaded headless evidence checksum mismatch")
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    return archive, expected_digest, evidence_version


def extract_headless_evidence(path: Path, state: dict[str, Any], archive: Path) -> Path:
    evidence_dir = path.parent / f"{state['run_id']}-evidence"
    if evidence_dir.exists() or evidence_dir.is_symlink():
        details = evidence_dir.lstat()
        if evidence_dir.is_symlink() or not stat.S_ISDIR(details.st_mode):
            raise LiveTestError("headless evidence directory path is unsafe")
        return evidence_dir
    staging = Path(
        tempfile.mkdtemp(dir=path.parent, prefix=f".{state['run_id']}-extract-")
    )
    os.chmod(staging, 0o700)
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            member_names: set[str] = set()
            expanded_bytes = 0
            unsafe = False
            for item in members:
                relative = PurePosixPath(item.name)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                    or relative.as_posix() != item.name
                    or item.issym()
                    or item.islnk()
                    or not (item.isfile() or item.isdir())
                    or item.name in member_names
                ):
                    unsafe = True
                    break
                member_names.add(item.name)
                if item.isfile():
                    expanded_bytes += item.size
            if (
                unsafe
                or len(members) > MAX_HEADLESS_EVIDENCE_FILES
                or expanded_bytes > MAX_HEADLESS_EVIDENCE_BYTES
            ):
                raise LiveTestError(
                    "headless evidence archive contains an unsafe member"
                )
            bundle.extractall(staging, filter="data")
        staging.replace(evidence_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return evidence_dir


def validate_headless_evidence(
    ledger: dict[str, Any], state: dict[str, Any], evidence_dir: Path
) -> tuple[dict[str, Any], list[Path]]:
    summaries = list(evidence_dir.rglob("runner-summary.json"))
    calls = list(evidence_dir.rglob("call-evidence/*.json"))
    if len(summaries) != 1:
        raise LiveTestError("headless evidence has no unique runner summary")
    try:
        summary = json.loads(summaries[0].read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise LiveTestError("headless runner summary is invalid") from error
    scenarios = headless_scenarios(ledger, state["suite"])
    expected_calls = len(scenarios) * 2 * (2 if state["suite"] == "full" else 1)
    if (
        not isinstance(summary, dict)
        or summary.get("execution_id") != ledger["execution_id"]
        or summary.get("suite") != state["suite"]
        or summary.get("passed") is not True
        or summary.get("scenarios") != scenarios
        or summary.get("source_tree_sha256") != state["source_tree_sha256"]
        or len(calls) != expected_calls
    ):
        raise LiveTestError("headless evidence does not prove the requested scenarios")
    return summary, calls


def run_headless(args: argparse.Namespace) -> None:
    path, ledger = load_ledger(args.execution_id)
    if ledger.get("connect_mode") != "disposable":
        raise LiveTestError("headless qualification requires a disposable Connect run")
    if ledger.get("status") not in {"verified", "lifecycle_verified"}:
        raise LiveTestError("headless qualification requires a verified deployment")
    if args.confirm != ledger["execution_id"]:
        raise LiveTestError("--confirm must exactly equal the execution ID")
    current_value = ledger.get("headless_run")
    current = (
        validate_headless_run_state(ledger, current_value)
        if current_value is not None
        else None
    )
    if (
        current is not None
        and current["suite"] == args.suite
        and current["phase"] == "verified"
    ):
        proof_path = existing_headless_proof(ledger, current)
        print(proof_path)
        return
    if args.suite == "full" and ledger.get("status") != "verified":
        raise LiveTestError(
            "full headless qualification must run before the lifecycle test"
        )
    needs_start_or_adoption = (
        current is None
        or current["suite"] != args.suite
        or current["phase"] in {"prepared", "input_published"}
    )
    remaining_seconds = (
        require_qualification_deadline(
            path, ledger, "headless qualification start or resume"
        )
        if needs_start_or_adoption
        else 1
    )
    state = adopt_headless_run(path, ledger, args.suite, remaining_seconds)
    credentials = RefreshableRoleEnvironment(ledger, "qualification")
    if state["phase"] in {"prepared", "input_published"}:
        publish_headless_input(path, ledger, state, credentials)
    start_headless_build(path, ledger, state, credentials)
    state = validate_headless_run_state(ledger, ledger["headless_run"])
    build = wait_headless_build(path, ledger, state, credentials)
    if build.get("buildStatus") != "SUCCEEDED":
        phase = next(
            (
                item
                for item in reversed(build.get("phases", []))
                if item.get("contexts")
            ),
            {},
        )
        raise LiveTestError(
            f"headless qualification {build.get('buildStatus', 'did not finish')}: "
            f"{json.dumps(phase.get('contexts', []))[-1200:]}"
        )
    archive, digest, evidence_version = download_headless_evidence(
        path, ledger, state, credentials
    )
    evidence_dir = extract_headless_evidence(path, state, archive)
    summary, calls = validate_headless_evidence(ledger, state, evidence_dir)
    imported = False
    if args.suite == "full":
        command(
            [
                "python3",
                os.fspath(root_dir() / "scripts" / "run-recipe-qualification.py"),
                "import-packaged",
                "--execution-id",
                ledger["execution_id"],
                "--source-directory",
                os.fspath(evidence_dir),
                "--confirm",
                ledger["execution_id"],
            ],
            cwd=root_dir(),
            inherit_live_lock=True,
        )
        path, ledger = load_ledger(args.execution_id)
        state = validate_headless_run_state(ledger, ledger.get("headless_run"))
        imported = True
    proof = {
        "schema_version": 1,
        "execution_id": ledger["execution_id"],
        "suite": args.suite,
        "run_id": state["run_id"],
        "build_id": state["build_id"],
        "build_status": build["buildStatus"],
        "scenarios": headless_scenarios(ledger, args.suite),
        "call_evidence_files": len(calls),
        "qualification_stage": summary.get("qualification_stage"),
        "official_evidence_imported": imported,
        "evidence_sha256": digest,
        "evidence_version": evidence_version,
        "evidence_object": (
            f"s3://{ledger['artifact_bucket']}/{state['evidence_key']}"
        ),
        "terminal_at": state["terminal_at"],
        "deadline_at": state["deadline_at"],
        "verified_at": utc_now(),
    }
    proof_path = path.parent / f"{state['run_id']}-headless-proof.json"
    atomic_json(proof_path, proof)
    state["phase"] = "verified"
    state["proof_path"] = os.fspath(proof_path)
    state["proof_sha256"] = hashlib.sha256(proof_path.read_bytes()).hexdigest()
    state["evidence_sha256"] = digest
    state["evidence_version"] = evidence_version
    ledger["headless_qualification_verified"] = True
    ledger["headless_verified_at"] = proof["verified_at"]
    ledger["headless_proof_path"] = os.fspath(proof_path)
    if args.suite == "full":
        ledger["headless_full_qualification_verified"] = True
        ledger["headless_full_verified_at"] = proof["verified_at"]
    record(path, ledger, "headless_qualification_verified", suite=args.suite)
    print(proof_path)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--execution-id", required=True)
    subparsers = value.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--region", default="us-west-2")
    init_parser.add_argument(
        "--max-usd",
        type=float,
        default=200.0,
        help="ceiling for the conservative planning estimate; not a spend cap",
    )
    init_parser.add_argument(
        "--planned-hours",
        type=float,
        default=8.0,
        help=(
            "hours from init until paid qualification phases are blocked; existing "
            "AWS resources still require explicit teardown"
        ),
    )
    init_parser.add_argument("--connect-minutes", type=int, default=30)
    init_parser.add_argument(
        "--allow-root-bootstrap",
        action="store_true",
        help=(
            "explicitly acknowledge a one-time account-root bootstrap exception; "
            "application operations still use temporary scoped roles"
        ),
    )
    init_parser.add_argument(
        "--runtime-profile",
        choices=("starter", "high_availability"),
        default="starter",
    )
    connect_group = init_parser.add_mutually_exclusive_group(required=True)
    connect_group.add_argument(
        "--create-connect-demo",
        action="store_true",
        help="create and later delete a nonproduction Amazon Connect instance",
    )
    connect_group.add_argument("--connect-instance-arn")
    init_parser.add_argument("--target-flow-arn")
    init_parser.add_argument(
        "--enable-demo-site",
        action="store_true",
        help=(
            "include the optional private-S3/CloudFront browser test page; "
            f"requires {PUBLIC_KEY_ENV}"
        ),
    )
    dns_group = init_parser.add_mutually_exclusive_group()
    dns_group.add_argument("--hosted-zone-id")
    dns_group.add_argument("--delegated-zone-name")
    init_parser.add_argument("--sip-hostname")
    init_parser.add_argument(
        "--secure-sips-proof",
        action="store_true",
        help="opt into SIPS/SRTP proof; requires a public DNS zone and hostname",
    )
    init_parser.set_defaults(function=init)
    recovery_review_parser = subparsers.add_parser(
        "recover-lost-ledger-review",
        help=(
            "read-only AWS review for a recent bootstrap-only execution; remote "
            "capsules are not consumed and app/qualification history is forbidden"
        ),
        description=(
            "Run a read-only AWS inventory for one recent bootstrap-only execution. "
            "The review expires after 15 minutes and prints an immutable review path "
            "plus its exact file-byte SHA-256. Remote recovery capsules are currently "
            "write-only evidence and are not consumed; any application or qualification "
            "stack history is rejected. This command never mutates AWS."
        ),
    )
    recovery_review_parser.add_argument(
        "--account-id", required=True, help="exact 12-digit AWS account ID"
    )
    recovery_review_parser.add_argument(
        "--region", required=True, help="exact bootstrap AWS region"
    )
    recovery_review_parser.add_argument(
        "--bootstrap-stack-id",
        required=True,
        help="full immutable CloudFormation bootstrap stack ARN",
    )
    recovery_review_parser.add_argument(
        "--expect-demo-site", choices=("true", "false"), required=True
    )
    recovery_review_parser.add_argument("--confirm-account", required=True)
    recovery_review_parser.add_argument("--confirm-region", required=True)
    recovery_review_parser.add_argument("--confirm-execution", required=True)
    recovery_review_parser.set_defaults(function=recover_lost_ledger_review)
    recovery_execute_parser = subparsers.add_parser(
        "recover-lost-ledger-execute",
        help=(
            "recheck AWS read-only and install only local teardown authority; "
            "this command performs no AWS mutation"
        ),
        description=(
            "Re-read an unexpired immutable review by its exact file-byte SHA-256, "
            "repeat the complete read-only AWS inventory, and atomically install a "
            "local teardown-only ledger. No AWS mutation occurs. The recovered ID is "
            "permanently retired; after teardown, start future work with a fresh ID."
        ),
    )
    recovery_execute_parser.add_argument("--account-id", required=True)
    recovery_execute_parser.add_argument("--region", required=True)
    recovery_execute_parser.add_argument("--review-sha256", required=True)
    recovery_execute_parser.add_argument("--confirm", required=True)
    recovery_execute_parser.add_argument("--confirm-account", required=True)
    recovery_execute_parser.add_argument("--confirm-region", required=True)
    recovery_execute_parser.set_defaults(function=recover_lost_ledger_execute)
    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_parser.add_argument(
        "--adopt-existing",
        action="store_true",
        help=(
            "adopt only an exact CREATE_COMPLETE bootstrap stack created by an "
            "authorized bootstrap identity"
        ),
    )
    bootstrap_parser.set_defaults(function=bootstrap)
    caller_parser = subparsers.add_parser("authorize-caller")
    caller_parser.add_argument("--principal-arn", required=True)
    caller_parser.add_argument("--confirm", required=True)
    caller_parser.set_defaults(function=authorize_caller)
    bootstrap_refresh_parser = subparsers.add_parser("bootstrap-refresh")
    bootstrap_refresh_parser.add_argument("--confirm", required=True)
    bootstrap_refresh_parser.set_defaults(function=bootstrap_refresh)
    bootstrap_refresh_verify_parser = subparsers.add_parser("bootstrap-refresh-verify")
    bootstrap_refresh_verify_parser.add_argument("--confirm", required=True)
    bootstrap_refresh_verify_parser.set_defaults(function=bootstrap_refresh_verify)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument(
        "--refresh-candidate",
        action="store_true",
        help=(
            "supersede an undeployed published candidate after an intentional "
            "source change; the prior immutable objects remain teardown-owned"
        ),
    )
    publish_parser.set_defaults(function=publish)
    subparsers.add_parser("dns-status").set_defaults(function=dns_status)
    source_parser = subparsers.add_parser("bind-qualification-source")
    source_parser.add_argument("--cidr", required=True)
    source_parser.add_argument("--confirm", required=True)
    source_parser.set_defaults(function=bind_qualification_source)
    subparsers.add_parser("change-set").set_defaults(function=create_change_set)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--confirm", required=True)
    execute_parser.set_defaults(function=execute)
    subparsers.add_parser("verify").set_defaults(function=verify)
    lifecycle_parser = subparsers.add_parser("lifecycle-test")
    lifecycle_parser.add_argument("--confirm", required=True)
    lifecycle_parser.set_defaults(function=lifecycle_test)
    headless_parser = subparsers.add_parser("run-headless")
    headless_parser.add_argument("--suite", choices=("smoke", "full"), default="smoke")
    headless_parser.add_argument("--confirm", required=True)
    headless_parser.set_defaults(function=run_headless)
    destroy_parser = subparsers.add_parser("destroy")
    destroy_parser.add_argument("--confirm", required=True)
    destroy_parser.set_defaults(function=destroy)
    destroy_finalize_parser = subparsers.add_parser("destroy-finalize")
    destroy_finalize_parser.add_argument("--confirm", required=True)
    destroy_finalize_parser.set_defaults(function=destroy_finalize)
    subparsers.add_parser("inventory").set_defaults(function=inventory)
    cleanup_orphans_parser = subparsers.add_parser("cleanup-orphans")
    cleanup_orphans_parser.add_argument("--confirm", required=True)
    cleanup_orphans_parser.set_defaults(function=cleanup_orphans)
    return value


def enforce_teardown_only_command_authority(args: argparse.Namespace) -> None:
    if args.command in {
        "init",
        "recover-lost-ledger-review",
        "recover-lost-ledger-execute",
    }:
        return
    path = ledger_path(args.execution_id)
    legacy = legacy_ledger_path(args.execution_id)
    if not os.path.lexists(path) and not os.path.lexists(legacy):
        return
    _path, ledger = load_ledger(args.execution_id)
    if ledger.get("recovery_mode") == "teardown_only" and args.command not in {
        "inventory",
        "destroy",
        "destroy-finalize",
    }:
        raise LiveTestError(
            "lost-ledger recovery is teardown-only; only inventory, destroy, and "
            "destroy-finalize are authorized"
        )


def main() -> int:
    args = parser().parse_args()
    try:
        with execution_lock(
            args.execution_id,
            root_scope=args.command
            in {"init", "recover-lost-ledger-review", "recover-lost-ledger-execute"},
        ):
            enforce_teardown_only_command_authority(args)
            args.function(args)
    except LiveTestError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
