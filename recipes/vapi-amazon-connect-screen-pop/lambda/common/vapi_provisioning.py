"""Ownership-safe Vapi provisioning for the canonical Bridgefu recipe."""

from __future__ import annotations

import hashlib
import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol


RECIPE_ID = "vapi-amazon-connect-screen-pop@1"
PENDING_PHYSICAL_ID = "bridgefu-vapi-pending"
ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
MAX_REQUEST_TIMEOUT_SECONDS = 15.0
MAX_READ_RETRIES = 1
RETRIABLE_HTTP_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class VapiProvisioningError(Exception):
    """Safe error whose message contains no credentials or payloads."""


class VapiApi(Protocol):
    def list(self, resource: str) -> list[Mapping[str, Any]]: ...

    def get(self, resource: str, resource_id: str) -> Mapping[str, Any] | None: ...

    def create(self, resource: str, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def update(
        self, resource: str, resource_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def delete(self, resource: str, resource_id: str) -> None: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class VapiHttpClient:
    """Small no-redirect Vapi client with bounded responses."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.vapi.ai",
        *,
        request_timeout=None,
        read_retries: int = MAX_READ_RETRIES,
    ) -> None:
        if not isinstance(api_key, str) or len(api_key) < 24:
            raise VapiProvisioningError("vapi_api_key_invalid")
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise VapiProvisioningError("vapi_base_url_invalid")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )
        if request_timeout is not None and not callable(request_timeout):
            raise VapiProvisioningError("vapi_request_timeout_invalid")
        if not isinstance(read_retries, int) or not 0 <= read_retries <= MAX_READ_RETRIES:
            raise VapiProvisioningError("vapi_retry_budget_invalid")
        self._request_timeout = request_timeout
        self._read_retries = read_retries

    def _timeout_seconds(self) -> float:
        value = (
            MAX_REQUEST_TIMEOUT_SECONDS
            if self._request_timeout is None
            else self._request_timeout()
        )
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0 < float(value) <= MAX_REQUEST_TIMEOUT_SECONDS
        ):
            raise VapiProvisioningError("vapi_request_timeout_invalid")
        return float(value)

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        allow_missing: bool = False,
    ) -> Any:
        if not path.startswith("/") or ".." in path:
            raise VapiProvisioningError("vapi_path_invalid")
        body = None
        headers = {
            "authorization": f"Bearer {self._api_key}",
            "accept": "application/json",
            "user-agent": "bridgefu-cloudformation/1",
        }
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(body) > 131_072:
                raise VapiProvisioningError("vapi_request_too_large")
            headers["content-type"] = "application/json"
        request = urllib.request.Request(
            self._base_url + path,
            data=body,
            method=method,
            headers=headers,
        )
        attempts = 1 + (self._read_retries if method == "GET" else 0)
        for attempt in range(attempts):
            try:
                with self._opener.open(
                    request, timeout=self._timeout_seconds()
                ) as response:
                    raw = response.read(1_048_577)
                    status = response.status
                break
            except urllib.error.HTTPError as error:
                if allow_missing and error.code == 404:
                    return None
                if (
                    method == "GET"
                    and error.code in RETRIABLE_HTTP_STATUS_CODES
                    and attempt + 1 < attempts
                ):
                    continue
                if error.code in (401, 403):
                    raise VapiProvisioningError("vapi_unauthorized") from None
                if error.code == 404:
                    raise VapiProvisioningError("vapi_resource_missing") from None
                if error.code == 409:
                    raise VapiProvisioningError("vapi_conflict") from None
                if error.code == 429:
                    raise VapiProvisioningError("vapi_throttled") from None
                raise VapiProvisioningError("vapi_request_failed") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if method == "GET" and attempt + 1 < attempts:
                    continue
                raise VapiProvisioningError("vapi_unavailable") from None
        if status < 200 or status >= 300:
            raise VapiProvisioningError("vapi_request_failed")
        if len(raw) > 1_048_576:
            raise VapiProvisioningError("vapi_response_too_large")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise VapiProvisioningError("vapi_response_invalid") from None

    def list(self, resource: str) -> list[Mapping[str, Any]]:
        # Vapi list endpoints default to a short first page.  The provisioner
        # deliberately uses the documented maximum page size and refuses a
        # full page: without a continuation contract, a full page cannot prove
        # that an owner scan was exhaustive.
        payload = self._request("GET", f"/{resource}?limit=1000")
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, Mapping) and isinstance(payload.get("results"), list):
            items = payload["results"]
        else:
            raise VapiProvisioningError("vapi_response_invalid")
        if len(items) >= 1_000 or not all(isinstance(item, Mapping) for item in items):
            raise VapiProvisioningError("vapi_response_invalid")
        return items

    def get(self, resource: str, resource_id: str) -> Mapping[str, Any] | None:
        resource_id = _resource_id(resource_id)
        result = self._request(
            "GET", f"/{resource}/{resource_id}", allow_missing=True
        )
        if result is not None and not isinstance(result, Mapping):
            raise VapiProvisioningError("vapi_response_invalid")
        return result

    def create(self, resource: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = self._request("POST", f"/{resource}", payload)
        if not isinstance(result, Mapping):
            raise VapiProvisioningError("vapi_response_invalid")
        return result

    def update(
        self, resource: str, resource_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        resource_id = _resource_id(resource_id)
        result = self._request("PATCH", f"/{resource}/{resource_id}", payload)
        if not isinstance(result, Mapping):
            raise VapiProvisioningError("vapi_response_invalid")
        return result

    def delete(self, resource: str, resource_id: str) -> None:
        resource_id = _resource_id(resource_id)
        self._request(
            "DELETE", f"/{resource}/{resource_id}", allow_missing=True
        )


@dataclass(frozen=True)
class ProvisioningConfig:
    stack_id: str
    deployment_id: str
    prepare_url: str
    transfer_url: str
    model: str
    voice_id: str
    webhook_token: str | None
    asset_root: Path

    def __post_init__(self) -> None:
        if not isinstance(self.stack_id, str) or not self.stack_id.startswith("arn:"):
            raise VapiProvisioningError("stack_identity_invalid")
        _resource_id(self.deployment_id)
        _https_url(self.prepare_url)
        _https_url(self.transfer_url)
        if not VALUE_PATTERN.fullmatch(self.model):
            raise VapiProvisioningError("vapi_model_invalid")
        if not VALUE_PATTERN.fullmatch(self.voice_id):
            raise VapiProvisioningError("vapi_voice_invalid")
        if self.webhook_token is not None and (
            not isinstance(self.webhook_token, str) or len(self.webhook_token) < 32
        ):
            raise VapiProvisioningError("webhook_credential_invalid")
        if not self.asset_root.is_dir():
            raise VapiProvisioningError("vapi_assets_missing")

    @property
    def owner_token(self) -> str:
        return hashlib.sha256(self.stack_id.encode("utf-8")).hexdigest()[:32]

    @property
    def assistant_name(self) -> str:
        prefix = re.sub(r"[^A-Za-z0-9-]", "-", self.deployment_id)[:17]
        return f"Bridgefu {prefix} {self.owner_token[:10]}"[:40]

    @property
    def credential_name(self) -> str:
        return f"Bridgefu {self.owner_token[:30]}"

    @property
    def metadata(self) -> dict[str, str]:
        return {
            "bridgefu_recipe": RECIPE_ID,
            "bridgefu_owner": self.owner_token,
            "bridgefu_deployment": self.deployment_id,
        }


@dataclass(frozen=True)
class ProvisionedVapi:
    assistant_id: str
    prepare_tool_id: str
    webhook_credential_id: str

    @property
    def physical_id(self) -> str:
        return (
            "bridgefu-vapi-v2:"
            f"{self.assistant_id}:{self.prepare_tool_id}:{self.webhook_credential_id}"
        )


def _resource_id(value: Any) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise VapiProvisioningError("vapi_resource_id_invalid")
    return value


def _https_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise VapiProvisioningError("vapi_endpoint_invalid")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise VapiProvisioningError("vapi_endpoint_invalid")
    return value


def parse_physical_id(value: Any) -> tuple[str, str, str | None]:
    if not isinstance(value, str):
        raise VapiProvisioningError("vapi_physical_id_invalid")
    parts = value.split(":")
    if len(parts) == 3 and parts[0] == "bridgefu-vapi-v1":
        return _resource_id(parts[1]), _resource_id(parts[2]), None
    if len(parts) == 4 and parts[0] == "bridgefu-vapi-v2":
        return (
            _resource_id(parts[1]),
            _resource_id(parts[2]),
            _resource_id(parts[3]),
        )
    raise VapiProvisioningError("vapi_physical_id_invalid")


def _load_asset(config: ProvisioningConfig, name: str) -> dict[str, Any]:
    if name not in {
        "assistant.json.tmpl",
        "prepare-handoff-tool.json.tmpl",
        "transfer-tool.json.tmpl",
    }:
        raise VapiProvisioningError("vapi_asset_invalid")
    path = (config.asset_root / name).resolve()
    try:
        path.relative_to(config.asset_root.resolve())
        payload = json.loads(path.read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        raise VapiProvisioningError("vapi_asset_invalid") from None
    if not isinstance(payload, dict):
        raise VapiProvisioningError("vapi_asset_invalid")
    return payload


def _replace(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value, value)
    if isinstance(value, list):
        return [_replace(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _replace(item, replacements) for key, item in value.items()}
    return value


def _preliminary_assistant(
    config: ProvisioningConfig,
    credential_id: str | None = None,
) -> dict[str, Any]:
    assistant = _load_asset(config, "assistant.json.tmpl")
    transfer = _load_asset(config, "transfer-tool.json.tmpl")
    assistant = _replace(
        assistant,
        {
            "__MODEL__": config.model,
            "__VOICE_ID__": config.voice_id,
            "__TRANSFER_URL__": config.transfer_url,
        },
    )
    assistant["model"].pop("toolIds", None)
    assistant["model"]["tools"] = [transfer]
    if credential_id is None:
        assistant["server"].pop("credentialId", None)
        assistant.pop("credentialIds", None)
    else:
        assistant["server"]["credentialId"] = credential_id
        assistant["credentialIds"] = [credential_id]
    assistant["name"] = config.assistant_name
    assistant["metadata"] = config.metadata
    return assistant


def _assistant_credential_id(assistant: Mapping[str, Any]) -> str | None:
    values = assistant.get("credentialIds")
    if values is None:
        values = []
    if not isinstance(values, list) or len(values) > 1:
        raise VapiProvisioningError("vapi_credential_result_invalid")
    listed_id = _resource_id(values[0]) if values else None
    server = assistant.get("server")
    server_id = None
    if isinstance(server, Mapping) and server.get("credentialId") is not None:
        server_id = _resource_id(server.get("credentialId"))
    if listed_id is not None and server_id is not None and listed_id != server_id:
        raise VapiProvisioningError("vapi_credential_result_invalid")
    return listed_id or server_id


def _credential_payload(config: ProvisioningConfig) -> dict[str, Any]:
    if not isinstance(config.webhook_token, str) or len(config.webhook_token) < 32:
        raise VapiProvisioningError("webhook_credential_invalid")
    return {
        "provider": "custom-credential",
        "name": config.credential_name,
        "authenticationPlan": {
            "type": "bearer",
            "token": config.webhook_token,
            "headerName": "Authorization",
            "bearerPrefixEnabled": True,
        },
    }


def _credential_id(credential: Mapping[str, Any]) -> str:
    return _resource_id(credential.get("id"))


def _is_owned_credential_shape(
    credential: Mapping[str, Any], config: ProvisioningConfig
) -> bool:
    plan = credential.get("authenticationPlan")
    return (
        credential.get("provider") == "custom-credential"
        and credential.get("name") == config.credential_name
        and isinstance(plan, Mapping)
        and plan.get("type") == "bearer"
        and plan.get("headerName", "Authorization") == "Authorization"
        and plan.get("bearerPrefixEnabled", True) is True
    )


def _prepare_tool(
    config: ProvisioningConfig, credential_id: str
) -> dict[str, Any]:
    return _replace(
        _load_asset(config, "prepare-handoff-tool.json.tmpl"),
        {
            "__PREPARE_URL__": config.prepare_url,
            "__WEBHOOK_CREDENTIAL_ID__": credential_id,
        },
    )


def _final_assistant(
    config: ProvisioningConfig,
    credential_id: str,
    prepare_tool_id: str,
) -> dict[str, Any]:
    assistant = _replace(
        _load_asset(config, "assistant.json.tmpl"),
        {
            "__MODEL__": config.model,
            "__VOICE_ID__": config.voice_id,
            "__TRANSFER_URL__": config.transfer_url,
            "__WEBHOOK_CREDENTIAL_ID__": credential_id,
            "__PREPARE_TOOL_ID__": prepare_tool_id,
        },
    )
    assistant["name"] = config.assistant_name
    assistant["metadata"] = config.metadata
    assistant["credentialIds"] = [credential_id]
    return assistant


def _owned_assistant(
    assistant: Mapping[str, Any], config: ProvisioningConfig
) -> bool:
    metadata = assistant.get("metadata")
    return (
        isinstance(metadata, Mapping)
        and metadata.get("bridgefu_recipe") == RECIPE_ID
        and metadata.get("bridgefu_owner") == config.owner_token
    )


def _assistant_id(assistant: Mapping[str, Any]) -> str:
    return _resource_id(assistant.get("id"))


def _tool_id(tool: Mapping[str, Any]) -> str:
    return _resource_id(tool.get("id"))


def _is_prepare_tool(
    tool: Mapping[str, Any], config: ProvisioningConfig
) -> bool:
    function = tool.get("function")
    server = tool.get("server")
    return (
        tool.get("type") == "function"
        and isinstance(function, Mapping)
        and function.get("name") == "prepare_handoff"
        and isinstance(server, Mapping)
        and server.get("url") == config.prepare_url
    )


def _find_assistant(
    client: VapiApi, config: ProvisioningConfig
) -> Mapping[str, Any] | None:
    matches = [
        item
        for item in client.list("assistant")
        if item.get("name") == config.assistant_name
    ]
    if len(matches) > 1:
        raise VapiProvisioningError("vapi_assistant_ambiguous")
    if not matches:
        return None
    if not _owned_assistant(matches[0], config):
        raise VapiProvisioningError("vapi_assistant_ownership_conflict")
    return matches[0]


def _find_credential(
    client: VapiApi,
    config: ProvisioningConfig,
    assistant: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    matches = [
        item
        for item in client.list("credential")
        if item.get("name") == config.credential_name
    ]
    if len(matches) > 1:
        raise VapiProvisioningError("vapi_credential_ambiguous")
    if not matches:
        return None
    credential = matches[0]
    if not _is_owned_credential_shape(credential, config):
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    attached_id = _assistant_credential_id(assistant)
    if attached_id is not None and attached_id != _credential_id(credential):
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    return credential


def _credential_name_matches(
    client: VapiApi, config: ProvisioningConfig
) -> list[Mapping[str, Any]]:
    return [
        item
        for item in client.list("credential")
        if item.get("name") == config.credential_name
    ]


def _find_prepare_tool(
    client: VapiApi,
    config: ProvisioningConfig,
    credential_id: str,
) -> Mapping[str, Any] | None:
    matches = [item for item in client.list("tool") if _is_prepare_tool(item, config)]
    if len(matches) > 1:
        raise VapiProvisioningError("vapi_prepare_tool_ambiguous")
    if not matches:
        return None
    server = matches[0].get("server")
    if not isinstance(server, Mapping) or server.get("credentialId") != credential_id:
        raise VapiProvisioningError("vapi_prepare_tool_ownership_conflict")
    return matches[0]


def provision_create(client: VapiApi, config: ProvisioningConfig) -> ProvisionedVapi:
    assistant = _find_assistant(client, config)
    if assistant is None:
        if _credential_name_matches(client, config):
            raise VapiProvisioningError("vapi_credential_ownership_conflict")
        assistant = client.create("assistant", _preliminary_assistant(config))
    if not _owned_assistant(assistant, config):
        raise VapiProvisioningError("vapi_assistant_ownership_conflict")
    assistant_id = _assistant_id(assistant)
    credential = _find_credential(client, config, assistant)
    if credential is None:
        credential = client.create("credential", _credential_payload(config))
    if not _is_owned_credential_shape(credential, config):
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    credential_id = _credential_id(credential)
    attached_id = _assistant_credential_id(assistant)
    if attached_id is not None and attached_id != credential_id:
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    assistant = client.update(
        "assistant",
        assistant_id,
        _preliminary_assistant(config, credential_id),
    )

    tool = _find_prepare_tool(client, config, credential_id)
    desired_tool = _prepare_tool(config, credential_id)
    if tool is None:
        tool = client.create("tool", desired_tool)
    prepare_tool_id = _tool_id(tool)
    client.update("tool", prepare_tool_id, desired_tool)
    client.update(
        "assistant",
        assistant_id,
        _final_assistant(config, credential_id, prepare_tool_id),
    )
    return ProvisionedVapi(assistant_id, prepare_tool_id, credential_id)


def provision_update(
    client: VapiApi,
    old_config: ProvisioningConfig,
    new_config: ProvisioningConfig,
    physical_id: str,
) -> ProvisionedVapi:
    assistant_id, prepare_tool_id, physical_credential_id = parse_physical_id(
        physical_id
    )
    assistant = client.get("assistant", assistant_id)
    tool = client.get("tool", prepare_tool_id)
    if assistant is None or tool is None:
        raise VapiProvisioningError("vapi_owned_resource_missing")
    if not _owned_assistant(assistant, old_config):
        raise VapiProvisioningError("vapi_assistant_ownership_conflict")
    if not _is_prepare_tool(tool, old_config):
        raise VapiProvisioningError("vapi_prepare_tool_ownership_conflict")
    credential_id = _assistant_credential_id(assistant)
    if credential_id is None:
        raise VapiProvisioningError("vapi_owned_resource_missing")
    if physical_credential_id is not None and physical_credential_id != credential_id:
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    credential = client.get("credential", credential_id)
    if credential is None:
        raise VapiProvisioningError("vapi_owned_resource_missing")
    if not _is_owned_credential_shape(credential, old_config):
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    server = tool.get("server")
    if (
        not _is_prepare_tool(tool, old_config)
        or not isinstance(server, Mapping)
        or server.get("credentialId") != credential_id
    ):
        raise VapiProvisioningError("vapi_prepare_tool_ownership_conflict")
    client.update("credential", credential_id, _credential_payload(new_config))
    client.update("tool", prepare_tool_id, _prepare_tool(new_config, credential_id))
    client.update(
        "assistant",
        assistant_id,
        _final_assistant(new_config, credential_id, prepare_tool_id),
    )
    return ProvisionedVapi(assistant_id, prepare_tool_id, credential_id)


def provision_delete(
    client: VapiApi,
    config: ProvisioningConfig,
    physical_id: str,
) -> None:
    pending = physical_id == PENDING_PHYSICAL_ID
    if pending:
        assistants = [
            item
            for item in client.list("assistant")
            if item.get("name") == config.assistant_name
            and _owned_assistant(item, config)
        ]
        credentials = [
            item
            for item in _credential_name_matches(client, config)
            if _is_owned_credential_shape(item, config)
        ]
        credential_ids = {_credential_id(item) for item in credentials}
        tools = []
        for item in client.list("tool"):
            server = item.get("server")
            if (
                _is_prepare_tool(item, config)
                and isinstance(server, Mapping)
                and server.get("credentialId") in credential_ids
            ):
                tools.append(item)
        for item in assistants:
            client.delete("assistant", _assistant_id(item))
        for item in tools:
            client.delete("tool", _tool_id(item))
        for item in credentials:
            client.delete("credential", _credential_id(item))
        return
    else:
        assistant_id, prepare_tool_id, credential_id = parse_physical_id(physical_id)
        assistant = client.get("assistant", assistant_id)
        tool = client.get("tool", prepare_tool_id)
        if credential_id is None:
            if assistant is not None:
                credential_id = _assistant_credential_id(assistant)
            if credential_id is None and tool is not None:
                server = tool.get("server")
                if isinstance(server, Mapping) and server.get("credentialId") is not None:
                    credential_id = _resource_id(server.get("credentialId"))
        credential = (
            client.get("credential", credential_id)
            if credential_id is not None
            else None
        )

    if assistant is not None and not _owned_assistant(assistant, config):
        raise VapiProvisioningError("vapi_assistant_ownership_conflict")
    if credential is not None and not _is_owned_credential_shape(credential, config):
        raise VapiProvisioningError("vapi_credential_ownership_conflict")
    if tool is not None:
        server = tool.get("server")
        if (
            not _is_prepare_tool(tool, config)
            or credential_id is None
            or not isinstance(server, Mapping)
            or server.get("credentialId") != credential_id
        ):
            raise VapiProvisioningError("vapi_prepare_tool_ownership_conflict")

    if not pending and assistant is not None:
        model = assistant.get("model")
        tool_ids = model.get("toolIds") if isinstance(model, Mapping) else None
        if tool is not None and (
            not isinstance(tool_ids, list) or prepare_tool_id not in tool_ids
        ):
            raise VapiProvisioningError("vapi_prepare_tool_ownership_conflict")
        attached_credential_id = _assistant_credential_id(assistant)
        if credential is not None and attached_credential_id != credential_id:
            raise VapiProvisioningError("vapi_credential_ownership_conflict")

    if assistant is not None:
        client.delete("assistant", assistant_id)
    if tool is not None and prepare_tool_id is not None:
        client.delete("tool", prepare_tool_id)
    if credential is not None and credential_id is not None:
        client.delete("credential", credential_id)
    if not pending:
        # A lost Create response can be followed by another owner-equivalent
        # create before the first write is list-visible.  After deleting the
        # physical-ID objects, exhaustively scan the deterministic owner keys
        # so such duplicates cannot outlive the stack.
        provision_delete(client, config, PENDING_PHYSICAL_ID)
