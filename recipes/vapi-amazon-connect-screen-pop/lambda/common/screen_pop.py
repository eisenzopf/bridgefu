"""Bounded customer-configurable screen-pop field contract."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


MAX_FIELDS = 8
MAX_CONFIG_BYTES = 4_096
MAX_CONTEXT_BYTES = 8_192
MAX_TOTAL_VALUE_BYTES = 8_192
KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
RESERVED_KEYS = frozenset(
    {
        "correlation_id",
        "schema_version",
        "vapi_call_reference",
        "vapi_call_fingerprint",
        "content_hash",
        "created_at",
        "updated_at",
        "expires_at",
        "handoff_status",
        "bridgefu_call_id",
        "attachment_expires_at",
        "screen_pop_schema_hash",
        "context_available",
    }
)


class ScreenPopConfigError(ValueError):
    """Low-cardinality field configuration or value error."""


@dataclass(frozen=True)
class ScreenPopField:
    key: str
    label: str
    description: str
    field_type: str = "text"
    max_length: int = 256
    required: bool = True
    choices: tuple[str, ...] = ()


DEFAULT_FIELDS = (
    ScreenPopField("customer_name", "Customer", "Caller's name for the agent.", max_length=256),
    ScreenPopField(
        "issue_summary",
        "Issue",
        "Short summary of why the caller needs an agent.",
        max_length=1_024,
    ),
    ScreenPopField("intent", "Intent", "Short routing or support intent.", max_length=128),
    ScreenPopField(
        "verification_status",
        "Verification",
        "Display-only summary of verification already completed.",
        max_length=128,
    ),
)


def default_fields_json() -> str:
    return fields_json(DEFAULT_FIELDS)


def fields_json(fields: Sequence[ScreenPopField]) -> str:
    return json.dumps(
        [
            {
                "key": field.key,
                "label": field.label,
                "description": field.description,
                "type": field.field_type,
                "max_length": field.max_length,
                "required": field.required,
                **(
                    {"choices": list(field.choices)}
                    if field.field_type == "choice"
                    else {}
                ),
            }
            for field in fields
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _plain_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ScreenPopConfigError(f"invalid_{field}")
    if any(ord(character) < 0x20 for character in value) or "<" in value or ">" in value:
        raise ScreenPopConfigError(f"invalid_{field}")
    return value


def parse_fields(value: str | Sequence[Mapping[str, Any]]) -> tuple[ScreenPopField, ...]:
    if isinstance(value, str):
        if not value or len(value.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ScreenPopConfigError("screen_pop_fields_invalid")
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            raise ScreenPopConfigError("screen_pop_fields_invalid") from None
    else:
        decoded = value
    if not isinstance(decoded, list) or not 1 <= len(decoded) <= MAX_FIELDS:
        raise ScreenPopConfigError("screen_pop_fields_invalid")
    fields: list[ScreenPopField] = []
    keys: set[str] = set()
    labels: set[str] = set()
    total = 0
    for item in decoded:
        if not isinstance(item, Mapping) or set(item) - {
            "key",
            "label",
            "description",
            "max_length",
            "required",
            "type",
            "choices",
        }:
            raise ScreenPopConfigError("screen_pop_fields_invalid")
        key = item.get("key")
        if (
            not isinstance(key, str)
            or KEY_PATTERN.fullmatch(key) is None
            or key in RESERVED_KEYS
            or key in keys
        ):
            raise ScreenPopConfigError("screen_pop_field_key_invalid")
        label = _plain_text(item.get("label"), "screen_pop_field_label", 64)
        normalized_label = label.casefold()
        if normalized_label in labels:
            raise ScreenPopConfigError("screen_pop_field_label_invalid")
        description = _plain_text(
            item.get("description"), "screen_pop_field_description", 256
        )
        field_type = item.get("type", "text")
        if field_type not in ("text", "choice"):
            raise ScreenPopConfigError("screen_pop_field_type_invalid")
        choices: tuple[str, ...] = ()
        if field_type == "text":
            max_length = item.get("max_length")
            if (
                isinstance(max_length, bool)
                or not isinstance(max_length, int)
                or not 1 <= max_length <= 1_024
                or "choices" in item
            ):
                raise ScreenPopConfigError("screen_pop_field_length_invalid")
        else:
            raw_choices = item.get("choices")
            if (
                not isinstance(raw_choices, list)
                or not 2 <= len(raw_choices) <= 20
                or "max_length" in item
            ):
                raise ScreenPopConfigError("screen_pop_field_choices_invalid")
            normalized_choices: set[str] = set()
            parsed_choices: list[str] = []
            for choice in raw_choices:
                choice = _plain_text(choice, "screen_pop_field_choice", 128)
                if choice in normalized_choices:
                    raise ScreenPopConfigError("screen_pop_field_choices_invalid")
                normalized_choices.add(choice)
                parsed_choices.append(choice)
            choices = tuple(parsed_choices)
            max_length = max(len(choice.encode("utf-8")) for choice in choices)
        required = item.get("required", True)
        if not isinstance(required, bool):
            raise ScreenPopConfigError("screen_pop_field_required_invalid")
        total += max_length
        keys.add(key)
        labels.add(normalized_label)
        fields.append(
            ScreenPopField(
                key,
                label,
                description,
                field_type,
                max_length,
                required,
                choices,
            )
        )
    if total > MAX_TOTAL_VALUE_BYTES:
        raise ScreenPopConfigError("screen_pop_fields_too_large")
    return tuple(fields)


def schema_hash(fields: Sequence[ScreenPopField]) -> str:
    return hashlib.sha256(fields_json(fields).encode("utf-8")).hexdigest()


def validate_values(
    raw: Mapping[str, Any], fields: Sequence[ScreenPopField]
) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ScreenPopConfigError("screen_pop_values_invalid")
    allowed = {field.key for field in fields}
    required = {field.key for field in fields if field.required}
    if set(raw) - allowed or not required.issubset(raw):
        raise ScreenPopConfigError("screen_pop_values_invalid")
    values: dict[str, str] = {}
    for field in fields:
        value = raw.get(field.key, "")
        if not isinstance(value, str) or len(value.encode("utf-8")) > field.max_length:
            raise ScreenPopConfigError("screen_pop_value_invalid")
        if (
            field.field_type == "choice"
            and value not in field.choices
            and not (value == "" and not field.required)
        ):
            raise ScreenPopConfigError("screen_pop_value_invalid")
        if any(
            ord(character) < 0x20 and character not in ("\t",)
            for character in value
        ):
            raise ScreenPopConfigError("screen_pop_value_invalid")
        values[field.key] = value
    if len(json.dumps(values, ensure_ascii=False).encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ScreenPopConfigError("screen_pop_values_too_large")
    return values


def vapi_parameters(fields: Sequence[ScreenPopField]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [field.key for field in fields if field.required],
        "properties": {
            field.key: {
                "type": "string",
                "description": field.description,
                **(
                    {"enum": list(field.choices)}
                    if field.field_type == "choice"
                    else {"maxLength": field.max_length}
                ),
            }
            for field in fields
        },
    }


def connect_rows(
    fields: Sequence[ScreenPopField], values: Mapping[str, str] | None
) -> dict[str, str]:
    rows: dict[str, str] = {}
    for index in range(1, MAX_FIELDS + 1):
        if index <= len(fields):
            field = fields[index - 1]
            rows[f"screen_pop_label_{index}"] = field.label
            rows[f"screen_pop_value_{index}"] = (
                values.get(field.key, "") if values is not None else ""
            )
            rows[f"screen_pop_key_{index}"] = field.key
        else:
            rows[f"screen_pop_label_{index}"] = ""
            rows[f"screen_pop_value_{index}"] = ""
            rows[f"screen_pop_key_{index}"] = ""
    return rows
