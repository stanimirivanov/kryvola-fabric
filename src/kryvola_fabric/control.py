"""Strict bounded metadata snapshots. These functions grant no execution or disclosure rights."""

import json
from importlib.resources import files
from typing import Any

from google.protobuf import (
    descriptor_pb2,
    descriptor_pool,
    json_format,
    message_factory,
    unknown_fields,
)
from google.protobuf.message import DecodeError, Message
from jsonschema import Draft202012Validator, ValidationError

_ASSETS = files("kryvola_fabric").joinpath("_spec")
_LIMITS = json.loads(_ASSETS.joinpath("limits.json").read_bytes())
_SCHEMAS = json.loads(_ASSETS.joinpath("schemas.json").read_bytes())
# Protobuf exports these C-backed APIs dynamically; ty cannot model the generated declarations.
_POOL = descriptor_pool.DescriptorPool()
for _file in descriptor_pb2.FileDescriptorSet.FromString(
    _ASSETS.joinpath("descriptor.bin").read_bytes()
).file:
    _POOL.Add(_file)
_VALIDATORS = {name: Draft202012Validator(schema) for name, schema in _SCHEMAS.items()}


class ControlError(ValueError):
    """Fixed safe code only; no original payload, diagnostic or exception chain."""


def check_control_size(payload: bytes, temporal: bool = False) -> None:
    if not isinstance(payload, bytes):
        raise ControlError("INVALID_CONTROL")
    maximum = int(_LIMITS["temporal_payload_bytes" if temporal else "control_bytes"])
    if len(payload) > maximum:
        raise ControlError("CONTROL_TOO_LARGE")


def _known(message: Message) -> bool:
    if len(unknown_fields.UnknownFieldSet(message)):
        return False
    for field, value in message.ListFields():
        if field.message_type:
            for child in value if field.is_repeated else [value]:
                if not _known(child):
                    return False
    return True


def _consistent(value: Any) -> bool:
    if isinstance(value, list):
        return all(_consistent(child) for child in value)
    if not isinstance(value, dict):
        return True
    if not all(_consistent(child) for child in value.values()):
        return False
    if "plan_ref" in value:
        if any(
            value[name]["tenant_scope"] != value["tenant_scope"]
            for name in ("plan_ref", "key_context_ref", "disclosure_identity")
        ):
            return False
        if value["disclosure_identity"]["logical_job_id"] != value["logical_job_id"]:
            return False
    if "operation" in value:
        ex = value.get("execution", value.get("observation", {}).get("execution"))
        if ex and (
            any(
                value["operation"][name] != ex["attempt"][name]
                for name in ("tenant_scope", "operation_id", "workflow_epoch")
            )
            or value["operation"]["deadline_unix_ms"] != ex["deadline_unix_ms"]
        ):
            return False
    for name in ("operators", "required_operators", "program_digests", "security_profiles"):
        if name in value and len(set(value[name])) != len(value[name]):
            return False
    if "input_refs" in value and (
        value["security_profile"] != "FHE-Q1"
        or any(
            ref["tenant_scope"] != value["operation"]["tenant_scope"] for ref in value["input_refs"]
        )
    ):
        return False
    if "output_refs" in value:
        state = value["execution"]["physical_state"]
        if (
            (state in ("FAILED", "CANCELLED", "EXPIRED")) == (value["error_code"] == "NONE")
            or (state == "SUCCEEDED") == (not value["output_refs"])
            or any(
                ref["tenant_scope"] != value["execution"]["attempt"]["tenant_scope"]
                for ref in value["output_refs"]
            )
        ):
            return False
    return True


def decode_control(kind: str, payload: bytes, temporal: bool = False) -> dict[str, Any]:
    """Check actual bytes before permissive typed decoding; return caller-owned raw metadata."""
    check_control_size(payload, temporal)
    result = None
    try:
        if not isinstance(kind, str) or kind not in _VALIDATORS:
            raise ValueError
        message = message_factory.GetMessageClass(
            _POOL.FindMessageTypeByName("kryvola.spec.v1." + kind)
        )()
        message.ParseFromString(payload)
        if not _known(message):
            raise ValueError
        value = json_format.MessageToDict(
            message, preserving_proto_field_name=True, always_print_fields_with_no_presence=True
        )
        _VALIDATORS[kind].validate(value)
        if not _consistent(value):
            raise ValueError
        result = value
    except ValueError, KeyError, TypeError, DecodeError, ValidationError:
        pass
    if result is None:
        raise ControlError("INVALID_CONTROL")
    return result


def temporal_call(payloads: list[tuple[str, bytes]], metadata: bytes = b"") -> list[dict[str, Any]]:
    """Include complete application headers/framing separately from serialized payload bytes."""
    if not isinstance(metadata, bytes):
        raise ControlError("INVALID_CONTROL")
    if not isinstance(payloads, list) or any(
        not isinstance(p, tuple) or len(p) != 2 for p in payloads
    ):
        raise ControlError("INVALID_CONTROL")
    total = len(metadata)
    if total > int(_LIMITS["temporal_call_bytes"]):
        raise ControlError("CONTROL_TOO_LARGE")
    for _, payload in payloads:
        check_control_size(payload, True)
        total += len(payload)
        if total > int(_LIMITS["temporal_call_bytes"]):
            raise ControlError("CONTROL_TOO_LARGE")
    return [decode_control(kind, payload, True) for kind, payload in payloads]
