"""Golden bytes, cross-object negatives, transport budgets and sanitized failures."""

import copy
import json
import traceback
import unittest
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory

from kryvola_fabric.control import ControlError, check_control_size, decode_control, temporal_call

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "contracts/native/vectors.json").read_bytes())
FIXTURES = json.loads((ROOT / "contracts/native/fixtures.json").read_bytes())
POOL = descriptor_pool.DescriptorPool()  # ty: ignore[possibly-missing-implicit-call]
for file in descriptor_pb2.FileDescriptorSet.FromString(  # ty: ignore[unresolved-attribute] - generated export
    (ROOT / "contracts/native/descriptor.bin").read_bytes()
).file:
    POOL.Add(file)


def wire(kind, value):
    message = message_factory.GetMessageClass(
        POOL.FindMessageTypeByName("kryvola.spec.v1." + kind)
    )()
    return json_format.ParseDict(value, message).SerializeToString()


class ControlTests(unittest.TestCase):
    def test_all_golden_bytes_and_limits(self):
        for vector in VECTORS:
            self.assertEqual(
                decode_control(vector["type"], bytes.fromhex(vector["wire"])), vector["value"]
            )
        large = next(bytes.fromhex(v["wire"]) for v in VECTORS if len(v["wire"]) == 131072)
        boundary = (ROOT / "tests/fixtures/temporal-execute.bin").read_bytes()
        self.assertEqual(len(boundary), 32768)
        self.assertEqual(decode_control("ExecuteRequest", boundary, True)["schema_version"], "1")
        with self.assertRaisesRegex(ControlError, "CONTROL_TOO_LARGE"):
            decode_control("ExecuteRequest", boundary + b"\0", True)
        self.assertEqual(len(large), 65536)
        with self.assertRaisesRegex(ControlError, "CONTROL_TOO_LARGE"):
            decode_control("ExecuteRequest", large + b"\0")
        check_control_size(b"x" * 32768, True)
        with self.assertRaises(ControlError):
            check_control_size(b"x" * 32769, True)
        for size in (32768, 65536):
            with self.assertRaises(ControlError):
                decode_control("ExecuteRequest", b"x" * size)

    def test_unknown_versions_fields_malformed_and_safe_errors(self):
        for kind, value in FIXTURES.items():
            for payload in (
                wire(kind, value) + b"\xf8\x1f\x01",
                wire(kind, {**value, "schema_version": "2"}),
                wire(kind, {k: v for k, v in value.items() if k != "schema_version"}),
                b"\xffSECRET_X",
                b'{"private_key":"SECRET_X"}',
            ):
                with self.assertRaises(ControlError) as caught:
                    decode_control(kind, payload)
                error = caught.exception
                self.assertEqual(str(error), "INVALID_CONTROL")
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertNotIn("SECRET_X", "".join(traceback.format_exception(error)))
        with self.assertRaises(ControlError):
            decode_control("FutureVersion", b"")
        request = message_factory.GetMessageClass(
            POOL.FindMessageTypeByName("kryvola.spec.v1.ExecuteRequest")
        )()
        request.ParseFromString(wire("ExecuteRequest", FIXTURES["ExecuteRequest"]))
        request.execution.MergeFromString(b"\xfa\x1f\x08SECRET_X")
        with self.assertRaises(ControlError):
            decode_control("ExecuteRequest", request.SerializeToString())

    def test_correlations_and_native_bounds(self):
        for change in (
            lambda v: v["operation"]["plan_ref"].update(tenant_scope="other"),
            lambda v: v["execution"]["attempt"].update(workflow_epoch="1"),
            lambda v: v["execution"].update(deadline_unix_ms="0"),
            lambda v: v["input_refs"][0].update(tenant_scope="other"),
            lambda v: v["input_refs"][0].update(byte_length="1073741825"),
            lambda v: v.update(required_operators=["ADD", "ADD"], security_profile="wrong"),
        ):
            value = copy.deepcopy(FIXTURES["ExecuteRequest"])
            change(value)
            with self.assertRaises(ControlError):
                decode_control("ExecuteRequest", wire("ExecuteRequest", value))
        observation = copy.deepcopy(FIXTURES["GetExecutionStatusResponse"])
        observation["execution"]["physical_state"] = "RUNNING"
        with self.assertRaises(ControlError):
            decode_control(
                "GetExecutionStatusResponse", wire("GetExecutionStatusResponse", observation)
            )

    def test_temporal_aggregate_uses_actual_bytes_and_metadata(self):
        payload = wire("GetCapabilitiesRequest", FIXTURES["GetCapabilitiesRequest"])
        self.assertEqual(
            len(
                temporal_call(
                    [("GetCapabilitiesRequest", payload)] * 4, b"x" * (131072 - 4 * len(payload))
                )
            ),
            4,
        )
        with self.assertRaisesRegex(ControlError, "CONTROL_TOO_LARGE"):
            temporal_call(
                [("GetCapabilitiesRequest", payload)] * 4, b"x" * (131073 - 4 * len(payload))
            )
        with self.assertRaises(ControlError):
            temporal_call([], b"x" * 131073)
