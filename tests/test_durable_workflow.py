import unittest

from temporalio.api.common.v1 import Payload
from temporalio.api.failure.v1 import Failure
from temporalio.exceptions import ApplicationError

from kryvola_fabric.compute_workflow import (
    WorkflowFailureConverter,
    WorkflowPayloadConverter,
    workflow_id,
)


class WorkflowBoundaryTests(unittest.TestCase):
    def test_stable_identity_is_scoped_and_unambiguous(self):
        self.assertEqual(workflow_id("tenant", "op"), workflow_id("tenant", "op"))
        self.assertNotEqual(workflow_id("a:b", "c"), workflow_id("a", "b:c"))
        self.assertNotEqual(workflow_id("tenant", "op"), workflow_id("other", "op"))

    def test_encoded_application_budgets(self):
        converter = WorkflowPayloadConverter()
        self.assertTrue(converter.to_payloads([bytes(32000)]))
        for values in ([bytes(32768)], [bytes(30000)] * 5):
            with self.assertRaises(ValueError):
                converter.to_payloads(values)

    def test_inbound_budget_and_failure_redaction(self):
        converter = WorkflowPayloadConverter()
        with self.assertRaisesRegex(ValueError, "COMPUTE_PAYLOAD_TOO_LARGE"):
            converter.from_payloads([Payload(data=bytes(32769))])
        failure = Failure()
        WorkflowFailureConverter().to_failure(
            ApplicationError("COMPUTE_UNAVAILABLE", "private fixture detail"),
            converter,
            failure,
        )
        self.assertEqual(failure.message, "COMPUTE_UNAVAILABLE")
        self.assertFalse(failure.application_failure_info.non_retryable)
        self.assertNotIn(b"private fixture detail", failure.SerializeToString())
        self.assertLess(failure.ByteSize(), 32768)
