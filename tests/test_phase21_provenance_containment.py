"""Regression tests for fail-closed Phase 21 provenance containment."""
import pytest
from framework.auth_correlation.dispatcher import ControlledDispatchWorkflow
from framework.auth_correlation.ledger import ExecutionProvenanceError, issue_execution_capability
from framework.auth_correlation.model import ApprovalSecurityError, AttestationSecurityError
from framework.auth_correlation.revocation import _create_controlled_invalidation_attestation_from_record
from framework.common.evidence import EvidencePersistenceError, EvidenceStore


def test_mode_b_refuses_before_transport_or_approval_side_effects(tmp_path):
    class NeverDispatch:
        calls = 0
        def send_request(self, request):
            self.calls += 1
            raise AssertionError("transport must never be called")
    engine = NeverDispatch()
    workflow = ControlledDispatchWorkflow(program_id="test", state_dir=str(tmp_path / "state"), evidence_store=object(), transport_engine=engine)
    with pytest.raises(ApprovalSecurityError, match="isolated execution provenance boundary"):
        workflow.execute(None, "ACT-" + "0" * 64, {})
    assert engine.calls == 0
    assert not (tmp_path / "state" / "consumed_approvals.json").exists()


def test_caller_cannot_create_trusted_transport_capture(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    with pytest.raises(EvidencePersistenceError, match="cannot prove transport dispatch"):
        store.save_transport_dispatch_capture(request=object(), response=object(), action_id="ACT-" + "0" * 64, approval_id="approval", session_ref="session", principal_id="user", program_id="program", dispatch_op_id="DISP-OP-" + "0" * 64)


def test_capability_issuer_fails_closed_even_for_constructed_input():
    with pytest.raises(ExecutionProvenanceError, match="issuance is disabled"):
        issue_execution_capability(dispatch_result=object())


def test_controlled_attestation_factory_fails_closed():
    with pytest.raises(AttestationSecurityError, match="issuance is disabled"):
        _create_controlled_invalidation_attestation_from_record(execution_record=object(), execution_ledger=None, evidence_store=None)
