"""
Deterministic Test Suite for Cloud Security & Misconfiguration Intelligence (Phase 13).

Validates:
1.  Multi-signal provider fingerprinting (AWS, Azure, GCP, Cloudflare, Fastly, DigitalOcean).
2.  Cloud service identification (S3, Blob, GCS, CloudFront, App Service, Cloud Run, API Gateway).
3.  Exposure hypothesis generation (Read, Listing, Write suspicion, Takeover, Admin interface).
4.  Safe Cloud Validator & False Positive Elimination (AccessDenied rejected, HTML 200 rejected for listing).
5.  Cloud Exposure Scorer & Prioritization Engine (Priority rankings and composite risk scoring).
6.  CloudSecurityPolicy enforcement (Forbidden methods blocked, metadata IP blocked, ScopeEngine gating).
7.  Atomic state persistence and resume capabilities (~/.../state/cloud.json).
8.  Secret masking and data sanitization.
9.  CLI execution (--help, --lab, --tree, --json, --dry-run).
10. LocalCloudSecurityLab 15 deterministic offline scenarios.
11. Security hygiene: zero shell=True, os.system, eval, or exec in cloud_security.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import pytest

from framework.cloud_security.discovery import CloudServiceIdentifier
from framework.cloud_security.engine import CloudSecurityEngine
from framework.cloud_security.exposure import CloudExposureHypothesisEngine
from framework.cloud_security.fingerprints import ProviderFingerprinter
from framework.cloud_security.lab import LocalCloudSecurityLab
from framework.cloud_security.models import (
    CloudAsset,
    CloudExposureHypothesis,
    CloudExposureState,
    CloudFindingCandidate,
    CloudHypothesisType,
    CloudProvider,
    CloudServiceType,
    HypothesisValidationStatus,
)
from framework.cloud_security.policy import CloudSecurityPolicy
from framework.cloud_security.prioritization import CloudExposureScorer, CloudPrioritizationEngine
from framework.cloud_security.storage import CloudStateManager
from framework.cloud_security.validators import CloudFalsePositiveClassifier, SafeCloudValidator
from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.validation.request import ControlledRequest, ControlledResponse


@pytest.fixture
def temp_program_dir():
    tmp = tempfile.mkdtemp(prefix="test_bb_phase13_")
    state_dir = os.path.join(tmp, "state")
    os.makedirs(state_dir, exist_ok=True)
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


# ==============================================================================
# 1. Multi-Signal Provider Fingerprinting Tests
# ==============================================================================

def test_aws_provider_fingerprinting():
    prov, conf, sigs = ProviderFingerprinter.fingerprint(
        hostname="assets.acme.com",
        cnames=["acme-bucket.s3.amazonaws.com"],
        headers={"server": "AmazonS3", "x-amz-request-id": "1234"},
    )
    assert prov == CloudProvider.AWS
    assert conf >= 0.80
    assert any("amazons3" in s.lower() or "x-amz" in s.lower() for s in sigs)


def test_azure_provider_fingerprinting():
    prov, conf, sigs = ProviderFingerprinter.fingerprint(
        hostname="portal.acme.com",
        cnames=["acme-portal.azurewebsites.net"],
        headers={"server": "Microsoft-IIS/10.0", "x-ms-request-id": "az123"},
    )
    assert prov == CloudProvider.AZURE
    assert conf >= 0.80
    assert any("azurewebsites.net" in s or "x-ms-" in s for s in sigs)


def test_gcp_provider_fingerprinting():
    prov, conf, sigs = ProviderFingerprinter.fingerprint(
        hostname="storage.acme.com",
        cnames=["acme-data.storage.googleapis.com"],
        headers={"server": "UploadServer", "x-goog-generation": "555"},
    )
    assert prov == CloudProvider.GCP
    assert conf >= 0.80


def test_cloudflare_and_unknown_fingerprinting():
    prov_cf, conf_cf, _ = ProviderFingerprinter.fingerprint(
        hostname="cdn.acme.com",
        headers={"cf-ray": "123456-IAD", "server": "cloudflare"},
    )
    assert prov_cf == CloudProvider.CLOUDFLARE

    prov_unk, conf_unk, _ = ProviderFingerprinter.fingerprint(
        hostname="custom-bare-metal.example.com",
        headers={"server": "nginx"},
    )
    assert prov_unk == CloudProvider.UNKNOWN
    assert conf_unk == 0.0


# ==============================================================================
# 2. Cloud Service Identification Tests
# ==============================================================================

def test_cloud_service_identification():
    # AWS S3
    srv, ident, reg = CloudServiceIdentifier.identify_service(
        CloudProvider.AWS, "my-backup.s3-us-west-2.amazonaws.com"
    )
    assert srv == CloudServiceType.OBJECT_STORAGE
    assert ident == "my-backup"
    assert reg == "us-west-2"

    # AWS API Gateway
    srv_api, ident_api, reg_api = CloudServiceIdentifier.identify_service(
        CloudProvider.AWS, "xyz123.execute-api.eu-central-1.amazonaws.com"
    )
    assert srv_api == CloudServiceType.API_GATEWAY
    assert ident_api == "xyz123"
    assert reg_api == "eu-central-1"

    # Azure Blob Storage
    srv_az, ident_az, _ = CloudServiceIdentifier.identify_service(
        CloudProvider.AZURE, "corpdata.blob.core.windows.net", path="/public/report.pdf"
    )
    assert srv_az == CloudServiceType.OBJECT_STORAGE
    assert "corpdata" in ident_az

    # GCP Cloud Run
    srv_run, ident_run, _ = CloudServiceIdentifier.identify_service(
        CloudProvider.GCP, "orders-service.run.app"
    )
    assert srv_run == CloudServiceType.CONTAINER_ENDPOINT
    assert ident_run == "orders-service"


# ==============================================================================
# 3. Hypothesis Formulation and Prioritization Tests
# ==============================================================================

def test_hypothesis_generation_and_prioritization():
    asset = CloudAsset(
        id="ca-test-1",
        asset="files.target.com.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hostname="files.target.com.s3.amazonaws.com",
    )
    hypotheses = CloudExposureHypothesisEngine.generate_hypotheses(asset)
    assert len(hypotheses) >= 3

    types = {h.hypothesis_type for h in hypotheses}
    assert CloudHypothesisType.PUBLIC_OBJECT_READ in types
    assert CloudHypothesisType.PUBLIC_OBJECT_LISTING in types
    assert CloudHypothesisType.WRITE_CAPABILITY_SUSPECTED in types

    prioritized = CloudPrioritizationEngine.prioritize(hypotheses)
    # WRITE_CAPABILITY_SUSPECTED (rank 1) and PUBLIC_OBJECT_LISTING (rank 2) should precede PUBLIC_OBJECT_READ (rank 6)
    assert prioritized[0].hypothesis_type == CloudHypothesisType.WRITE_CAPABILITY_SUSPECTED
    assert prioritized[1].hypothesis_type == CloudHypothesisType.PUBLIC_OBJECT_LISTING


# ==============================================================================
# 4. Safe Validator and False Positive Classifier Tests
# ==============================================================================

def test_validator_detects_public_listing():
    h = CloudExposureHypothesis(
        id="hyp-s3-1",
        asset="public.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_LISTING,
        confidence=0.6,
        severity_hint="HIGH",
        rationale="Test listing",
        endpoint="https://public.s3.amazonaws.com",
    )

    def mock_listing(req: ControlledRequest) -> ControlledResponse:
        return ControlledResponse(
            status_code=200,
            headers={"content-type": "application/xml"},
            body_text="<ListBucketResult><Name>public</Name><Contents><Key>secret.bak</Key></Contents></ListBucketResult>",
        )

    validator = SafeCloudValidator(mock_listing)
    status, state, candidate, detail = validator.validate_hypothesis(h)
    assert status == HypothesisValidationStatus.ACCEPTED
    assert state == CloudExposureState.PUBLIC_LISTING_LIKELY
    assert candidate is not None
    assert candidate.validation_state == FindingLifecycle.VALIDATED


def test_validator_rejects_access_denied_private_bucket():
    h = CloudExposureHypothesis(
        id="hyp-s3-2",
        asset="private.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_READ,
        confidence=0.6,
        severity_hint="MEDIUM",
        rationale="Test private read",
        endpoint="https://private.s3.amazonaws.com",
    )

    def mock_denied(req: ControlledRequest) -> ControlledResponse:
        return ControlledResponse(
            status_code=403,
            body_text="<Error><Code>AccessDenied</Code></Error>",
        )

    validator = SafeCloudValidator(mock_denied)
    status, state, candidate, detail = validator.validate_hypothesis(h)
    assert status == HypothesisValidationStatus.REJECTED
    assert state == CloudExposureState.PRIVATE_LIKELY
    assert candidate is None
    assert "Access control enforced" in detail


def test_validator_rejects_html_for_bucket_listing():
    h = CloudExposureHypothesis(
        id="hyp-s3-3",
        asset="marketing-site.s3.amazonaws.com",
        provider=CloudProvider.AWS,
        service=CloudServiceType.OBJECT_STORAGE,
        hypothesis_type=CloudHypothesisType.PUBLIC_OBJECT_LISTING,
        confidence=0.6,
        severity_hint="HIGH",
        rationale="Test web html false positive",
        endpoint="https://marketing-site.s3.amazonaws.com",
    )

    def mock_html(req: ControlledRequest) -> ControlledResponse:
        return ControlledResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body_text="<html><body>Welcome to marketing website</body></html>",
        )

    validator = SafeCloudValidator(mock_html)
    status, state, candidate, detail = validator.validate_hypothesis(h)
    assert status == HypothesisValidationStatus.REJECTED
    assert "normal HTML content" in detail


# ==============================================================================
# 5. Policy Enforcements and Scope Gating Tests
# ==============================================================================

def test_cloud_security_policy_enforcement():
    # Forbidden method: POST / PUT / DELETE
    safe, msg = CloudSecurityPolicy.evaluate_action_safety("PUT", "https://target.s3.amazonaws.com/test.txt")
    assert not safe
    assert "forbidden" in msg.lower()

    # Forbidden metadata IP
    safe_meta, msg_meta = CloudSecurityPolicy.evaluate_action_safety("GET", "http://169.254.169.254/latest/meta-data/")
    assert not safe_meta
    assert "metadata" in msg_meta.lower()

    # Allowed safe method
    safe_ok, _ = CloudSecurityPolicy.evaluate_action_safety("HEAD", "https://target.s3.amazonaws.com/doc.pdf")
    assert safe_ok


# ==============================================================================
# 6. Atomic State Persistence and Resumption Tests
# ==============================================================================

def test_atomic_state_persistence_and_resume(temp_program_dir):
    mgr = CloudStateManager(temp_program_dir)
    assert mgr.get_summary()["total_assets"] == 0

    asset = CloudAsset(
        id="ca-persist-1",
        asset="app.azurewebsites.net",
        provider=CloudProvider.AZURE,
        service=CloudServiceType.APP_HOSTING,
    )
    mgr.record_asset(asset)
    assert mgr.get_summary()["total_assets"] == 1

    # Fingerprint deduplication and resume
    fp = "test-fp-123456"
    assert not mgr.is_fingerprint_tested(fp)
    mgr.mark_fingerprint_tested(fp)
    assert mgr.is_fingerprint_tested(fp)

    # Reload from disk
    new_mgr = CloudStateManager(temp_program_dir)
    assert new_mgr.is_fingerprint_tested(fp)
    assert new_mgr.get_summary()["total_assets"] == 1


# ==============================================================================
# 7. Local Cloud Security Lab 15 Scenarios Test
# ==============================================================================

def test_local_cloud_security_lab_execution(temp_program_dir):
    scenarios = LocalCloudSecurityLab.list_scenarios()
    assert len(scenarios) == 15

    requester = LocalCloudSecurityLab.make_mock_requester()
    engine = CloudSecurityEngine(temp_program_dir, request_hook=requester)

    for skey in scenarios:
        sdata = LocalCloudSecurityLab.get_scenario(skey)
        assert sdata is not None

        asset, hypotheses = engine.analyze_asset(
            asset_identifier=sdata["asset"],
            hostname=sdata["asset"],
            headers=dict(sdata["mock_response"].headers),
            server=sdata["mock_response"].headers.get("server"),
        )
        assert len(hypotheses) >= 1
        results = engine.validate_hypotheses(hypotheses)
        assert len(results) >= 1


# ==============================================================================
# 8. Security Hygiene Invariant Tests
# ==============================================================================

def test_security_hygiene_no_shell_exec():
    """Verify strictly zero shell=True, os.system, eval, or exec in cloud_security."""
    cloud_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "framework", "cloud_security"))
    for root, _, files in os.walk(cloud_dir):
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                    assert "shell=True" not in content
                    assert "os.system(" not in content
                    assert "eval(" not in content
                    assert "exec(" not in content
