"""Trust-boundary status for Phase 21 controlled execution provenance.

The current implementation runs dispatch, evidence persistence, and capability
issuance in one Python security context. Caller-constructible objects and
caller-writable artifacts cannot establish an independent transport authority.
Mode B therefore remains disabled until a separate OS-isolated dispatcher owns
network I/O, signing keys, approval consumption, and evidence persistence.
"""

PROVENANCE_BOUNDARY_STATUS = "UNAVAILABLE"
PROVENANCE_BOUNDARY_REASON = (
    "No isolated OS-enforced dispatcher currently owns transport execution and provenance"
)
