"""
Phase 21: Isolated Execution Dispatcher IPC Package.
"""

from framework.auth_correlation.ipc.protocol import (
    PROTOCOL_VERSION,
    MAX_MESSAGE_BYTES,
    IPCProtocolError,
    IPCValidationError,
    IPCTimeoutError,
    DispatcherUnavailableError,
    pack_message,
    read_framed_message,
    validate_request_frame,
    validate_response_frame,
)
from framework.auth_correlation.ipc.receipt import (
    RECEIPT_VERSION,
    canonicalize_receipt,
    sign_execution_receipt,
    verify_execution_receipt,
)
from framework.auth_correlation.ipc.client import (
    IsolatedDispatcherClient,
    get_default_ipc_endpoint,
)
from framework.auth_correlation.ipc.service import (
    IsolatedExecutionDispatcher,
)

__all__ = [
    "PROTOCOL_VERSION",
    "MAX_MESSAGE_BYTES",
    "RECEIPT_VERSION",
    "IPCProtocolError",
    "IPCValidationError",
    "IPCTimeoutError",
    "DispatcherUnavailableError",
    "pack_message",
    "read_framed_message",
    "validate_request_frame",
    "validate_response_frame",
    "canonicalize_receipt",
    "sign_execution_receipt",
    "verify_execution_receipt",
    "IsolatedDispatcherClient",
    "get_default_ipc_endpoint",
    "IsolatedExecutionDispatcher",
]
