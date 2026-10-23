"""
Precision Barrier Synchronizer for Concurrent Burst Dispatching.

Uses threading.Barrier to coordinate parallel worker threads so requests
reach the server within the same microsecond execution window.

Enforces:
1. Bounded overall synchronization deadline (no linear wait per worker).
2. Distinction between completed, failed, cancelled, and timed-out unresolved operations.
3. Isolated per-burst execution containers preventing late-worker state corruption.
4. Transport limitation documentation: Python socket/HTTP transport cannot forcibly kill
   in-flight remote requests, so timed-out in-flight operations are marked UNRESOLVED.
"""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from framework.concurrency.model import (
    SingleProbeExecution,
    WorkerLifecycleState,
)
from framework.validation.request import ControlledRequest, ControlledResponse


class BurstExecutionContainer:
    """
    Isolated result container for a single barrier burst execution.
    Seals results upon completion, locking out late worker thread mutations.
    """

    def __init__(self, burst_id: str, burst_size: int):
        self.burst_id = burst_id
        self.burst_size = burst_size
        self.is_sealed = False
        self.lock = threading.Lock()
        self.results: List[Optional[Tuple[SingleProbeExecution, Optional[ControlledResponse]]]] = [None] * burst_size

    def seal(self) -> None:
        """Permanently seals container to reject late worker writes."""
        with self.lock:
            self.is_sealed = True

    def record_result(
        self,
        idx: int,
        exec_info: SingleProbeExecution,
        resp: Optional[ControlledResponse],
    ) -> bool:
        """Records worker outcome if container is not sealed."""
        with self.lock:
            if self.is_sealed:
                return False
            self.results[idx] = (exec_info, resp)
            return True


class BarrierSynchronizer:
    """Coordinates deterministic parallel microsecond burst execution."""

    def __init__(
        self,
        dispatch_fn: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        timeout: float = 5.0,
    ):
        self.default_dispatch_fn = dispatch_fn
        self.timeout = max(1.0, float(timeout))

    def dispatch_burst(
        self,
        base_request: ControlledRequest,
        burst_size: int = 4,
        per_request_mutations: Optional[List[Dict[str, Any]]] = None,
        dispatch_fn: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
    ) -> List[Tuple[SingleProbeExecution, Optional[ControlledResponse]]]:
        """
        Executes a synchronized burst of requests using a threading.Barrier.
        
        All worker threads are instantiated and pre-armed, then held at the barrier.
        Upon release, all threads execute simultaneously to trigger the server-side race window.
        
        Total waiting time is bounded by a single overall deadline to prevent linear wait inflation.
        """
        active_dispatch_fn = dispatch_fn or self.default_dispatch_fn
        if not active_dispatch_fn:
            raise RuntimeError("No dispatch_fn provided to BarrierSynchronizer.")

        burst_size = max(2, min(10, int(burst_size)))
        burst_id = f"burst-{uuid.uuid4().hex[:8]}"
        container = BurstExecutionContainer(burst_id=burst_id, burst_size=burst_size)

        barrier = threading.Barrier(parties=burst_size, timeout=self.timeout)
        threads: List[threading.Thread] = []

        def worker(idx: int, req: ControlledRequest, burst_container: BurstExecutionContainer):
            try:
                # Wait for all sibling threads to reach the barrier
                barrier.wait(timeout=self.timeout)
            except (threading.BrokenBarrierError, Exception) as be:
                burst_container.record_result(
                    idx,
                    SingleProbeExecution(
                        request_index=idx,
                        status_code=0,
                        response_time_ms=0.0,
                        body_snippet="",
                        error=f"Barrier synchronization error: {be.__class__.__name__}",
                        worker_state=WorkerLifecycleState.CANCELLED,
                    ),
                    None,
                )
                return

            start_t = time.perf_counter()
            try:
                resp = active_dispatch_fn(req)
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                snippet = (resp.body_text or resp.body or "")[:256]
                exec_info = SingleProbeExecution(
                    request_index=idx,
                    status_code=resp.status_code,
                    response_time_ms=elapsed_ms,
                    body_snippet=snippet,
                    headers=resp.headers or {},
                    worker_state=WorkerLifecycleState.COMPLETED,
                )
                burst_container.record_result(idx, exec_info, resp)
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                exec_info = SingleProbeExecution(
                    request_index=idx,
                    status_code=0,
                    response_time_ms=elapsed_ms,
                    body_snippet="",
                    error=f"Dispatch error: {e.__class__.__name__}",
                    worker_state=WorkerLifecycleState.FAILED,
                )
                burst_container.record_result(idx, exec_info, None)

        # Prepare distinct requests and launch worker threads
        for i in range(burst_size):
            req_copy = copy.deepcopy(base_request)
            if per_request_mutations and i < len(per_request_mutations):
                mutation = per_request_mutations[i]
                if "headers" in mutation and isinstance(mutation["headers"], dict):
                    req_copy.headers.update(mutation["headers"])
                if "body" in mutation and isinstance(mutation["body"], str):
                    req_copy.body = mutation["body"]
            t = threading.Thread(
                target=worker,
                args=(i, req_copy, container),
                name=f"bb-race-worker-{i}-{burst_id}",
            )
            threads.append(t)
            t.start()

        # Bounded overall join deadline (prevents linear wait scaling across N workers)
        deadline = time.monotonic() + self.timeout + 1.0
        for t in threads:
            remaining = max(0.001, deadline - time.monotonic())
            t.join(timeout=remaining)

        # Seal container immediately: locks out any subsequent late worker writes
        container.seal()

        # Inspect completion status for each worker thread
        final_results: List[Tuple[SingleProbeExecution, Optional[ControlledResponse]]] = []
        for idx in range(burst_size):
            entry = container.results[idx]
            t = threads[idx]

            if t.is_alive():
                # Worker exceeded join deadline while still running in transport
                # Transport cannot kill in-flight socket: mark outcome as UNRESOLVED
                unresolved_exec = SingleProbeExecution(
                    request_index=idx,
                    status_code=0,
                    response_time_ms=0.0,
                    body_snippet="",
                    error=(
                        "Worker execution timed out while HTTP request in flight; "
                        "socket cancellation unsupported by transport; server mutation outcome unresolved."
                    ),
                    worker_state=WorkerLifecycleState.TIMED_OUT_UNRESOLVED,
                )
                final_results.append((unresolved_exec, None))
            elif entry is not None:
                final_results.append(entry)
            else:
                # Thread terminated without populating container
                final_results.append((
                    SingleProbeExecution(
                        request_index=idx,
                        status_code=0,
                        response_time_ms=0.0,
                        body_snippet="",
                        error="Worker terminated without producing response",
                        worker_state=WorkerLifecycleState.FAILED,
                    ),
                    None,
                ))

        return final_results
