"""
Precision Barrier Synchronizer for Concurrent Burst Dispatching.

Uses threading.Barrier to coordinate parallel worker threads so requests
reach the server within the same microsecond execution window.
"""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from framework.concurrency.model import SingleProbeExecution
from framework.validation.request import ControlledRequest, ControlledResponse


class BarrierSynchronizer:
    """Coordinates deterministic parallel microsecond burst execution."""

    def __init__(self, dispatch_fn: Callable[[ControlledRequest], ControlledResponse], timeout: float = 5.0):
        self.dispatch_fn = dispatch_fn
        self.timeout = max(1.0, float(timeout))

    def dispatch_burst(
        self,
        base_request: ControlledRequest,
        burst_size: int = 4,
        per_request_mutations: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Tuple[SingleProbeExecution, Optional[ControlledResponse]]]:
        """
        Executes a synchronized burst of requests using a threading.Barrier.
        
        All worker threads are instantiated and pre-armed, then held at the barrier.
        Upon release, all threads execute simultaneously to trigger the server-side race window.
        """
        burst_size = max(2, min(10, int(burst_size)))
        barrier = threading.Barrier(parties=burst_size, timeout=self.timeout)
        results: List[Optional[Tuple[SingleProbeExecution, Optional[ControlledResponse]]]] = [None] * burst_size

        is_finalized = threading.Event()
        lock = threading.Lock()
        threads: List[threading.Thread] = []

        def worker(idx: int, req: ControlledRequest):
            try:
                # Wait for all sibling threads to reach the barrier
                barrier.wait(timeout=self.timeout)
            except (threading.BrokenBarrierError, Exception) as be:
                with lock:
                    if not is_finalized.is_set():
                        results[idx] = (
                            SingleProbeExecution(
                                request_index=idx,
                                status_code=0,
                                response_time_ms=0.0,
                                body_snippet="",
                                error=f"Barrier synchronization error: {be.__class__.__name__}",
                            ),
                            None,
                        )
                return

            start_t = time.perf_counter()
            try:
                resp = self.dispatch_fn(req)
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                with lock:
                    if is_finalized.is_set():
                        # Timed out and finalized: drop late response to prevent state mutation
                        return
                    snippet = (resp.body_text or resp.body or "")[:256]
                    exec_info = SingleProbeExecution(
                        request_index=idx,
                        status_code=resp.status_code,
                        response_time_ms=elapsed_ms,
                        body_snippet=snippet,
                        headers=resp.headers or {},
                    )
                    results[idx] = (exec_info, resp)
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                with lock:
                    if is_finalized.is_set():
                        return
                    exec_info = SingleProbeExecution(
                        request_index=idx,
                        status_code=0,
                        response_time_ms=elapsed_ms,
                        body_snippet="",
                        error=f"Dispatch error: {e.__class__.__name__}",
                    )
                    results[idx] = (exec_info, None)

        # Prepare distinct requests
        for i in range(burst_size):
            req_copy = copy.deepcopy(base_request)
            if per_request_mutations and i < len(per_request_mutations):
                mutation = per_request_mutations[i]
                if "headers" in mutation and isinstance(mutation["headers"], dict):
                    req_copy.headers.update(mutation["headers"])
                if "body" in mutation and isinstance(mutation["body"], str):
                    req_copy.body = mutation["body"]
            t = threading.Thread(target=worker, args=(i, req_copy), name=f"bb-race-worker-{i}")
            threads.append(t)
            t.start()

        # Join all threads with bounding timeout
        for t in threads:
            t.join(timeout=self.timeout + 1.0)

        # Finalize burst: lock out late worker writes
        with lock:
            is_finalized.set()

        # Inspect worker completion and populate uninitialized entries
        final_results = []
        for idx, entry in enumerate(results):
            if entry is not None and not threads[idx].is_alive():
                final_results.append(entry)
            else:
                final_results.append((
                    SingleProbeExecution(
                        request_index=idx,
                        status_code=0,
                        response_time_ms=0.0,
                        body_snippet="",
                        error="Worker execution timed out",
                    ),
                    None,
                ))

        return final_results
