"""
State Machine Model and Safe Replay Engine for Business Workflows (Phase 12).

Provides stateful modeling of multi-step application workflows and bounded replay execution:
- Exact request replay
- Modified parameter replay
- Out-of-order transition replay
- Bounded concurrency execution for deterministic race-condition testing in local labs
"""

from __future__ import annotations

import concurrent.futures
import copy
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import uuid

from framework.business_logic.model import (
    BusinessLogicCategory,
    Workflow,
    WorkflowStep,
    WorkflowTransition,
)
from framework.validation.request import ControlledRequest, ControlledResponse


class WorkflowStateMachine:
    """Manages state graph transitions and validates progression logic."""

    def __init__(self, workflow: Workflow):
        self.workflow = workflow
        self.current_state = "INITIAL"
        self.history: List[Dict[str, Any]] = []

    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        for s in self.workflow.steps:
            if s.step_id == step_id:
                return s
        return None

    def get_allowed_next_steps(self, from_state: Optional[str] = None) -> List[WorkflowStep]:
        state = from_state or self.current_state
        allowed_step_ids = [t.step_id for t in self.workflow.transitions if t.from_state == state]
        return [s for s in self.workflow.steps if s.step_id in allowed_step_ids]

    def transition_to(self, new_state: str, action_summary: str = "") -> None:
        self.history.append({
            "from_state": self.current_state,
            "to_state": new_state,
            "action": action_summary,
        })
        self.current_state = new_state


class WorkflowReplayEngine:
    """Bounded, safe replay execution engine for workflow transitions."""

    def __init__(
        self,
        send_request_hook: Callable[[ControlledRequest], ControlledResponse],
        max_replays: int = 5,
        max_concurrency: int = 5,
    ):
        self.send_request = send_request_hook
        self.max_replays = max(1, min(20, int(max_replays)))
        self.max_concurrency = max(1, min(10, int(max_concurrency)))

    def replay_single(
        self,
        base_request: ControlledRequest,
        mutations: Optional[Dict[str, Any]] = None,
        headers_override: Optional[Dict[str, str]] = None,
    ) -> ControlledResponse:
        """Executes a single mutated or exact replay request."""
        url = base_request.url or base_request.build_effective_url()
        method = base_request.method
        headers = dict(base_request.headers)
        if headers_override:
            headers.update(headers_override)

        body = base_request.body
        # Apply mutations if requested
        if mutations:
            parsed = urlparse(url)
            # If query mutation
            q_dict = dict(parse_qsl(parsed.query))
            for k, v in mutations.items():
                if k in q_dict or "?" in url:
                    q_dict[k] = str(v)
            new_query = urlencode(q_dict)
            url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            # If JSON body mutation
            if "application/json" in headers.get("content-type", "").lower() and body:
                import json
                try:
                    b_json = json.loads(body)
                    b_json.update(mutations)
                    body = json.dumps(b_json)
                except Exception:
                    pass

        req = ControlledRequest(
            url=url,
            method=method,
            headers=headers,
            body=body,
        )
        return self.send_request(req)

    def replay_sequence(
        self,
        requests: List[ControlledRequest],
    ) -> List[ControlledResponse]:
        """Executes sequential step replay with bounds checking."""
        responses: List[ControlledResponse] = []
        for r in requests[:self.max_replays]:
            responses.append(self.send_request(r))
        return responses

    def replay_concurrent(
        self,
        request: ControlledRequest,
        concurrency: int = 3,
    ) -> List[ControlledResponse]:
        """
        Executes bounded concurrent requests against deterministic local security lab.
        Enforces concurrency caps and threads.
        """
        count = max(2, min(self.max_concurrency, concurrency))
        responses: List[ControlledResponse] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(self.send_request, copy.deepcopy(request)) for _ in range(count)]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    responses.append(fut.result())
                except Exception as e:
                    pass

        return responses
