---
description: Research public disclosures and generate scope-aware next-step recommendations (Phase 23)
---

Run the BugBounty-Agent Phase 23 `/Arise` workflow for `$ARGUMENTS` using the existing `Bug-Bounty` primary agent and the `knowledge-research` skill. Do not create or delegate to a subagent.

Resolve the selected local program workspace. If the program is ambiguous, ask which workspace to use. Read its current scope configuration offline before associating anything with assets. If scope is missing or invalid, stop recommendation generation.

Read the Phase 23 guide and skill instructions. Rebuild the local coverage view with `bb-plan --program <name> --coverage-only --json`. Use the available read-only public research/search capability to recheck every saved source link and search for relevant **publicly disclosed** material. Do not use private or undisclosed reports, copy full reports, or claim that target vulnerabilities exist based on public reports. If no research capability is available, state that sources were not checked and mark them unchecked.

Save only short, sanitized, attributed report metadata in a JSON file under the selected program's local `state/` directory. Run `bb-arise` with `--discoveries` and explicit `--checked-source` / `--unchecked-source` host flags reflecting actual source checks. Then run `bb-plan` with a bounded request budget and review the ranked recommendations, skipped categories, assumptions, public source references, estimated cost, and score factors.

This workflow is research and planning only. Do not send requests to target assets, launch scanners, validate recommendations, modify customer data, or submit reports. State explicitly that selecting a recommendation is not approval; any active follow-up must separately pass current scope checks and the existing human approval and dispatch gates. Keep all target state and research metadata in the local workspace, never in Git.
