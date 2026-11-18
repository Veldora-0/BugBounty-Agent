# Phase 8 — Authorization, BOLA, and IDOR

**Status:** Implemented for candidate modeling and bounded differential checks; reliable active testing requires operator-managed test identities and explicit approval.
**Implementation:** **framework/authz/**, **scripts/bb-authz**, and the **authorization skill**
**State file:** **state/authorization.json** in the local program workspace.

## What authorization testing asks

Authorization is the rule that decides which signed-in person may perform an action or see a resource. A Broken Object Level Authorization issue (BOLA), often called an Insecure Direct Object Reference (IDOR), occurs when changing an object identifier lets a user access an object they should not be allowed to access. A function-level issue occurs when a user can invoke an action reserved for a more privileged role.

A useful test compares the same request under two researcher-controlled accounts with different ownership or privilege. For example, account A requests its own profile, then account B tries the same read-only profile request using the recorded identifier. If the second account receives account A’s private data, that is evidence of a possible access-control failure. Do not use random identifiers, real customer accounts, or requests that change or delete data.

## Inputs and workflow

The engine reads endpoint and resource candidates from API, web application, JavaScript, and authorization state. It associates test principals with those resources, creates candidate cases, and can compare expected and observed access. The **--principal** option selects an already configured test identity; it is not a credential-import option. Configure test identities through the project’s approved local workflow and keep their secrets out of the repository and command history.

Run in passive-only mode to inventory candidate resources without requests. Dry-run mode shows planned cases. Active tests need the configured scope plus explicit approval flags and must remain within the program’s permitted request and test budgets. Candidate and result records are stored in **authorization.json**.

## How to use it

~~~bash
# Discover and display candidate resources without sending requests.
bb-authz --program <program-name> --passive-only --tree

# Plan checks for one known endpoint and one configured test principal.
bb-authz --program <program-name> --endpoint https://app.example.org/api/profile --principal <test-principal> --dry-run --json

# Review the exact test dossier before any active work.
bb-authz --program <program-name> --dossier --json

# Approve one reviewed case and keep the run small.
bb-authz --program <program-name> --endpoint https://app.example.org/api/profile --principal <test-principal> --approve-id <case-id> --max-tests 1 --max-requests 2 --json
~~~

Review the installed CLI help before use. Prefer approval for one case over a broad approval option whenever the program and workflow support it.

## Evidence and interpretation

A strong authorization finding records which test principal owned the object, which principal made the comparison request, the exact resource relationship, what each account could see, and a sanitized response comparison. A status-code difference alone may not prove a data exposure. Some applications intentionally return a generic response, and cached or stale content can mislead.

Report the narrowest demonstrated boundary failure. Do not retrieve unrelated records to estimate scale. If the safe test cannot prove ownership or impact, keep it as a hypothesis and explain what evidence is missing. The report should not include account passwords, access tokens, or unnecessary personal data.

## Safety and limitations

Use only program-approved accounts and low-impact reads. Never enumerate other users or change ownership, roles, or financial state. Tests using local fixture principals validate the comparison logic; they do not prove that an application’s authorization model is correctly understood. Dynamic session-health and richer operator identity integration remain areas for improvement.

See **tests/test_authz_engine.py**, the [Phase 21 identity-correlation guide](PHASE-21-authentication-authorization-correlation.md), [security policy](../security.md), and [roadmap](../ROADMAP-24-PHASES.md).