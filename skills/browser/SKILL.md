---
name: browser
description: Browser-based security investigation using headless automation, DOM execution observation, dynamic SPA analysis, and centralized network interception.
---

# Browser Security Investigation Methodology

## Core Objective
Analyze modern single-page applications (SPAs) and dynamic web interfaces that require JavaScript execution, DOM evaluation, and browser event simulation to expose attack surfaces and verify execution proofs while strictly enforcing privacy, data redaction, execution budgets, and scope constraints.

---

## 1. Prerequisites & Runtime Architecture
* **Strictly Opt-In**: Headless browser automation is disabled by default across all workflows (`browser_enabled=False`). It must be explicitly enabled by researchers for targeted verification.
* **Component Prerequisites**:
  * Python `playwright` package installed.
  * System browser driver (e.g. `/usr/bin/node` on Linux/Kali).
  * Sandboxed Chromium executable installed (`playwright install chromium`).
* **Truthful Capability Detection**: The system evaluates actual launchability before dispatching tasks. Missing packages or browser binaries return `UNAVAILABLE` without attempting automatic package downloads or background installations.
* **Headless & Sandboxed**: All execution occurs in headless mode with sandboxing enabled. Never requires an X11 or Wayland display server.

---

## 2. Scope & Destination Restrictions (Fail-Closed)
* **Local Validating Egress Security Proxy (`ValidatingEgressProxy`)**:
  * All headless browser egress is channeled through a local validating proxy on `127.0.0.1` launched with `--proxy-bypass-list=<-loopback>` to prevent Chromium from bypassing loopback proxying.
  * **Anti-DNS-Rebinding (IP Pinning)**: Resolves destination hostnames pre-flight and verifies *every* resolved address against SSRF prohibitions. Upstream TCP connections are established directly to the pre-validated numeric `sockaddr`, eliminating the DNS TOCTOU rebinding window.
  * **Pre-Connection Gating**: Validates destination IP, scheme, and scope before any upstream socket connection is initiated. If prohibited or out-of-scope, responds with `HTTP 403 Forbidden` and terminates the client socket without connecting upstream.
* **Centralized Network Policy (`BrowserNetworkPolicy`)**:
  * Applies to the initial main-frame navigation, all subsequent redirects, iframe loads, background subresources (scripts, images, stylesheets, fetch/XHR), and WebSocket connections.
  * **Protocol Restrictions**: Only `http`, `https`, `ws`, and `wss` schemes are permitted. Schemes such as `file:`, `data:`, `javascript:`, `ftp:`, and `gopher:` are immediately rejected.
  * **Literal IP Prohibitions**: Literal loopback (`127.0.0.0/8`, `::1`), private (RFC 1918), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, and cloud metadata (`169.254.169.254`) destinations are blocked.
  * **IPv4-Mapped IPv6**: Mapped representations (e.g. `::ffff:127.0.0.1`, `::ffff:169.254.169.254`) are unmapped and evaluated against prohibitions. Bracketed IPv6 authorities (e.g. `[::1]:80`, `[2606:2800:..]:443`) are parsed strictly.
  * **Scope Authorization**: Targets must match authorized rules in `scope.yaml`. Scope authorization cannot override destination or DNS safety failures.
  * **Service Worker Blocking**: Browser contexts configure `service_workers="block"` to prevent background workers from making unintercepted network requests.
* **WebSocket Security & Pre-Handshake Architecture Boundary**:
  * **Browser-Level Pre-Handshake Interception (`BrowserContext.route_web_socket`)**: Implemented via Playwright's WebSocket routing mechanism. When `allow_websockets=False`, all incoming `ws://` and `wss://` connections are intercepted at the browser engine level and closed with code 1008 prior to initiating an upstream connection; `ws_route.connect_to_server()` is never called, guaranteeing that the WebSocket handshake never reaches the server. When enabled, destinations undergo pre-flight SSRF and scope validation before connection.
  * **Transport Proxy Gating (`ValidatingEgressProxy`)**: Cleartext `ws://` upgrade requests are also intercepted and blocked pre-connection at the transport layer when `allow_websockets=False`. For encrypted `wss://` traversing TLS `CONNECT` tunnels, the proxy validates destinations, enforces anti-SSRF literal and DNS checks, and pins the connection to the validated IP tuple before connecting upstream.
  * **Post-Handshake Defense-in-Depth (`context.on("websocket")`)**: Maintained as a secondary audit and emergency cleanup hook across all contexts and popup pages.
* **Application-Level Enforcement vs. OS-Level Network Isolation**:
  * *Application-Level Boundary*: Proxy routing (`--proxy-server`, `--proxy-bypass-list=<-loopback>`) and route interception reliably constrain cooperative browser-initiated traffic, preventing web application SSRF, XSS callbacks, and DNS rebinding.
  * *OS-Level Boundary*: Application flags do not prevent raw socket syscalls if a compromised native renderer escapes the browser sandbox. Production deployments requiring kernel-level guarantees should supplement this with OS primitives (e.g. Linux network namespaces `ip netns` or container network policies).

---

## 3. Operational Execution Budgets
To prevent runaway browser instances, denial of service, or infinite loops, every session enforces explicit execution budgets:
* **Session Timeout**: Default 5.0s, hard ceiling 15.0s.
* **Redirect Limit**: Maximum 5 redirects per navigation chain.
* **Request Budget**: Maximum 50 network requests per session.
* **Route Observation**: Maximum 10 SPA route transitions.
* **Telemetry Caps**: Maximum 20 console messages, maximum 20 page errors.
* **Evidence Size**: Maximum 64 KB total evidence text payload.
* When a budget is exhausted, subsequent requests are aborted immediately and the session yields `BUDGET_EXCEEDED` without classifying the target as secure or vulnerable.

---

## 4. Privacy, Credential Redaction & Data Minimization
* **Zero Plaintext Credential Storage**:
  * Sensitive request headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`) are automatically redacted to `[REDACTED]`.
  * Sensitive query parameters (`token`, `access_token`, `api_key`, `key`, `secret`, `password`, `session`, `jwt`, `auth`, `code`) are redacted from URLs before logging or persistence.
  * Embedded URL credentials (`http://user:pass@host/`) have passwords stripped immediately.
  * Console messages, page errors, and exception traces are sanitized through global sensitive-pattern scrubbers before storage.
* **Storage & Body Restrictions**:
  * Never dump or persist raw POST request/response bodies.
  * Never extract, log, or persist raw localStorage/sessionStorage values containing JWTs or tokens. Inspect key names only.
  * Never record raw WebSocket message payload frames.
  * Never commit browser session cache, cookies, or profile folders to Git.

---

## 5. Dynamic Application & SPA Analysis
* **Bounded Route Observation**:
  * Monitors client-side navigation (History API `pushState`, `replaceState`, `hashchange`) within strict bounds.
  * Captures DOM mutation summaries (mutation count, dynamic `<script>` addition count) without unbounded DOM snapshots.
  * Records dynamically inserted script tag source URLs with query parameters sanitized.

---

## 6. Canary-Aware DOM & XSS Verification
* **Canary Correlation**:
  * Inject traceable unique canary tokens (`bbxss_<hex>`).
  * Only script dialogs (`alert`, `confirm`, `prompt`) whose message explicitly contains the injected canary token confirm execution.
* **Evidence Classification**:
  * `CONFIRMED`: Injected canary token verified inside an executed browser dialog.
  * `OBSERVED`: Clean browser execution completed; no script dialog triggered.
  * `INCONCLUSIVE`: Dialog triggered but did not match canary token (unrelated site notification/alert), or canary token was empty.
  * `BLOCKED`: Pre-flight destination safety, DNS check, or scope policy denied navigation.
  * `TIMEOUT`: Navigation or event processing exceeded the allotted timeout budget.
  * `BUDGET_EXCEEDED`: Request, redirect, or observation limits were reached.
  * `UNAVAILABLE`: Headless browser runtime is disabled or missing from the host.
* **Static Matches Remain Unconfirmed**: Co-occurrence of sources and sinks in client JavaScript remains candidate intelligence (`OBSERVED`), never confirmed findings without execution proof.

---

## 7. Exception-Safe Resource Lifecycle
* All browser automation utilizes `BrowserSessionManager` context management.
* Partial initialization failure (e.g. context fails after browser launches, or page fails after context opens) guarantees closure of all opened resources in reverse order without masking primary exceptions.
* All page, context, and browser instances close deterministically across success, timeout, and exception exits.
