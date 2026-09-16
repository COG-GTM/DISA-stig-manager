# STIG Manager D-DIL Connectivity Cybersecurity Engineering Assessment

Denied, Degraded, Intermittent, and Limited (D-DIL) connectivity assessment of the STIG Manager API and Web Client, prepared as an engineering deliverable for program-office review.

All tables and counts in this document are generated from [`ddil-findings.json`](ddil-findings.json) by [`build_ddil_summary.py`](build_ddil_summary.py); [`test_ddil_assessment.py`](test_ddil_assessment.py) verifies that every identifier appears in both files and that every `file:line` evidence reference resolves to an existing line at the assessed commit.

## 1. Summary

<!-- BEGIN GENERATED: summary -->
- Assessed commit: `c066205075826a893833d9c1491589309c9bac32` (`COG-GTM/DISA-stig-manager`, branch `main`, API package version 1.6.13).
- External dependencies enumerated: **8** (DEP-01, DEP-02, DEP-03, DEP-04, DEP-05, DEP-06, DEP-07, DEP-08).
- Failure modes analyzed: **32** = 8 dependencies x 4 conditions (Denied: 8, Degraded: 8, Intermittent: 8, Limited: 8).
- Failure modes by confidence: confirmed in code **24**, containing inferred elements **8**.
- Ranked engineering recommendations: **14** (effort S: 8, M: 5, L: 1; Engineering-owned: 10, requiring a Government decision: 4).
- Distinct NIST SP 800-53 Rev. 5 controls referenced: **18** (AC-12, AC-14, AU-12, AU-4, AU-5, AU-8, AU-9, CM-6, CP-10, IA-2, IA-5, SC-23, SC-45, SC-5, SC-8, SI-11, SI-7, SR-3).
- Lab test cases defined: **14** (one per recommendation).
- Items requiring a Government decision: **7**.
- Distinct `file:line` evidence references: **142**.
<!-- END GENERATED: summary -->

### Top five recommendations

<!-- BEGIN GENERATED: top-recommendations -->
1. **REC-01 - Bound client request time and fail fast when no token is held** (Degraded, Intermittent; SC-5, SI-11, AC-12; effort S; owner: Engineering)
2. **REC-02 - Make token refresh tolerant of transient IdP loss** (Degraded, Intermittent; IA-5, SC-23, AC-12; effort M; owner: Engineering)
3. **REC-03 - Define the IdP-unreachable policy for the API (JWKS staleness window)** (Denied, Intermittent; IA-5, SC-23, CP-10; effort M; owner: Government decision (policy) + Engineering (implementation))
4. **REC-04 - Provide a durable audit-log path independent of network log shipping** (Denied, Intermittent; AU-4, AU-5, AU-9, AU-12; effort M; owner: Engineering (deployment) + Government decision (acceptable gap))
5. **REC-05 - Remove stack traces and token payloads from failure-path outputs** (Denied, Degraded, Intermittent; SI-11, AU-9, IA-5; effort S; owner: Engineering)
<!-- END GENERATED: top-recommendations -->

## 2. Scope, method, and assessed revision

### 2.1 Scope

- **In scope:** the API (`api/source/`), the Web Client (`client/src/js/`), runtime configuration (`api/source/utils/config.js`), the container image definition (`Dockerfile`), the installation, authentication, reverse-proxy, and logging documentation (`docs/installation-and-setup/`), and the existing state/connectivity tests (`test/state/`).
- **Out of scope:** the OIDC provider implementation, the MySQL server, the reverse proxy product, the operating system and container runtime, and the separately packaged client parsing modules (`@nuwcdivnpt/stig-manager-client-modules`, consumed as a dependency at `client/src/js/modules/package.json:3`).
- **Assessment only.** No application, dependency, container, or CI change is proposed in this deliverable; recommendations are findings for engineering and Government disposition.

### 2.2 Method

1. Static reading of the API bootstrap path (`api/source/index.js`, `api/source/bootstrap/`), the state machine (`api/source/utils/state.js`), the OIDC/JWT middleware (`api/source/utils/auth.js`, `api/source/utils/jwksCache.js`), the MySQL layer (`api/source/service/utils.js`, `api/source/utils/PoolMonitor.js`), the logger (`api/source/utils/logger.js`), and the error handler (`api/source/bootstrap/errorHandlers.js`).
2. Static reading of the client bootstrap (`client/src/js/init.js`), the OIDC and state SharedWorkers (`client/src/js/workers/`), the XHR transport (`client/src/js/SM/Ajax.js`, `client/src/js/overrides.js`), the re-authentication UI (`client/src/js/stigman.js`), and the CKL/CKLB/XCCDF import flow (`client/src/js/SM/ReviewsImport.js`).
3. Enumeration of every network dependency and classification of behavior under each of the four D-DIL conditions.
4. Mapping of each finding to NIST SP 800-53 Rev. 5 controls and to a reproducible local lab test.

**Confidence marking.** Each failure mode is labelled *confirmed* (behavior read at the cited lines) or *inferred* (behavior that depends on a library or platform default which the repository does not set explicitly). Where behavior depends on runtime configuration, the environment variable and its default in `api/source/utils/config.js` are cited.

### 2.3 Assessed revision

The assessed commit is recorded in the summary above and in `ddil-findings.json` (`assessment.assessed_sha`). Line references in this document are valid at that commit only.

### 2.4 Architecture relevant to D-DIL

- The API listens first and only then initializes its two hard dependencies concurrently: OIDC discovery/JWKS and MySQL (`api/source/bootstrap/server.js:66-75`, `api/source/bootstrap/dependencies.js:7-18`). Either failing after `STIGMAN_DEPENDENCY_RETRIES` (default 24, `api/source/utils/config.js:21`) attempts at a fixed 5 s (`api/source/utils/auth.js:278-287`, `api/source/service/utils.js:245-255`) moves the state machine to `fail`, which calls `process.exit(1)` (`api/source/utils/state.js:180-184`).
- The state machine reports `available` only while both dependencies are up (`api/source/utils/state.js:82-89`). While not `available`, every `/api` request other than `/api/op/state*` is answered `503` with the state object (`api/source/bootstrap/middlewares.js:61-76`). The design is therefore **fail-closed**: no request is served with a missing dependency.
- The client is a single-page application whose tokens live only in SharedWorker memory (`client/src/js/workers/oidc-worker.js:4-7`), and which subscribes to the API state via SSE (`client/src/js/workers/state-worker.js:45`) so that dependency outages are surfaced to users (`client/src/js/SM/ApiState.js:31-53`).

## 3. External dependency matrix

Every network dependency identified at the assessed commit. "Startup" refers to API process start (or, for browser-side rows, application load).

<!-- BEGIN GENERATED: dependency-matrix -->
| ID | Dependency | Direction | Protocol/port | Required at startup? | Required per request? | Evidence (file:line) |
| --- | --- | --- | --- | --- | --- | --- |
| DEP-01 | OIDC Provider (discovery metadata + JWKS) - API side | API -> IdP (outbound) | HTTP or HTTPS per STIGMAN_OIDC_PROVIDER (default http://localhost:8080/realms/stigman); TCP port from the authority URL | Yes. Discovery + JWKS fetch is retried STIGMAN_DEPENDENCY_RETRIES (default 24) times at fixed 5 s; failure sets state 'fail' and the process exits 1. | No when the token kid is cached. Yes when an unknown kid is presented (one synchronous refresh). Background refresh at half of STIGMAN_JWKS_CACHE_MAX_AGE (default 10 min); API becomes 'unavailable' once the cache is stale. | `api/source/utils/config.js:95`, `api/source/utils/config.js:21`, `api/source/utils/config.js:100`, `api/source/utils/auth.js:239-291`, `api/source/utils/auth.js:51-71`, `api/source/utils/auth.js:209-215`, `api/source/utils/jwksCache.js:45-57`, `api/source/utils/jwksCache.js:85`, `api/source/bootstrap/dependencies.js:7-18`, `api/source/utils/state.js:176-184` |
| DEP-02 | MySQL database | API -> MySQL (outbound) | MySQL protocol over TCP; STIGMAN_DB_HOST default localhost, STIGMAN_DB_PORT default 3306; optional TLS via STIGMAN_DB_TLS_* (no default) | Yes. Preflight connection retried STIGMAN_DEPENDENCY_RETRIES (default 24) times at fixed 5 s, then version check (>= 8.0.24) and schema migration; failure sets state 'fail' and the process exits 1. | Yes. Every authenticated /api request loads the user row and may write lastAccess/lastClaims before the controller runs; all business data is in MySQL. | `api/source/utils/config.js:70-80`, `api/source/service/utils.js:162-200`, `api/source/service/utils.js:245-255`, `api/source/service/utils.js:287-324`, `api/source/utils/auth.js:117`, `api/source/utils/auth.js:128-139`, `api/source/utils/PoolMonitor.js:31-54`, `api/source/bootstrap/dependencies.js:7-18` |
| DEP-03 | OIDC Provider (metadata, authorization endpoint, token endpoint) - browser side | Browser -> IdP (outbound from user workstation) | HTTPS required in practice (client refuses to run outside a secure context); authority from STIGMAN_CLIENT_OIDC_PROVIDER, falling back to STIGMAN_OIDC_PROVIDER | Yes (application load). The client fetches /.well-known/openid-configuration, then performs an authorization-code + PKCE (S256) flow. | No. Needed at access-token refresh (scheduled 10 s before exp) and at re-authentication after a refresh failure, refresh-token expiry, or idle timeout. | `client/src/js/init.js:12`, `client/src/js/init.js:71-83`, `client/src/js/init.js:93-94`, `api/source/utils/config.js:37`, `client/src/js/workers/oidc-worker.js:313-322`, `client/src/js/workers/oidc-worker.js:334-346`, `client/src/js/workers/oidc-worker.js:527-553`, `client/src/js/workers/oidc-worker.js:555-572` |
| DEP-04 | STIG Manager API (REST, /op/state, SSE /op/state/sse, WebSocket /socket/log-socket) | Browser -> API (inbound to API) | HTTP on STIGMAN_API_PORT (default 54000) or HTTPS when STIGMAN_API_TLS_KEY_FILE and STIGMAN_API_TLS_CERT_FILE are set; client path prefix STIGMAN_CLIENT_API_BASE (default 'api') | Yes (application load). Env.js and static assets are served by the API; the state SharedWorker must receive the first SSE event within 5 s and the app blocks until currentState is 'available'. | Yes. Every data operation is an XHR with an Authorization: Bearer header; XHRs are silently not sent when no token is held. | `api/source/utils/config.js:59-62`, `api/source/utils/config.js:38`, `api/source/bootstrap/server.js:39-49`, `api/source/bootstrap/client.js:66-72`, `client/src/js/workers/state-worker.js:45-75`, `client/src/js/init.js:293-325`, `client/src/js/SM/Ajax.js:189-213`, `client/src/js/stigman.js:1`, `api/source/controllers/Operation.js:126-164` |
| DEP-05 | Reverse proxy / ingress controller (optional; required for mTLS/CAC) | Browser -> Proxy -> API | HTTPS (site-specific, typically TCP 443) on the front side; HTTP/HTTPS to the API on the back side | Yes when deployed - all client traffic, including the SSE stream the client requires at load, traverses it. | Yes when deployed. Proxy buffering or short idle timeouts break the SSE, NDJSON streaming, and WebSocket endpoints. | `docs/installation-and-setup/reverse-proxy.rst:12-20`, `docs/installation-and-setup/reverse-proxy.rst:56-60`, `docs/installation-and-setup/reverse-proxy.rst:67-88`, `docs/installation-and-setup/reverse-proxy.rst:136-140`, `api/source/controllers/Operation.js:131`, `client/src/js/workers/state-worker.js:7-9`, `client/src/js/workers/state-worker.js:67-74` |
| DEP-06 | npm registry / package sources (build time; runtime only if launched via npm start) | Build host -> registry.npmjs.org and PyPI (outbound) | HTTPS TCP 443 | No for the container image (CMD runs node index.js directly). Yes if the API is launched with `npm start`, because the `prestart` script runs `npm install`. | No. | `Dockerfile:31-32`, `Dockerfile:55`, `api/source/package.json:7-8`, `client/build.sh:5-6`, `client/src/js/modules/package.json:2-6`, `docs/requirements.txt:1` |
| DEP-07 | Object storage / other outbound HTTP - none present | N/A (no object storage; the only outbound HTTP client in the API is the OIDC discovery/JWKS fetch) | N/A. Uploaded files are buffered in API process memory (multer memoryStorage) up to STIGMAN_API_MAX_UPLOAD (default 1073741824 bytes) and never written to external storage. | No. | No. | `api/source/bootstrap/middlewares.js:42-51`, `api/source/utils/config.js:62`, `api/source/utils/auth.js:9`, `api/source/utils/auth.js:253`, `api/source/healthcheck.js:10` |
| DEP-08 | Container health probe -> API (loopback) | Orchestrator -> API (localhost) | HTTP to localhost:STIGMAN_API_PORT (default 54000), 2 s timeout | N/A (probe only). The probe path /api/op/definition is behind the 503 service check, so the probe fails whenever MySQL or the OIDC provider is unavailable. | N/A. | `api/source/healthcheck.js:3-8`, `api/source/healthcheck.js:12-17`, `api/source/bootstrap/middlewares.js:61-76` |
<!-- END GENERATED: dependency-matrix -->

Notes:

- There is **no object storage** and **no outbound HTTP other than OIDC discovery/JWKS**: the only `fetch` in the API is the discovery call (`api/source/utils/auth.js:253`), the JWKS fetch uses Node `http`/`https` (`api/source/utils/jwksCache.js:92-93`), and uploads are held in process memory (`api/source/bootstrap/middlewares.js:43`).
- The API can terminate TLS itself when `STIGMAN_API_TLS_KEY_FILE` and `STIGMAN_API_TLS_CERT_FILE` are set (`api/source/utils/config.js:63-67`, `api/source/bootstrap/server.js:41-49`); otherwise transport protection depends on the reverse proxy (`docs/installation-and-setup/reverse-proxy.rst:12-20`).
- `CORS` is enabled with library defaults (`api/source/bootstrap/middlewares.js:53-55`); this is unrelated to D-DIL and is noted for completeness only.

## 4. Failure-mode analysis

One row per dependency per condition. "Security consequence" uses the categories auth-bypass risk, audit-log gap, data-integrity risk, session fixation/stale-token risk, information disclosure via error handling, and availability/DoS.

<!-- BEGIN GENERATED: failure-modes -->
| ID | Dependency | Condition | Observed/expected behavior | Confidence | Security consequence | Evidence (file:line) |
| --- | --- | --- | --- | --- | --- | --- |
| FM-01 | DEP-01 OIDC Provider (discovery metadata + JWKS) - API side | Denied | At startup: discovery is retried 24 times at 5 s (about 2 min), then state becomes 'fail' and the process exits with code 1. Mid-session: scheduled refresh (every cacheMaxAge/2, default 5 min) fails and is retried every 10 s; when the stale timer fires at cacheMaxAge (default 10 min) known keys are cleared, oidc status is set false, state becomes 'unavailable', and all /api requests except /api/op/state receive 503 until a refresh succeeds. Tokens carrying a kid not in cache are rejected with SigningKeyNotFoundError after one failed refresh attempt. | confirmed | availability loss (fail-closed); no auth bypass: unknown or stale keys are never trusted; audit-log gap while 503s are returned (transactions are still logged as 503) | `api/source/utils/auth.js:278-287`, `api/source/utils/state.js:180-184`, `api/source/utils/jwksCache.js:45-57`, `api/source/utils/jwksCache.js:63-74`, `api/source/utils/auth.js:209-215`, `api/source/utils/auth.js:51-71`, `api/source/bootstrap/middlewares.js:61-76` |
| FM-02 | DEP-01 OIDC Provider (discovery metadata + JWKS) - API side | Degraded | JWKS requests use a hard 10 s socket timeout; a timeout counts as a failed refresh. An unknown-kid lookup blocks the request for up to 10 s on the refresh before rejecting the token. The startup discovery fetch (undici) sets no explicit timeout, so a black-holed connection can consume the whole retry budget on a single attempt (inferred: undici defaults apply). | confirmed for timeout value; inferred for undici default behavior | latency amplification on unknown-kid requests; premature 'unavailable' if RTT exceeds 10 s; no bypass risk | `api/source/utils/jwksCache.js:85`, `api/source/utils/auth.js:55`, `api/source/utils/auth.js:253` |
| FM-03 | DEP-01 OIDC Provider (discovery metadata + JWKS) - API side | Intermittent | A failed scheduled refresh is retried every 10 s; the stale timer is only armed after a successful update, so the cache remains valid for cacheMaxAge after the last success. Recovery is automatic: the next successful refresh emits cacheUpdate, oidc status returns to true and state returns to 'available'. Unknown kids seen during an outage are cached as 'unknown' sentinels that survive a stale clear and are only removed by a subsequent successful update replacing the cache. | confirmed | stale-key risk bounded by STIGMAN_JWKS_CACHE_MAX_AGE (default 10 min): a key revoked at the IdP remains trusted until refresh; IdP key rotation during an outage causes user lockout until connectivity returns | `api/source/utils/jwksCache.js:54`, `api/source/utils/jwksCache.js:63-69`, `api/source/utils/auth.js:212-214`, `api/source/utils/auth.js:59-62`, `api/source/utils/config.js:100` |
| FM-04 | DEP-01 OIDC Provider (discovery metadata + JWKS) - API side | Limited | JWKS documents are small (a few KB) and are fetched at most every cacheMaxAge/2 plus on unknown kids; bandwidth is not a limiting factor unless throughput is so low that the 10 s timeout is hit. No compression or conditional (ETag) requests are used. | confirmed | none beyond FM-02 when the 10 s budget is exceeded | `api/source/utils/jwksCache.js:85`, `api/source/utils/jwksCache.js:45-50` |
| FM-05 | DEP-02 MySQL database | Denied | At startup: preflight retried 24 times at 5 s, then 'fail' and exit 1. Mid-session: db status is set false only when the pool emits 'remove' and the pool has become empty; a restore is attempted every 20 s (preflight + version check + schema check). While unavailable, /api requests return 503 with the state object. In-flight queries fail with a MySQL driver error that reaches the generic error handler as a 500 including the stack trace. | confirmed | availability loss; information disclosure: 500 responses include err.stack; audit-log gap: request transaction logs still go to stdout, but no business audit trail (review history) can be written; user lastAccess/lastClaims updates lost | `api/source/service/utils.js:245-255`, `api/source/service/utils.js:296`, `api/source/utils/PoolMonitor.js:31-38`, `api/source/utils/PoolMonitor.js:45-54`, `api/source/bootstrap/middlewares.js:61-76`, `api/source/bootstrap/errorHandlers.js:20-23` |
| FM-06 | DEP-02 MySQL database | Degraded | The pool config sets connectionLimit (default 25) and TCP keepalive (10 s initial delay) but no connectTimeout, no per-query timeout, and no acquire timeout. Slow queries therefore hold connections indefinitely; once 25 connections are busy new requests queue inside mysql2 with no bound (inferred: mysql2 default queueLimit 0 = unlimited). Because the client has an effectively infinite XHR timeout (30,000,000 ms), users see hung requests rather than errors. Deadlocks are retried 15 times at 200 ms. | confirmed for configuration; inferred for mysql2 queue default | denial of service via connection/queue exhaustion (SC-5); state remains 'available' so the SSE monitor does not warn users; no data-integrity risk: transactions commit or roll back atomically | `api/source/service/utils.js:163-183`, `api/source/utils/config.js:75`, `client/src/js/stigman.js:1`, `api/source/service/utils.js:595-617`, `api/source/service/utils.js:619-649` |
| FM-07 | DEP-02 MySQL database | Intermittent | Individual connection drops remove one pooled connection; db status is not changed unless the pool becomes empty, so single failed requests surface as 500 errors while the API still reports 'available'. Multi-statement operations use explicit START TRANSACTION/COMMIT with rollback on error, so partial writes inside one request are not committed. The client import loop is per-asset with no retry: a failed asset is reported and the loop continues, so a batch import can be partially applied. | confirmed | data-integrity risk at the batch level (partial imports) without an audit marker; information disclosure via 500 stack traces; misleading 'available' state | `api/source/utils/PoolMonitor.js:32-33`, `api/source/service/ReviewService.js:503`, `api/source/service/ReviewService.js:535`, `api/source/service/utils.js:619-649`, `client/src/js/SM/ReviewsImport.js:2394-2428`, `client/src/js/SM/ReviewsImport.js:2498-2504`, `api/source/bootstrap/errorHandlers.js:21` |
| FM-08 | DEP-02 MySQL database | Limited | Large result sets (checklist exports, review listings) and bulk review POSTs (up to STIGMAN_API_MAX_JSON_BODY, default 31457280 bytes) stream through the pool without pagination limits enforced by the server for most list endpoints. No query timeout means low DB throughput directly extends request duration; requests are not shed. | confirmed for limits; inferred for absence of server-side pagination (not exhaustively verified per endpoint) | resource exhaustion (SC-5); no integrity risk | `api/source/utils/config.js:61`, `api/source/bootstrap/middlewares.js:85-88`, `api/source/service/utils.js:163-183` |
| FM-09 | DEP-03 OIDC Provider (metadata, authorization endpoint, token endpoint) - browser side | Denied | At load: metadata fetch throws 'failed to get' and initialization stops at the loading screen. Mid-session: the access-token timer fires 10 s before exp, clears the access token, and calls refresh; the token endpoint fetch rejects, clearTokens(true) runs, and 'noToken' is broadcast. The UI shows a 'Credentials Expired' modal and all subsequent XHRs are silently not sent because window.oidcWorker.token is null. There is no offline or cached-credential path; tokens exist only in SharedWorker memory. | confirmed | hard session termination at access-token expiry (fail-closed); no stale-token risk: expired tokens are discarded client-side and rejected server-side; usability: unsaved work cannot be submitted | `client/src/js/init.js:71-83`, `client/src/js/workers/oidc-worker.js:313-322`, `client/src/js/workers/oidc-worker.js:555-572`, `client/src/js/stigman.js:284-303`, `client/src/js/stigman.js:380-389`, `client/src/js/SM/Ajax.js:192`, `client/src/js/workers/oidc-worker.js:4-7` |
| FM-10 | DEP-03 OIDC Provider (metadata, authorization endpoint, token endpoint) - browser side | Degraded | The refresh is attempted exactly once, 10 s before exp, with the browser default fetch timeout (no AbortController). If the round trip exceeds the 10 s buffer the new token arrives after the old one expired; in the gap XHRs are not sent (token cleared at timer fire). If the fetch ultimately errors, tokens are cleared and re-authentication is required even though the refresh token was still valid. | confirmed for buffer and single attempt; inferred for browser fetch timeout | unnecessary re-authentication under high latency; brief request blackout each refresh cycle | `client/src/js/workers/oidc-worker.js:334`, `client/src/js/workers/oidc-worker.js:346`, `client/src/js/workers/oidc-worker.js:315-320`, `client/src/js/workers/oidc-worker.js:532-536`, `client/src/js/workers/oidc-worker.js:568-571` |
| FM-11 | DEP-03 OIDC Provider (metadata, authorization endpoint, token endpoint) - browser side | Intermittent | A single failed refresh is terminal for the session (tokens cleared, no retry/backoff). Recovery requires the user to complete an interactive re-authentication via popup/iframe/tab/reload per STIGMAN_CLIENT_REAUTH_ACTION (default popup). PKCE verifier and state are stored in localStorage for the re-auth round trip. | confirmed | session-fixation resistance preserved (fresh PKCE verifier/state per attempt); user-visible interruption on every transient IdP blip aligned with a refresh window | `client/src/js/workers/oidc-worker.js:565-571`, `client/src/js/stigman.js:325-336`, `api/source/utils/config.js:44` |
| FM-12 | DEP-03 OIDC Provider (metadata, authorization endpoint, token endpoint) - browser side | Limited | OIDC traffic is small (metadata once per load, token endpoint at refresh). The IdP login page assets themselves are outside STIG Manager. No issue unless throughput is low enough to exceed the 10 s refresh buffer (see FM-10). | confirmed | none beyond FM-10 | `client/src/js/workers/oidc-worker.js:334`, `client/src/js/init.js:71-83` |
| FM-13 | DEP-04 STIG Manager API (REST, /op/state, SSE /op/state/sse, WebSocket /socket/log-socket) | Denied | At load: Env.js/static assets fail (blank page), or the state worker's EventSource errors and initialization fails with 'API connection error'. Mid-session: in-flight XHRs fail with status 0/13030 and the failure callback runs (SM.Error dialog); the state SSE reconnects every 3 s and broadcasts 'state-error'; SM.ApiState shows an 'API unavailable' modal. No client-side write queue exists: unsaved edits are lost if the page is reloaded. | confirmed | availability loss; data loss of uncommitted UI edits; no bypass or integrity risk | `client/src/js/workers/state-worker.js:48-54`, `client/src/js/workers/state-worker.js:110-125`, `client/src/js/SM/Ajax.js:98-107`, `client/src/js/SM/Ajax.js:121-137`, `client/src/js/SM/ApiState.js:31-53` |
| FM-14 | DEP-04 STIG Manager API (REST, /op/state, SSE /op/state/sse, WebSocket /socket/log-socket) | Degraded | Global Ext.Ajax.timeout is 30,000,000 ms (about 8.3 h), so XHRs never time out client-side; a stalled request appears as an indefinite mask/spinner. The first SSE event must arrive within 5 s or the client refuses to initialize (unless STIGMAN_CLIENT_STATE_EVENTS=false). Server-side, in-flight requests whose client disconnects are logged with clientTerminated=true. | confirmed | denial of service via hung connections (SC-5); audit records for client-terminated requests carry status undefined | `client/src/js/stigman.js:1`, `client/src/js/workers/state-worker.js:67-74`, `api/source/utils/config.js:46`, `api/source/utils/logger.js:160-171` |
| FM-15 | DEP-04 STIG Manager API (REST, /op/state, SSE /op/state/sse, WebSocket /socket/log-socket) | Intermittent | Each XHR is fire-once; requestPromise rejects with ExtRequestError and the caller shows an error dialog. Bulk import issues one POST per asset sequentially with no retry or idempotency key; a mid-batch failure leaves earlier assets committed and later assets processed, with only the UI status grid recording which failed. Review PATCH/POST are individually transactional server-side. SSE auto-reconnects every 3 s. | confirmed | partial-import data-integrity risk; error dialogs include the server response body (which for 500s includes a stack trace) | `client/src/js/overrides.js:272-300`, `client/src/js/SM/ReviewsImport.js:2394-2428`, `client/src/js/SM/ReviewsImport.js:2466-2484`, `client/src/js/SM/Error.js:17-35`, `api/source/bootstrap/errorHandlers.js:20-21`, `client/src/js/workers/state-worker.js:12` |
| FM-16 | DEP-04 STIG Manager API (REST, /op/state, SSE /op/state/sse, WebSocket /socket/log-socket) | Limited | CKL/CKLB/XCCDF files are parsed in the browser and only JSON review arrays are POSTed, which reduces payload size. However, no HTTP response compression middleware is registered (the 'compression' package is declared but not wired), JSON bodies up to 31457280 bytes and multipart uploads up to 1073741824 bytes are accepted, and uploads are buffered entirely in API memory. Large exports are unpaginated. | confirmed | memory exhaustion on slow large uploads (SC-5); long transfer windows increase exposure to mid-transfer disconnects (FM-15) | `client/src/js/SM/ReviewsImport.js:2241`, `client/src/js/SM/ReviewsImport.js:2259`, `client/src/js/SM/ReviewsImport.js:2277`, `api/source/package.json:20`, `api/source/bootstrap/middlewares.js:22-31`, `api/source/bootstrap/middlewares.js:42-51`, `api/source/utils/config.js:61-62` |
| FM-17 | DEP-05 Reverse proxy / ingress controller (optional; required for mTLS/CAC) | Denied | Equivalent to FM-13 from the browser's perspective. If the proxy is up but the API is down, the proxy returns 502/504; the state worker treats these as errors and retries every 3 s. | confirmed | availability loss; proxy error pages may disclose proxy software/version (site-dependent, inferred) | `client/src/js/workers/state-worker.js:9`, `client/src/js/workers/state-worker.js:117-124` |
| FM-18 | DEP-05 Reverse proxy / ingress controller (optional; required for mTLS/CAC) | Degraded | Proxy response buffering delays the first SSE event beyond the 5 s client budget and the client refuses to initialize with a diagnostic message; the API sets X-Accel-Buffering: no to prevent this on nginx. Proxy idle timeouts shorter than the 30 s SSE keep-alive or 30 s WebSocket ping drop long-lived connections repeatedly. | confirmed | availability loss at application load; operators may be tempted to disable state events (STIGMAN_CLIENT_STATE_EVENTS=false), removing the user-facing dependency-status warning | `client/src/js/workers/state-worker.js:67-74`, `api/source/controllers/Operation.js:131`, `api/source/controllers/Operation.js:149-152`, `api/source/utils/logSocket.js:23`, `docs/installation-and-setup/reverse-proxy.rst:80-88`, `docs/installation-and-setup/reverse-proxy.rst:182-185` |
| FM-19 | DEP-05 Reverse proxy / ingress controller (optional; required for mTLS/CAC) | Intermittent | SSE and WebSocket sessions are re-established by the client (SSE every 3 s; WebSocket per the log-stream client). REST XHRs are not retried. TLS session resumption and connection reuse are proxy-dependent. | confirmed for client behavior | same as FM-15; no session-fixation risk: bearer tokens are re-sent per request, no proxy-side session cookie is used | `client/src/js/workers/state-worker.js:110-125`, `client/src/js/SM/Ajax.js:195` |
| FM-20 | DEP-05 Reverse proxy / ingress controller (optional; required for mTLS/CAC) | Limited | Proxy body-size limits (e.g., nginx client_max_body_size) reject large imports before they reach the API; the documentation recommends 100 MB. Without proxy-level compression, unpaginated JSON responses consume the constrained link. | confirmed (documentation) | availability loss for large imports; misleading client errors (proxy HTML error page fails JSON parsing -> NonJsonResponse) | `docs/installation-and-setup/reverse-proxy.rst:56-60`, `client/src/js/overrides.js:301-309` |
| FM-21 | DEP-06 npm registry / package sources (build time; runtime only if launched via npm start) | Denied | Image builds (npm ci) and client builds (uglify-js, client modules) fail without registry access. A deployment that launches the API with `npm start` fails at `prestart` (npm install) even though node_modules is already present, unless npm resolves everything from local cache. The container CMD (node index.js) is unaffected. | confirmed | inability to rebuild/patch in a disconnected enclave (CP-10, SR-3); temptation to disable integrity checks or use unvetted mirrors | `Dockerfile:32`, `Dockerfile:55`, `api/source/package.json:7`, `client/build.sh:5-6` |
| FM-22 | DEP-06 npm registry / package sources (build time; runtime only if launched via npm start) | Degraded | Slow registry access lengthens builds; npm's own retry/backoff applies (inferred: npm defaults). No runtime impact for the container image. | inferred | none at runtime | `Dockerfile:32` |
| FM-23 | DEP-06 npm registry / package sources (build time; runtime only if launched via npm start) | Intermittent | Partial installs are prevented by lockfile-driven `npm ci` (it fails rather than installs a subset). `npm install` in `prestart` could resolve floating ranges differently across attempts. | confirmed for npm ci semantics; inferred for prestart drift | supply-chain drift if prestart install is used in production (SR-3, CM-6) | `Dockerfile:32`, `api/source/package.json:7` |
| FM-24 | DEP-06 npm registry / package sources (build time; runtime only if launched via npm start) | Limited | Build-time only; large dependency trees (api/source/package-lock.json) transfer slowly. No runtime impact. | confirmed | none at runtime | `api/source/package.json:15`, `Dockerfile:32` |
| FM-25 | DEP-07 Object storage / other outbound HTTP - none present | Denied | Not applicable: there is no object store to lose. All persistent data resides in MySQL (DEP-02). Uploaded files are transient in-process buffers. | confirmed | none | `api/source/bootstrap/middlewares.js:43` |
| FM-26 | DEP-07 Object storage / other outbound HTTP - none present | Degraded | Not applicable (no external storage round trips). | confirmed | none | `api/source/bootstrap/middlewares.js:43` |
| FM-27 | DEP-07 Object storage / other outbound HTTP - none present | Intermittent | Not applicable. A multipart upload interrupted mid-transfer is discarded by multer; nothing partial is persisted. | confirmed | none | `api/source/bootstrap/middlewares.js:42-51` |
| FM-28 | DEP-07 Object storage / other outbound HTTP - none present | Limited | Because uploads are held in memory rather than streamed to storage, a slow upload keeps up to STIGMAN_API_MAX_UPLOAD (default 1 GiB) of process memory committed for the duration of the transfer; concurrent slow uploads multiply this. | confirmed | memory exhaustion / DoS (SC-5) | `api/source/bootstrap/middlewares.js:43-48`, `api/source/utils/config.js:62` |
| FM-29 | DEP-08 Container health probe -> API (loopback) | Denied | When MySQL or the OIDC provider is unreachable the API is 'unavailable' and /api/op/definition returns 503; the probe exits 1. An orchestrator configured to restart on probe failure will restart the API in a loop for the duration of the dependency outage, each restart re-running the 24x5 s bootstrap and ultimately exiting 1. | confirmed for probe semantics; orchestrator restart behavior is deployment-dependent (inferred) | prolonged availability loss and restart churn (CP-10); loss of in-memory JWKS cache and request statistics on every restart; log volume amplification | `api/source/healthcheck.js:6`, `api/source/healthcheck.js:12-17`, `api/source/bootstrap/middlewares.js:64-66`, `api/source/utils/auth.js:278-287`, `api/source/utils/state.js:180-184` |
| FM-30 | DEP-08 Container health probe -> API (loopback) | Degraded | The probe has a 2 s timeout; if the API event loop is saturated by slow DB work (FM-06) the probe times out and exits 1, so a degraded-but-functional API may be restarted. | confirmed | false-negative liveness -> restart during load (CP-10, SC-5) | `api/source/healthcheck.js:7`, `api/source/healthcheck.js:20-23` |
| FM-31 | DEP-08 Container health probe -> API (loopback) | Intermittent | Probe results flap with dependency state; orchestrator failure thresholds determine whether a restart is triggered (deployment-dependent). | inferred | restart churn | `api/source/healthcheck.js:12-17` |
| FM-32 | DEP-08 Container health probe -> API (loopback) | Limited | Loopback probe is unaffected by external bandwidth. | confirmed | none | `api/source/healthcheck.js:4` |
<!-- END GENERATED: failure-modes -->

### 4.1 Cross-cutting observations

- **No auth-bypass path was found under any condition.** Signing keys are never trusted unless fetched from the JWKS endpoint; unknown key IDs are cached as `unknown` and rejected (`api/source/utils/auth.js:59-68`); stale caches clear known keys and fail closed (`api/source/utils/jwksCache.js:63-74`, `api/source/utils/auth.js:209-215`). The WebSocket log stream performs the same verification (`api/source/utils/logSocket.js:171-173`) and requires the `admin` privilege (`api/source/utils/logSocket.js:174-177`).
- **The dominant D-DIL weakness is the absence of timeouts and retries**: the client XHR timeout is 30,000,000 ms (`client/src/js/stigman.js:1`), the MySQL pool sets no connect/query/acquire timeout (`api/source/service/utils.js:163-183`), the startup discovery `fetch` sets no timeout (`api/source/utils/auth.js:253`), and a single failed token refresh ends the session (`client/src/js/workers/oidc-worker.js:565-571`). Degraded links therefore present to users as hangs or forced re-authentication rather than bounded, retryable errors.
- **Information disclosure on the failure path**: the generic error handler attaches `err.stack` for status 500 and untyped errors (`api/source/bootstrap/errorHandlers.js:21`), which is precisely the class of error produced by DB connection loss; the client displays the response text in its error dialog (`client/src/js/SM/Error.js:23`, `client/src/js/overrides.js:284-290`).
- **Batch-level integrity**: individual writes are transactional with deadlock retry (`api/source/service/ReviewService.js:503`, `api/source/service/utils.js:619-649`), but the multi-asset import loop is not (`client/src/js/SM/ReviewsImport.js:2394-2428`), so intermittent loss yields partially applied batches whose only record is the transient UI status grid.

## 5. Authentication and session analysis under D-DIL

| Aspect | Behavior at the assessed commit | Confidence | Evidence |
| --- | --- | --- | --- |
| Token model | Authorization Code + PKCE (S256) in the browser; API is an OAuth2 resource server validating `Authorization: Bearer` JWTs. | confirmed | `client/src/js/workers/oidc-worker.js:267`, `client/src/js/workers/oidc-worker.js:48-76`, `api/source/utils/auth.js:84-100`, `api/source/utils/auth.js:187-192`, `docs/installation-and-setup/authentication.rst:137` |
| Token lifetime | Determined entirely by the IdP (`exp` claim). The API enforces `exp` via `jsonwebtoken.verify`. The client schedules refresh at `exp - 10 s` and treats a token with `timeoutInS <= 0` as absent. Documentation suggests a 10-minute IdP session idle. | confirmed | `api/source/utils/auth.js:74-81`, `client/src/js/workers/oidc-worker.js:334-346`, `client/src/js/workers/oidc-worker.js:364-369`, `docs/installation-and-setup/authentication.rst:210-212` |
| Refresh behavior | Timer-driven single attempt against the IdP `token_endpoint` with `grant_type=refresh_token`; on any error the access and refresh tokens are cleared and `noToken` is broadcast, producing the "Credentials Expired" modal. No retry, no backoff, no jitter. When the refresh token expires first, tokens are cleared at that instant. | confirmed | `client/src/js/workers/oidc-worker.js:313-322`, `client/src/js/workers/oidc-worker.js:555-572`, `client/src/js/workers/oidc-worker.js:324-332`, `client/src/js/stigman.js:284-303`, `client/src/js/stigman.js:380-389` |
| Idle timeout | `STIGMAN_CLIENT_USER_TIMEOUT` / `STIGMAN_CLIENT_ADMIN_TIMEOUT` (default 0 = disabled) clear tokens after inactivity and suppress refresh while idle. | confirmed | `api/source/utils/config.js:27-36`, `client/src/js/workers/oidc-worker.js:574-587`, `client/src/js/workers/oidc-worker.js:528-531` |
| JWKS caching and rotation | In-memory cache; refresh scheduled at `cacheMaxAge/2`; stale timer at `cacheMaxAge` clears known keys and marks OIDC unavailable; failed scheduled refreshes retry every 10 s; unknown `kid` triggers one synchronous refresh (10 s socket timeout) and is then cached as `unknown`. `STIGMAN_JWKS_CACHE_MAX_AGE` default 10 min, clamped to 1-35791 min. | confirmed | `api/source/utils/jwksCache.js:14-15`, `api/source/utils/jwksCache.js:45-57`, `api/source/utils/jwksCache.js:63-74`, `api/source/utils/jwksCache.js:85`, `api/source/utils/auth.js:51-71`, `api/source/utils/auth.js:200-215`, `api/source/utils/config.js:100` |
| Clock-skew tolerance | None configured: `jwt.verify` is called without `clockTolerance`, so `exp`/`nbf` are enforced with 0 s tolerance (inferred: library default). The WebSocket log session and the client compute expiry from local time. | confirmed (call site); inferred (default) | `api/source/utils/auth.js:75-77`, `api/source/utils/logSocket.js:197-207`, `client/src/js/workers/oidc-worker.js:340-346` |
| IdP unreachable mid-session (API) | Existing tokens with cached `kid` continue to verify until the stale timer fires (default 10 min after the last successful refresh), then all `/api` requests receive 503 until a refresh succeeds. Recovery is automatic. | confirmed | `api/source/utils/jwksCache.js:50-54`, `api/source/utils/auth.js:209-215`, `api/source/bootstrap/middlewares.js:61-76` |
| IdP unreachable mid-session (client) | The session survives until the access-token timer fires; the refresh then fails and the user is forced to re-authenticate. Because XHRs are not sent while no token is held, the UI appears to stall for actions attempted in that window. | confirmed | `client/src/js/workers/oidc-worker.js:315-320`, `client/src/js/workers/oidc-worker.js:568-571`, `client/src/js/SM/Ajax.js:192` |
| Offline / cached-credential path | **None exists.** Tokens are never persisted (SharedWorker memory only); PKCE verifier and OIDC state are placed in `localStorage` only for the duration of a re-authentication round trip. Server-side, `lastClaims`/`lastAccess` are stored in MySQL for audit, not for authentication. | confirmed | `client/src/js/workers/oidc-worker.js:4-7`, `client/src/js/stigman.js:333-336`, `api/source/utils/auth.js:128-139`, `api/source/service/UserService.js:345-353` |
| Should an offline path exist? | The assessment recommends **no** cached credentials in the browser client. The fail-closed behavior is correct for a bearer-token architecture. Where disconnected operation is required, the appropriate control is an enclave-local IdP (REC-11, GOV-01) combined with a mission-approved JWKS staleness window (REC-03, GOV-04) and refresh retry (REC-02). | assessment position | see recommendations |

## 6. Audit-log continuity analysis

| Question | Finding | Evidence |
| --- | --- | --- |
| What is logged? | Structured JSON records `{date, level, component, type, data}`. In the default `STIGMAN_LOG_MODE=combined` a single `transaction` record per request contains the request (method, URL, source IP, headers with `authorization` replaced by a boolean, **decoded access-token payload**, and the body when `elevate=true` or `STIGMAN_LOG_LEVEL=4`) and the response (status, headers, error body, response body for elevated requests). State transitions, dependency retries, JWKS events, and unexpected errors are logged by component. | `api/source/utils/logger.js:44-49`, `api/source/utils/logger.js:62-94`, `api/source/utils/logger.js:159-171`, `api/source/utils/config.js:113-117`, `docs/installation-and-setup/logging.rst:8-9` |
| Where? | `console.log` to **stdout only**. There is no file, database, or remote appender in the application; the documentation directs operators to capture stdout. Records are also fanned out in-process to an `EventEmitter` consumed by the admin WebSocket log stream. | `api/source/utils/logger.js:11`, `api/source/utils/logger.js:48-49`, `docs/installation-and-setup/logging.rst:8-9`, `api/source/utils/logSocket.js:9` |
| Synchronous or buffered? | Writes are synchronous calls to `console.log` at the time of the event. Node's stdout is synchronous for files and TTYs and asynchronous for pipes (inferred: platform behavior), so a container runtime capturing stdout through a pipe may lose the final records on a crash. The application maintains no buffer of its own and drops nothing intentionally. | `api/source/utils/logger.js:44-49` |
| When is a request logged? | In `combined` mode, only when the response finishes or the socket closes (`on-finished`). A client disconnect still produces a record (`clientTerminated: true`, `status: undefined`); a process crash mid-request produces none. | `api/source/utils/logger.js:185-190`, `api/source/utils/logger.js:164-165` |
| Business audit trail | Review history rows are written inside the same MySQL transaction as the review change, so they are either both committed or both rolled back. The `lastAccess`/`lastClaims` user record is refreshed at most once per `lastAccessResolution` (60 s) or on a new `jti`. | `api/source/service/ReviewService.js:503`, `api/source/service/ReviewService.js:535`, `api/source/utils/auth.js:128-139`, `api/source/utils/config.js:16` |
| Loss under **MySQL** outage | Request/transaction records continue to stdout (as 503/500 outcomes), so the *attempt* is auditable. No business change and no review-history row can be written, and `lastAccess`/`lastClaims` updates fail with the request. No queue or replay exists. | `api/source/bootstrap/middlewares.js:61-76`, `api/source/utils/auth.js:135`, `api/source/utils/PoolMonitor.js:31-38` |
| Loss under **network** outage to the log collector | Entirely dependent on the deployment's stdout capture. The application cannot detect or alert on collector loss (no AU-5 mechanism). In-memory request statistics are lost on every process exit or restart. | `api/source/utils/logger.js:44-49`, `api/source/utils/logger.js:136-139`, `api/source/utils/state.js:180-184` |
| Loss under **restart loops** | Each restart caused by a failing health probe during a dependency outage re-emits bootstrap logging and discards in-memory state; the probe path is gated by the 503 check. | `api/source/healthcheck.js:6`, `api/source/healthcheck.js:12-17`, `api/source/bootstrap/middlewares.js:64-66` |

## 7. Ranked engineering recommendations

Owner "Government decision" indicates the item cannot be closed by engineering alone; the corresponding decision items are in Section 9.

<!-- BEGIN GENERATED: recommendations -->
| Rank | ID | Recommendation | D-DIL condition addressed | NIST SP 800-53 Rev. 5 controls | Effort | Owner | Addresses | Evidence (file:line) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | REC-01 | **Bound client request time and fail fast when no token is held.** Replace the global Ext.Ajax.timeout of 30,000,000 ms with a bounded default (for example 60 s, with explicit longer per-request timeouts for exports/imports), surface an explicit error when Ajax.js declines to send because window.oidcWorker.token is null (today the request silently never fires), and add bounded retry with jittered backoff for idempotent GETs. | Degraded; Intermittent | SC-5; SI-11; AC-12 | S | Engineering | FM-14; FM-09; FM-15 | `client/src/js/stigman.js:1`, `client/src/js/SM/Ajax.js:192`, `client/src/js/SM/Ajax.js:179-185` |
| 2 | REC-02 | **Make token refresh tolerant of transient IdP loss.** In the OIDC SharedWorker, start the refresh earlier than 10 s before exp (configurable, e.g., 25% of lifetime), retry a failed refresh with backoff while the refresh token is still valid, and only clear tokens and broadcast 'noToken' when the refresh token itself has expired or the IdP returns a definitive 4xx. Keep the current fail-closed behavior at refresh-token expiry. | Degraded; Intermittent | IA-5; SC-23; AC-12 | M | Engineering | FM-10; FM-11 | `client/src/js/workers/oidc-worker.js:334`, `client/src/js/workers/oidc-worker.js:555-572`, `client/src/js/workers/oidc-worker.js:324-332` |
| 3 | REC-03 | **Define the IdP-unreachable policy for the API (JWKS staleness window).** Decide and document how long the API may keep verifying tokens with last-known JWKS keys when the IdP is unreachable. Today this is STIGMAN_JWKS_CACHE_MAX_AGE (default 10 min, max 35791 min), after which the API fails closed with 503. For enclave deployments, set the value to the mission-approved window, and consider an engineering change that distinguishes 'refresh failed' from 'keys expired' so that revocation latency and availability can be tuned independently. | Denied; Intermittent | IA-5; SC-23; CP-10 | M | Government decision (policy) + Engineering (implementation) | FM-01; FM-03 | `api/source/utils/config.js:100`, `api/source/utils/jwksCache.js:14-15`, `api/source/utils/auth.js:209-215` |
| 4 | REC-04 | **Provide a durable audit-log path independent of network log shipping.** Logging is synchronous JSON to stdout with no local buffer or file. Deploy a local log sink (file with rotation, or a sidecar/agent with disk-backed buffering) so audit records survive loss of the network path to the central collector, and configure the orchestrator not to drop container stdout during collector outages. Add an AU-5-style alert when the sink is unavailable. Document the accepted maximum audit gap. | Denied; Intermittent | AU-4; AU-5; AU-9; AU-12 | M | Engineering (deployment) + Government decision (acceptable gap) | FM-05; FM-13 | `api/source/utils/logger.js:44-57`, `api/source/utils/logger.js:185-190`, `docs/installation-and-setup/logging.rst:8-9` |
| 5 | REC-05 | **Remove stack traces and token payloads from failure-path outputs.** The generic error handler includes err.stack in 500 and untyped error responses, which under DB/network faults are the common path; the client then renders that body in an error dialog. Return a correlation id (requestId already exists) instead of the stack, and keep the stack in the server log only. In the default 'combined' log mode the decoded access-token payload is attached to every request log; the OIDC worker also console-logs full token responses. Restrict both to a debug level. | Denied; Degraded; Intermittent | SI-11; AU-9; IA-5 | S | Engineering | FM-05; FM-07; FM-15 | `api/source/bootstrap/errorHandlers.js:21`, `api/source/utils/logger.js:81-83`, `api/source/utils/logger.js:107`, `client/src/js/workers/oidc-worker.js:542`, `client/src/js/SM/Error.js:17-35` |
| 6 | REC-06 | **Add MySQL connect/query/acquire timeouts and error-driven unavailability.** Set connectTimeout, a per-query timeout, and a bounded queueLimit/acquire timeout in the pool config so degraded DB links fail fast. Additionally mark db unavailable (or emit a degraded state) on sustained query errors rather than only when the pool becomes empty, so the SSE state stream warns users before requests hang. | Degraded; Intermittent | SC-5; CP-10; SI-11 | M | Engineering | FM-06; FM-07; FM-08 | `api/source/service/utils.js:163-183`, `api/source/utils/PoolMonitor.js:31-38` |
| 7 | REC-07 | **Make bulk import resumable and idempotent.** The import loop issues one asset PATCH/POST and one review POST per asset with no retry; a mid-batch fault yields a partially applied batch. Add per-asset retry with backoff for network-class failures, an exportable 'not applied' manifest at the end of the run, and (server-side) an optional import-batch identifier recorded in review history so partial batches are auditable and re-runnable. | Intermittent; Limited | SI-7; CP-10; AU-12 | M | Engineering | FM-07; FM-15; FM-16 | `client/src/js/SM/ReviewsImport.js:2394-2428`, `client/src/js/SM/ReviewsImport.js:2498-2504`, `api/source/service/ReviewService.js:503` |
| 8 | REC-08 | **Separate liveness from readiness in the container health probe.** healthcheck.js requests /api/op/definition, which is gated by the 503 service check, so any dependency outage makes the container 'unhealthy' and invites restart loops. Point the liveness probe at /api/op/state (always served) and use the 'available' state only for readiness/traffic routing. | Denied; Intermittent | CP-10; SC-5 | S | Engineering | FM-29; FM-30; FM-31 | `api/source/healthcheck.js:6`, `api/source/bootstrap/middlewares.js:64-66`, `api/source/controllers/Operation.js:115-122` |
| 9 | REC-09 | **Publish a D-DIL reverse-proxy profile.** Codify the proxy settings the client depends on (no buffering for /op/state/sse and NDJSON endpoints, read/idle timeouts above the 30 s keep-alive, WebSocket upgrade, body size at least the expected import size, and passing 503 JSON bodies through unmodified) as a tested configuration fragment, and state that STIGMAN_CLIENT_STATE_EVENTS=false is a diagnostic setting, not a D-DIL mitigation. | Degraded; Limited | SC-8; SC-5; CM-6 | S | Engineering | FM-18; FM-20 | `docs/installation-and-setup/reverse-proxy.rst:136-140`, `docs/installation-and-setup/reverse-proxy.rst:182-185`, `api/source/controllers/Operation.js:149-152` |
| 10 | REC-10 | **Set an explicit JWT clock-skew tolerance.** jwt.verify is called without clockTolerance, so exp/nbf are enforced with zero tolerance; the WebSocket log session likewise computes expiry from local time. Edge nodes with drifting clocks (common when NTP is unreachable) will reject valid tokens or accept them slightly late. Add a configurable clockTolerance (e.g., 30-60 s) and document the NTP requirement. | Denied; Degraded | IA-5; AU-8; SC-45 | S | Engineering + Government decision (tolerance value) | FM-01; FM-09 | `api/source/utils/auth.js:74-81`, `api/source/utils/logSocket.js:197-207`, `client/src/js/workers/oidc-worker.js:340-346` |
| 11 | REC-11 | **Decide the offline-authentication posture (no cached-credential path exists).** Neither the client nor the API has an offline or cached-credential path; both fail closed when the IdP is unreachable. The assessment recommends against adding cached credentials to the browser client. If disconnected operation is a mission requirement, deploy an IdP instance inside the enclave (with key material and user federation synchronized when connected) and point STIGMAN_OIDC_PROVIDER / STIGMAN_CLIENT_OIDC_PROVIDER at it. | Denied | IA-2; IA-5; AC-14; CP-10 | L | Government decision | FM-01; FM-09 | `client/src/js/workers/oidc-worker.js:4-7`, `api/source/utils/auth.js:51-71`, `api/source/utils/config.js:37`, `api/source/utils/config.js:95` |
| 12 | REC-12 | **Enable response compression and cap unbounded payloads.** The 'compression' package is a declared dependency but no compression middleware is registered. Enable it for JSON responses, and review STIGMAN_API_MAX_JSON_BODY (default 31457280 bytes) and STIGMAN_API_MAX_UPLOAD (default 1073741824 bytes, held in memory) against the bandwidth and memory actually available at the edge. | Limited | SC-5; CM-6 | S | Engineering | FM-16; FM-28; FM-08 | `api/source/package.json:20`, `api/source/bootstrap/middlewares.js:22-31`, `api/source/utils/config.js:61-62` |
| 13 | REC-13 | **Remove registry access from the runtime start path and document offline builds.** The `prestart` script runs `npm install`, so `npm start` needs registry access; the container CMD does not. Document `node index.js` (or `npm start --ignore-scripts`) for disconnected hosts, and document an offline build procedure (private registry mirror or vendored lockfile with `npm ci --offline`) with integrity verification. | Denied | SR-3; CM-6; CP-10 | S | Engineering | FM-21; FM-23 | `api/source/package.json:7-8`, `Dockerfile:32`, `Dockerfile:55` |
| 14 | REC-14 | **Reconcile documented defaults with code.** The environment-variable reference documents STIGMAN_API_MAX_JSON_BODY default 5242880 while config.js uses 31457280. Reconcile so operators sizing proxies and links for D-DIL use the real value. | Limited | CM-6 | S | Engineering | FM-16; FM-20 | `docs/installation-and-setup/envvars.csv:4`, `api/source/utils/config.js:61` |
<!-- END GENERATED: recommendations -->

## 8. Lab test plan

All tests use local tooling only: `docker compose` (MySQL 8.0.24 or later, an OIDC provider such as Keycloak or the repository's mock at `test/api/mock-keycloak/`, the API image), toxiproxy for per-link latency/timeout/reset toxics, and `tc qdisc ... netem` for delay/loss/rate shaping on container interfaces. The existing `test/state/` suite already exercises the **Denied** case for OIDC and MySQL (stop/restart of each dependency, unknown-kid rejection, and the 24-retry exit path) and can be extended with the cases below; no test in this plan requires infrastructure outside the local host, and none was executed as part of this assessment.

Reference baseline (existing coverage):

- Bootstrap with no dependencies exits with code 1 after retries: `test/state/mocha/bootstrap.test.js:47-55`.
- OIDC down / restarted / re-keyed: `test/state/mocha/oidc.test.js:69-95`, `test/state/mocha/oidc.test.js:97-135`.
- DB shutdown and host-down: `test/state/mocha/db.test.js:58-80`, `test/state/mocha/db.test.js:155-180`.
- Unknown `kid` handling while OIDC is unavailable: `test/state/mocha/jwks.test.js:136-165`.

No existing test covers Degraded (latency/loss), Intermittent (flapping), or Limited-bandwidth conditions, client-side timeout/refresh behavior, or audit-log continuity.

<!-- BEGIN GENERATED: lab-plan -->
#### LAB-01 - verifies REC-01 (Bound client request time and fail fast when no token is held)

- **Tooling:** docker compose + toxiproxy (browser->API)
- **Setup:** Compose: mysql:8.0.24, keycloak (or test/api/mock-keycloak), stig-manager API, toxiproxy in front of the API port. Browser points at the toxiproxy listener.
- **Steps:**
   1. Log in; open a collection.
   2. Add toxic `timeout` (timeout=0) on the API proxy to black-hole responses.
   3. Trigger a GET (e.g., open Assets grid) and observe the UI for 120 s.
   4. Remove toxic; clear the token via IdP session logout and trigger a GET.
- **Pass:** The request fails with a user-visible timeout error within the configured bound (<= 60 s default); the no-token case shows an explicit error instead of a silent no-op.
- **Fail:** Spinner/mask persists beyond the bound, or no error is shown when no token is held.

#### LAB-02 - verifies REC-02 (Make token refresh tolerant of transient IdP loss)

- **Tooling:** docker compose + toxiproxy (browser->IdP)
- **Setup:** Keycloak access-token lifespan 2 min, refresh 30 min. toxiproxy in front of Keycloak.
- **Steps:**
   1. Log in and wait until 20 s before access-token exp.
   2. Add toxic `timeout` on the IdP proxy for 40 s, then remove it.
   3. Observe the OIDC worker and UI.
- **Pass:** Refresh is retried and succeeds after the toxic is removed; no 'Credentials Expired' modal while the refresh token remains valid.
- **Fail:** Tokens are cleared and re-authentication is demanded after the first failed refresh.

#### LAB-03 - verifies REC-03 (Define the IdP-unreachable policy for the API (JWKS staleness window))

- **Tooling:** docker compose + `docker stop` on the IdP; existing test/state harness pattern
- **Setup:** STIGMAN_JWKS_CACHE_MAX_AGE set to the approved window (e.g., 60).
- **Steps:**
   1. Obtain a token; stop the IdP container.
   2. Call an authenticated endpoint every 30 s and record the first 503.
   3. Restart the IdP and record time to 'available'.
- **Pass:** 503 begins only after the approved window elapses; recovery occurs within one refresh interval (<= 10 s retry) after the IdP returns; tokens with unknown kids are rejected throughout.
- **Fail:** 503 occurs earlier than the window, recovery requires an API restart, or any unknown-kid token is accepted.

#### LAB-04 - verifies REC-04 (Provide a durable audit-log path independent of network log shipping)

- **Tooling:** docker compose + log agent with disk buffer + `tc qdisc add dev <agent-if> root netem loss 100%`
- **Setup:** API stdout captured by a file-backed agent (e.g., a json-file driver plus a shipping agent) that forwards to a collector container.
- **Steps:**
   1. Generate 100 authenticated requests.
   2. Apply 100% loss between agent and collector for 5 min while generating 100 more requests.
   3. Remove the impairment and wait for drain.
- **Pass:** All 200 transaction records (matched by requestId) arrive at the collector; an alert is raised during the outage.
- **Fail:** Any requestId is missing at the collector, or no alert fires.

#### LAB-05 - verifies REC-05 (Remove stack traces and token payloads from failure-path outputs)

- **Tooling:** docker compose + `docker stop` on MySQL
- **Setup:** Default STIGMAN_LOG_MODE (combined).
- **Steps:**
   1. Stop MySQL while a review PATCH is in flight (or immediately before).
   2. Capture the HTTP response body and the browser error dialog.
   3. Inspect API stdout for the request record.
- **Pass:** Response body contains an error message and correlation id but no stack frames; stdout request records do not contain decoded token claims at the default log level.
- **Fail:** Response body or dialog shows a stack trace, or token claims appear in default-level logs.

#### LAB-06 - verifies REC-06 (Add MySQL connect/query/acquire timeouts and error-driven unavailability)

- **Tooling:** docker compose + toxiproxy (API->MySQL) with `latency` and `timeout` toxics
- **Setup:** toxiproxy between the API and MySQL; STIGMAN_DB_MAX_CONNECTIONS=5 to make exhaustion observable.
- **Steps:**
   1. Add `latency` 8000 ms on the DB proxy.
   2. Issue 10 concurrent GET /api/collections requests.
   3. Add `timeout` (timeout=0) and repeat with 5 requests; watch /api/op/state/sse.
- **Pass:** Requests fail within the configured query/acquire timeout with a 503/504-class error; the SSE stream reports db degraded/unavailable before the 20 s pool-empty restore cycle.
- **Fail:** Requests hang beyond the timeout, or state stays 'available' while all requests are failing.

#### LAB-07 - verifies REC-07 (Make bulk import resumable and idempotent)

- **Tooling:** docker compose + toxiproxy (browser->API) `limit_data` or `reset_peer` toxic
- **Setup:** Prepare a CKL import of 20 assets.
- **Steps:**
   1. Start the import.
   2. After ~10 assets, add a `reset_peer` toxic for 15 s, then remove it.
   3. Let the import finish and export the result manifest.
   4. Re-run the import with the same files.
- **Pass:** Failed assets are retried automatically or listed in a manifest; the re-run applies only the missing assets; review history shows a consistent batch identifier.
- **Fail:** Failed assets are silently skipped with no machine-readable manifest, or the re-run duplicates history entries without a batch marker.

#### LAB-08 - verifies REC-08 (Separate liveness from readiness in the container health probe)

- **Tooling:** docker compose with `healthcheck` stanza + `docker stop` on MySQL
- **Setup:** Compose healthcheck: `node healthcheck.js`, interval 10 s, retries 3; restart: on-failure.
- **Steps:**
   1. Stop MySQL for 5 min.
   2. Record API container restart count and `docker inspect` health status.
- **Pass:** Liveness stays healthy (no restarts); readiness/state reports 'unavailable'; API returns to 'available' within one restore interval (20 s) after MySQL returns.
- **Fail:** The API container restarts during the outage.

#### LAB-09 - verifies REC-09 (Publish a D-DIL reverse-proxy profile)

- **Tooling:** docker compose + nginx with the published D-DIL profile + `tc netem delay 800ms`
- **Setup:** nginx in front of the API using the profile fragment.
- **Steps:**
   1. `curl -N https://<proxy>/api/op/state/sse` and time the first event.
   2. Hold the SSE connection for 5 min under 800 ms delay.
   3. Upload a 50 MB CKL bundle.
- **Pass:** First SSE event within 2 s; the connection survives 5 min with keep-alives every 30 s; the upload is accepted.
- **Fail:** First event later than 5 s (client refuses to initialize), connection drops before 5 min, or upload rejected by the proxy.

#### LAB-10 - verifies REC-10 (Set an explicit JWT clock-skew tolerance)

- **Tooling:** docker compose + `faketime`/`date -s` inside the API container (or libfaketime)
- **Setup:** IdP clock correct; API clock skewed +45 s and then -45 s.
- **Steps:**
   1. Skew the API clock +45 s; call an endpoint with a freshly issued 5-min token.
   2. Skew -45 s; call with a token 30 s past exp.
- **Pass:** With the configured tolerance (e.g., 60 s) the fresh token is accepted under +45 s skew; a token more than tolerance past exp is rejected.
- **Fail:** Fresh tokens rejected due to skew inside tolerance, or expired tokens beyond tolerance accepted.

#### LAB-11 - verifies REC-11 (Decide the offline-authentication posture (no cached-credential path exists))

- **Tooling:** docker compose with an enclave-local Keycloak + `docker network disconnect` for the upstream federation link
- **Setup:** Enclave Keycloak configured as the STIG Manager OIDC provider; upstream IdP federated for user sync.
- **Steps:**
   1. Disconnect the upstream link.
   2. Log in with a previously synchronized user; work for 30 min including token refreshes.
   3. Reconnect and verify audit/sync.
- **Pass:** Login and refresh succeed against the local IdP throughout; no cached credentials exist in the browser (SharedWorker memory only); reconnection does not duplicate users.
- **Fail:** Login requires the upstream IdP, or any credential material is persisted in browser storage.

#### LAB-12 - verifies REC-12 (Enable response compression and cap unbounded payloads)

- **Tooling:** docker compose + `tc netem rate 256kbit`
- **Setup:** API with compression enabled; a collection with >= 500 assets.
- **Steps:**
   1. Measure transfer size and time for GET /api/collections/{id}/reviews under 256 kbit/s.
   2. Repeat with compression disabled for comparison.
- **Pass:** Compressed transfer is at least 4x smaller than uncompressed JSON and completes within the client request bound.
- **Fail:** Content-Encoding absent, or the request exceeds the client bound.

#### LAB-13 - verifies REC-13 (Remove registry access from the runtime start path and document offline builds)

- **Tooling:** docker build with `--network none` after pre-seeding; `npm start` on a host with registry blocked
- **Setup:** Vendored node_modules or private mirror per the documented offline procedure.
- **Steps:**
   1. Block registry.npmjs.org at the host firewall.
   2. Run the documented start command.
   3. Run the documented offline build.
- **Pass:** API starts without contacting the registry; the build completes from the mirror/vendored lockfile with integrity verification.
- **Fail:** Start or build attempts to reach the registry and fails.

#### LAB-14 - verifies REC-14 (Reconcile documented defaults with code)

- **Tooling:** Repository inspection
- **Setup:** None.
- **Steps:**
   1. Compare each default in docs/installation-and-setup/envvars.csv with api/source/utils/config.js.
- **Pass:** All documented defaults match code.
- **Fail:** Any mismatch remains.
<!-- END GENERATED: lab-plan -->

## 9. Items requiring a Government decision

<!-- BEGIN GENERATED: government-decisions -->
| ID | Topic | Decision required | Related recommendations |
| --- | --- | --- | --- |
| GOV-01 | Offline authentication policy | Whether STIG Manager must operate while the enterprise IdP is unreachable, and if so whether the approved mechanism is an enclave-local IdP (recommended) versus any form of cached credentials in the client (not recommended). | REC-11; REC-03 |
| GOV-02 | Acceptable audit-log gap and buffering | Maximum tolerable loss window for audit/transaction records during a network or collector outage, and whether local disk buffering of logs containing user identifiers is permitted in the deployment enclave. | REC-04 |
| GOV-03 | Token lifetimes and clock tolerance | Approved access/refresh token lifetimes, idle timeout values (STIGMAN_CLIENT_USER_TIMEOUT / STIGMAN_CLIENT_ADMIN_TIMEOUT, default 0 = disabled), and the JWT clock-skew tolerance for edge nodes. | REC-02; REC-10 |
| GOV-04 | JWKS staleness / revocation latency window | How long the API may continue to accept tokens signed with last-known keys after losing the IdP (STIGMAN_JWKS_CACHE_MAX_AGE), balancing availability against revocation latency. | REC-03 |
| GOV-05 | Data synchronization and conflict rules | Whether multiple enclave instances may operate on the same collections and, if so, the authoritative source and conflict rule (last-writer-wins by review timestamp vs. manual reconciliation) for reviews and review history imported after reconnection; and whether partial imports must be rolled back or completed. | REC-07 |
| GOV-06 | Degraded-mode operating posture | Whether a read-only or cached-view mode is desired when MySQL is degraded, or whether the current fail-closed 503 posture is acceptable. | REC-06; REC-08 |
| GOV-07 | Error-detail exposure level | Approved level of diagnostic detail in client-visible errors and in default-level operational logs (stack traces, decoded token claims). | REC-05 |
<!-- END GENERATED: government-decisions -->

## 10. Regenerating and verifying this document

```bash
# regenerate every table and count from ddil-findings.json
python3 docs/assessments/build_ddil_summary.py

# verify the markdown is current without writing
python3 docs/assessments/build_ddil_summary.py --check

# run the consistency and evidence tests
python3 -m pytest docs/assessments/test_ddil_assessment.py -q
```
