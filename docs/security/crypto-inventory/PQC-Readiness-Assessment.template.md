# Cryptographic Inventory and Post-Quantum Cryptography Readiness Assessment

**System:** STIG Manager (API, browser client, database schema, deployment assets in this repository)
**Deliverable:** CDRL A009 — Cryptographic Inventory and PQC Readiness Assessment
**Commit scanned:** `{{COMMIT_SHA}}`
**Generated:** {{GENERATED_UTC}} by `scripts/crypto_inventory.py`
**Companion files:** `Cryptographic-Inventory.xlsx`, `crypto-inventory.json` (same directory)

> NO production cryptographic service is introduced, replaced, disabled, or reconfigured by this work — recommendations only, pending Government authorization.

All counts and tables in this report are generated from `crypto-inventory.json` at render time. They cannot drift from the workbook.

## 1. Executive summary

STIG Manager is a web application that stores STIG evaluation results and POA&M-related data. It does not implement its own encryption of stored data. Its cryptography is concentrated in three places: (1) verification of OIDC access tokens signed by an external identity provider (IdP), (2) TLS for the API listener, the MySQL connection and the IdP connection, and (3) release signing in CI. Everything else is SHA-256 hashing for identifiers and content digests, and CSPRNG use in the browser.

The scanner produced **{{TOTAL_ROWS}} inventory rows** from **{{FILES_SCANNED}} files** using **{{RULE_COUNT}} detection rules**.

{{TABLE_BY_CLASS}}

Key conclusions:

- **Quantum exposure is dominated by signature forgery, not by harvest-now-decrypt-later (HNDL).** The system's only long-lived public-key trust relationships are the IdP's JWS signing key (RSA or ECDSA today) and the release-signing keys (OpenPGP in CI; ECDSA in `root.json`). A cryptographically relevant quantum computer (CRQC) would allow an attacker to forge access tokens or release signatures. It would not retroactively expose stored data, because the application stores nothing encrypted and its data has limited confidentiality life.
- **HNDL exposure exists only at the TLS layer** and only for traffic recorded today: API sessions (bearer tokens, STIG results), MySQL traffic, and IdP traffic. Bearer tokens are short-lived. STIG results are sensitive but are not secret keys; their confidentiality value decays as systems are re-scanned. This is a real but bounded exposure. It is addressed by hybrid key establishment in TLS (Phase 2), which is a deployment-layer change.
- **{{COUNT_SHOR_NONTEST}} Shor-vulnerable rows are outside test code**, all of them in the JWT verification path, CI release signing and the `root.json` trust metadata. {{COUNT_SHOR_TEST}} further rows are test fixtures.
- **{{COUNT_WEAK}} rows are weak regardless of PQC**: RSA-1024 keys and certificates. All are in test fixtures (`test/utils/mockOidc.js`, `test/api/mock-keycloak*`). None are in the deployed system. They should still be replaced because Node.js 24 with OpenSSL 3.5 at security level 2 rejects RSA keys under 2048 bits in TLS, and because they are a poor model of production.
- **The application never selects a signature or key-exchange algorithm itself.** Accepted JWS algorithms follow the key type published by the IdP (`jsonwebtoken` 9.x behavior) and the JWK key-type allowlist `RSA`/`EC`/`OKP` in `api/source/utils/jwksCache.js`. TLS versions and cipher suites are Node.js/OpenSSL defaults; the repository sets none. This makes the system **crypto-agile at the protocol layer but library-bound for signatures**: PQC signatures require (a) the IdP to issue ML-DSA-signed tokens, (b) a JWT library that accepts them, and (c) a one-line change to the JWK key-type filter. None of these exist in released form today.
- **The runtime is a mutable tag.** `Dockerfile` uses `node:lts-alpine` and CI uses `lts/*`. As of the generation date the LTS line is Node.js 24, which ships OpenSSL 3.5 (ML-KEM, ML-DSA and SLH-DSA are implemented in the library). On 2026-10-28 the `lts` tag is scheduled to move to Node.js 26. The Government should decide whether to pin a concrete version before any PQC evaluation, so results are reproducible.

Recommended immediate actions (Phase 0/1, no production change): adopt this inventory as the baseline, pin the evaluation runtime, add explicit TLS policy configuration to the deployment documentation, replace the RSA-1024 test fixtures, and open a tracking item for IdP and `jsonwebtoken` ML-DSA support. Decisions requiring Government approval are listed in Section 10.

## 2. System and boundary description

### 2.1 What the system is

- **API** (`api/source/`): Node.js/Express service. It exposes a REST API and a WebSocket log stream. It authenticates every request with an OIDC bearer token (JWT) verified against the IdP's JWKS (`api/source/utils/auth.js`, `api/source/utils/jwksCache.js`).
- **Client** (`client/src/`): browser application. It performs the OIDC authorization-code flow with PKCE in a web worker (`client/src/js/workers/oidc-worker.js`) and computes SHA-256 digests of uploaded attachments (`client/src/js/SM/Attachments.js`).
- **Database**: MySQL, reached through `mysql2`. TLS to MySQL is optional and enabled by three environment variables (`api/source/service/utils.js`).
- **Identity provider**: external. The API only consumes its discovery document and JWKS. The repository ships a test double under `test/api/mock-keycloak*` and `test/utils/mockOidc.js`.
- **Deployment**: `Dockerfile` (base `node:lts-alpine`), packaged binaries (`api/pkg.config.json`, Node 24 targets), GitHub Actions workflows, and a signed-image trust root (`root.json`).

### 2.2 Data and trust relationships that involve cryptography

| Flow | Direction | Cryptography | Who controls the algorithm |
|---|---|---|---|
| Browser → IdP | login, token refresh | TLS (browser and IdP); PKCE S256 (SHA-256) | Browser, IdP |
| Browser → API | bearer token, REST, WebSocket | TLS if `STIGMAN_API_TLS_*` set, otherwise plaintext to a reverse proxy | Operator (certificate), Node.js defaults (protocol/ciphers) |
| API → IdP | discovery, JWKS fetch | TLS or HTTP depending on `STIGMAN_OIDC_PROVIDER` scheme; optional custom CA | Operator, IdP |
| API (verify) | JWS signature check | RS*/PS*/ES* per key type; RSA/EC/OKP JWKs accepted | IdP (key type), `jsonwebtoken` (algorithm set) |
| API → MySQL | queries | TLS if `STIGMAN_DB_TLS_*` set; `mysql2` over Node `tls` | Operator, MySQL server, Node.js defaults |
| CI → release | artifact signing | OpenPGP detached signatures with `STIGMAN_PRIVATE_KEY` | CI secret owner (key algorithm not visible in repo) |
| Image consumers | image trust | ECDSA P-256 keys in `root.json` | Repository maintainers, registry Notary service |

### 2.3 Scope

Scanned: every text file under the repository at commit `{{COMMIT_SHA}}` except the exclusions below, plus `package.json`/`package-lock.json` for versions and JWKS/PEM material for certificate parsing.

Not scanned or out of scope:

- `node_modules`, `dist`, `client/src/ext` (vendored ExtJS), minified bundles.
- XCCDF/CKL STIG content fixtures (`test/api/form-data-files`, `*.xml`, `*.ckl`). These describe cryptography required *of the assessed systems*, not cryptography used *by* STIG Manager.
- The scanner and its own output directory.
- The IdP, MySQL server, reverse proxy/ingress, browsers, and the container base image contents. The scanner records what the repository configures for them and flags what it does not configure. Their actual algorithms are deployment facts that must be captured in the system's deployment inventory.
- Runtime negotiation. No TLS handshake or token exchange was observed. All findings are static.

## 3. Methodology

`scripts/crypto_inventory.py` is a static scanner with no runtime dependencies beyond the Python standard library. `openpyxl` is required for the workbook; `cryptography` or the `openssl` CLI is used when present for certificate parsing.

What it does:

{{METHOD_CHECKS}}

Each row carries: asset ID, file:line, scope, category, algorithm, key size/curve, mode/options, purpose, library, protocol context, security relevance, quantum-vulnerability class, CNSA 2.0 target, crypto-agility rating, external dependency, migration priority (1–4) with a one-line rationale, recommended action and roadmap phase, and a redacted evidence string. Secret rows carry path, line and type only.

Classes used: `Quantum-vulnerable (Shor)` for RSA/ECC/DH/EdDSA; `Symmetric — Grover-affected, adequate at ≥256-bit` for AES/SHA-2; `Deprecated/weak regardless of PQC` for MD5/SHA-1/3DES/RSA<2048/TLS<1.2; `Protocol/configuration — inherits class of negotiated algorithms` for TLS and JWT plumbing whose algorithms are chosen elsewhere; `Not applicable` for secrets, randomness, identifiers and runtime facts.

Priority scale: **1** act in Phase 1 or blocks later phases; **2** Phase 1/2 configuration and TLS work; **3** track, depends on an external party or is test-only; **4** informational.

### 3.1 Known limits of the method (also in the `Method` sheet)

{{METHOD_LIMITS}}

## 4. Cryptographic inventory summary

Counts below are generated from the scanner output.

**By migration priority**

{{TABLE_BY_PRIORITY}}

**By category**

{{TABLE_BY_CATEGORY}}

**By scope**

{{TABLE_BY_SCOPE}}

**By crypto-agility rating**

{{TABLE_BY_AGILITY}}

### 4.1 Top 10 rows by migration priority

Class abbreviations used in the tables below: Shor = Quantum-vulnerable (Shor); Grover = Symmetric — Grover-affected, adequate at ≥256-bit; Weak = Deprecated/weak regardless of PQC; Protocol = Protocol/configuration — inherits class of negotiated algorithms; N/A = Not applicable. P = migration priority (1 highest). Rows whose location starts with `test/` are test scope.

{{TABLE_TOP10}}

### 4.2 Quantum-vulnerable (Shor) rows

{{TABLE_SHOR}}

### 4.3 Deprecated or weak regardless of PQC

{{TABLE_WEAK}}

### 4.4 Symmetric and hash rows (Grover-affected)

SHA-256 is the only symmetric-class primitive found. It is used for PKCE, content digests and key identifiers. None of these uses protects long-lived confidentiality. CNSA 2.0 lists SHA-384 and SHA-512; SHA-256 remains acceptable under SP 800-131A Rev. 2. No AES, ChaCha20, 3DES, MD5, SHA-1, bcrypt, Argon2 or PBKDF2 use was found in application code. The application does not hash passwords; authentication is delegated to the IdP.

{{TABLE_GROVER}}

### 4.5 Libraries

{{TABLE_LIBRARIES}}

### 4.6 TLS and certificates

Rows in the `TLS` category (documentation-scope rows omitted here; see the workbook):

{{TABLE_TLS}}

Certificate material parsed from the tree (subject/issuer attribute types only; values withheld):

{{TABLE_CERTS}}

No PEM, CRT, KEY, JKS or P12 files are committed. `api/source/tls/` contains only a README that says TLS certificates and keys may be placed there; TLS material is supplied at deployment through `STIGMAN_API_TLS_KEY_FILE`, `STIGMAN_API_TLS_CERT_FILE` and `STIGMAN_DB_TLS_*`. `.gitignore` excludes `**.pem` and the MySQL TLS helper files under `api/source/tls/mysql*/`, which is the intended state. It does not exclude `.key`, `.crt`, `.p12` or `.jks`; adding those patterns is a Phase 1 hygiene item.

### 4.7 Runtime pins

{{TABLE_RUNTIME}}

Local probe of the scanning host (not the deployed image): {{RUNTIME_PROBE}}. Resolution of the `lts` tag supplied at scan time: {{LTS_RESOLVES_TO}}.

### 4.8 Secrets (type and location only)

{{COUNT_SECRETS}} rows record hardcoded credential-shaped values. All are in test, CI or documentation scope. No value is reproduced in any artifact. The JWT literals are test tokens signed by the repository's own RSA-1024 test key; the database passwords are those of throwaway containers in test and CI configuration and in deployment examples. They are inventoried because they show where a real credential could be pasted by mistake.

{{TABLE_SECRETS_BY_TYPE}}

## 5. Quantum-exposure analysis

### 5.1 What a CRQC would break here

A CRQC running Shor's algorithm breaks RSA, ECDSA, ECDH, EdDSA and finite-field DH. In this system those primitives appear in exactly four places:

1. **IdP token signatures** (`api/source/utils/auth.js:77`, `api/source/utils/jwksCache.js:188`). The API trusts any token whose signature verifies under a key from the IdP's JWKS. The key is RSA or EC today. With the IdP's private key recovered, an attacker mints tokens for any user and role. This is the highest-consequence exposure and it is an *authentication/integrity* exposure.
2. **TLS key exchange and server authentication** for browser→API, API→IdP and API→MySQL (`api/source/bootstrap/server.js:45`, `api/source/service/utils.js:198`, `api/source/utils/jwksCache.js:92`). Today these negotiate ECDHE (X25519 or P-256) with RSA or ECDSA certificates under Node.js defaults. Recorded traffic could be decrypted later if the ephemeral exchange is broken (HNDL). Server impersonation would also become possible, but only with a live CRQC.
3. **Release signing** (`.github/workflows/build-binary-artifacts.yml:65-82`). Detached OpenPGP signatures over binaries. The key algorithm is not visible in the repository; the key lives in a CI secret. Forgery lets an attacker ship a trojaned binary that passes the published verification step.
4. **Image trust metadata** (`root.json:1`). ECDSA P-256 public keys for a registry Notary trust root. Same consequence as 3, for container images.

### 5.2 Harvest-now-decrypt-later versus signature forgery

| Exposure | Data at risk | Lifetime of the data | Attack timing | Assessment |
|---|---|---|---|---|
| HNDL on browser→API TLS | Bearer tokens; STIG results, asset names, POA&M text | Tokens: minutes. Results: months to years (re-scanned periodically) | Record now, decrypt after CRQC | Bounded. Results are sensitive (they list unremediated weaknesses) but are refreshed; historical results lose value as systems change. Still worth hybrid key establishment because the fix is cheap and at the TLS terminator. |
| HNDL on API→MySQL TLS | Same data plus schema and credentials in flight | Same | Same | Same; also depends on the MySQL server build. Often on a private network. |
| HNDL on API→IdP TLS | JWKS (public), discovery (public) | Public data | n/a | Negligible. The JWKS is public by design. |
| Token forgery | Full application access | n/a | Requires a live CRQC | Highest consequence, but not retroactive. Mitigated when the IdP signs with ML-DSA and the API accepts it. |
| Release/image signature forgery | Supply chain | Signatures verified at install time | Requires a live CRQC | High consequence. Mitigated by ML-DSA or stateful hash-based signatures (LMS/XMSS) for firmware-like artifacts. |

Conclusion: the exposure profile of a read-only STIG/POA&M management system is mostly **integrity and authentication**. The data it holds is compliance evidence, not long-lived secrets. The HNDL surface is real but bounded to TLS, and TLS is where hybrid PQC is available first. Signature migration matters more for this system than key-establishment migration, and signature migration depends entirely on the IdP and library ecosystem.

### 5.3 What is not exposed

- No data-at-rest encryption is performed by the application, so there is no application-managed key to migrate. Database and disk encryption belong to the hosting environment and must be inventoried there.
- No password hashing. Authentication is delegated.
- No application-level encryption of attachments or exports.
- SHA-256 uses (PKCE, digests, `kid`) are collision/preimage uses with no public-key component. Grover's algorithm reduces effective preimage strength to about 128 bits, which remains adequate; CNSA 2.0 prefers SHA-384 for new designs.

## 6. Crypto-agility assessment

| Element | Where the algorithm is decided | Rating | Notes |
|---|---|---|---|
| JWS signature algorithm | IdP key type; `jsonwebtoken` maps key type → RS*/PS*/ES* (`auth.js:77`) | Library-bound | No `algorithms` option is passed. Swapping the IdP key from RSA to EC changes the accepted set with no code change. Adding ML-DSA needs a library that knows the `alg` and a JWK `kty` the filter accepts. |
| JWK key-type allowlist | `jwksCache.js:188` — literal `RSA`, `EC`, `OKP` | Hardcoded | A one-line change, but a change. ML-DSA JWKs use a different `kty` (`AKP` in the current IETF draft). |
| Audience / issuer checks | `config.js` `STIGMAN_JWT_AUD_VALUE` (audience optional); issuer from discovery | Configurable | Not PQC-relevant; noted because audience check is off unless configured. |
| TLS versions and ciphers | Not in repository; Node.js/OpenSSL defaults | Library-bound | Configurable only by changing the image or adding options in code. Default floor is TLS 1.2, ceiling TLS 1.3 on Node 24. |
| TLS certificate/key | `STIGMAN_API_TLS_*`, `STIGMAN_DB_TLS_*` files | Configurable | Any key type Node accepts. ML-DSA certificates would need OpenSSL 3.5+ and a CA that issues them. |
| Hybrid key exchange (X25519MLKEM768) | Node.js `tls` groups option / OpenSSL defaults | Library-bound | Node 24 with OpenSSL 3.5 can offer it when the group is in the default list or set explicitly. Not exposed as configuration in this repository. |
| HSTS and security headers | Not set in application | Absent | Must be set by the reverse proxy. |
| Release signing | GnuPG in CI; key from secret | Configurable | Algorithm follows the key generated by the secret owner. GnuPG ML-DSA support is not assumed here. |
| Image trust root | `root.json` static ECDSA keys | Hardcoded | Rotation requires a new trust root and consumer update. |

Gaps generated from the inventory:

{{TABLE_GAPS}}

## 7. Interoperability and dependency constraints

{{TABLE_DEPENDENCIES}}

### 7.1 Identity provider

The API accepts whatever the IdP publishes, within the RSA/EC/OKP filter. Migration to ML-DSA-signed tokens requires the IdP to (a) generate an ML-DSA key, (b) publish it in JWKS with the right `kty`/`alg`, and (c) sign access tokens with it. A JOSE algorithm registration for ML-DSA is in progress at the IETF (draft-ietf-cose-dilithium). Keycloak upstream has an open pull request for ML-DSA OIDC support (keycloak/keycloak#50358, open, not merged at the time of writing). No released Keycloak version is assumed to support it. Keycloak's active/passive key model allows adding a new signing key and rotating without downtime, which is the mechanism a later cutover would use.

### 7.2 JWT library

`jsonwebtoken` 9.0.2 supports HS*, RS*, PS* and ES* only. It does not support EdDSA, so the `OKP` entry in the JWK filter is currently unreachable in practice. It has no ML-DSA support. A library change (for example to a `jose` release that implements the ML-DSA draft) is a prerequisite for Phase 3 and is a code change that requires Government authorization.

### 7.3 MySQL server

`mysql2` uses Node's `tls`. The negotiated protocol and groups are the intersection of the Node/OpenSSL build and the MySQL server build. Hybrid ML-KEM groups require both sides on OpenSSL 3.5-class libraries. The application does not set `rejectUnauthorized`; Node's default verifies the server certificate against the supplied CA, but this should be confirmed in a test environment rather than assumed.

### 7.4 Node.js and OpenSSL

- Node.js 24 became LTS on 2025-10-28 and ships OpenSSL 3.5 from 24.5.0 onward (Node.js release notes). OpenSSL 3.5 implements ML-KEM, ML-DSA and SLH-DSA and is an LTS release supported to April 2030 (OpenSSL announcement).
- Node.js 24 uses OpenSSL security level 2 by default: RSA/DSA/DH keys under 2048 bits and EC keys under 224 bits are rejected in TLS (Node.js v22→v24 migration guide). This is why the RSA-1024 test fixtures are flagged even though they never touch TLS today.
- The scanning host (Node 24.19.0, OpenSSL 3.5.7) reported ML-KEM-768 and ML-DSA-65 key generation available through `node:crypto`. This is evidence for the Node 24 line, not for the deployed image, which is a mutable tag.
- Per the Node.js release schedule, the `lts` tag moves to Node.js 26 on 2026-10-28. The bundled OpenSSL of that line should be re-verified at that time.
- Packaged binaries target `node24-win` and `node24-linuxstatic` (`api/pkg.config.json:14`). Their embedded OpenSSL is whatever the packaging tool's Node 24 build bundles.

### 7.5 Browser

The browser negotiates TLS to the API and IdP. Chrome offers the X25519MLKEM768 hybrid group in TLS 1.3 from Chrome 131 (Google Security Blog, September 2024); the server side (reverse proxy or Node) decides whether it is used. The client performs no public-key operations of its own; PKCE uses SHA-256 and `crypto.getRandomValues`.

### 7.6 Mutable runtime tags

`node:lts-alpine` (`Dockerfile:15`) and `lts/*` (CI) resolve differently over time. Any PQC evaluation result is only valid for the concrete Node/OpenSSL version tested. Recommendation: record the resolved digest in the evaluation report, and decide (Government) whether production should pin a version.

## 8. Phased PQC migration roadmap

No phase below changes production without a separate, authorized change. Phases 1–4 list what would change *if* authorized, and what to test first.

### Phase 0 — Inventory and governance (now)

- Adopt this inventory as the baseline. Re-run the scanner on each release; compare `crypto-inventory.json` between releases and review any new Shor-class row.
- Record deployment-side facts the scanner cannot see: IdP signing algorithm and key size, MySQL server TLS version and cipher, reverse proxy TLS policy, actual Node/OpenSSL version of the deployed image (`node -p process.versions.openssl`), OpenPGP key algorithm behind `STIGMAN_PRIVATE_KEY`.
- Open tracking items for the three external dependencies: IdP ML-DSA support, `jsonwebtoken`/`jose` ML-DSA support, MySQL server hybrid-group support.
- Decide pinning policy for the runtime image (Decision D5).

### Phase 1 — Hygiene (no PQC yet)

- Replace RSA-1024 test fixtures with RSA-3072 or P-256 (`test/utils/mockOidc.js:21,48`; `test/api/mock-keycloak*/.../certs`). Test-only change; still requires authorization because it touches the repository.
- Document and, when authorized, configure an explicit TLS policy: minimum TLS 1.2, prefer TLS 1.3, approved cipher suites (SP 800-52 Rev. 2), HSTS at the reverse proxy. Today none of this is set in the repository (`server.js:45`, absence rows).
- Document that `STIGMAN_OIDC_PROVIDER` must use `https://` in production; the default and the JWKS client permit `http://` (`config.js:95`, `jwksCache.js:92`).
- Document that `STIGMAN_JWT_AUD_VALUE` should be set so audience checking is active (`config.js`, `auth.js:77`).
- Confirm `rejectUnauthorized` behavior for the MySQL connection in a test environment.

### Phase 2 — Hybrid key establishment at TLS termination (non-production)

- Target: X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem) offered by the TLS terminator in front of the API and, where the MySQL server supports it, on the database connection.
- Preferred placement: the reverse proxy or ingress, not the Node process. This leaves application code untouched and centralizes policy.
- Alternative: Node.js `https.createServer` with an explicit `groups`/`ecdhCurve`-style option on Node 24 + OpenSSL 3.5. This is a code change and is listed only for evaluation.
- Test-and-evaluation plan (non-production):
  1. Build the evaluation image from a pinned Node 24 digest; record `process.versions.openssl`.
  2. Terminate TLS at a proxy configured with X25519MLKEM768 first, X25519 fallback. Confirm handshake group with a packet capture or `openssl s_client -groups`.
  3. Exercise the full API test suite (`test/api`) through the proxy; measure handshake latency and CPU against the classical baseline.
  4. Confirm browser interoperability with the browsers in the Government's approved list.
  5. Repeat against a MySQL server built on OpenSSL 3.5 if available; otherwise record the constraint.
  6. Report: negotiated groups, failures, performance deltas, and any client that fell back to classical.

### Phase 3 — Signature migration (when IdP and libraries support ML-DSA)

- Prerequisites: IdP release with ML-DSA signing; JOSE `alg` registration final; a JWT library in the API supporting it; Government approval of ML-DSA parameter set (ML-DSA-65 or ML-DSA-87 per CNSA 2.0 guidance for the system's classification).
- Changes that would be needed (all require authorization): swap or upgrade the JWT library; extend the JWK `kty` filter (`jwksCache.js:188`); optionally pass an explicit `algorithms` allowlist so the accepted set is configuration, not inference.
- Transition pattern: IdP publishes both classical and ML-DSA keys (passive/active rotation). API accepts both during overlap. Cut over when all clients obtain ML-DSA-signed tokens. Then remove classical keys.
- Release signing: generate an ML-DSA (or LMS/XMSS for long-lived, rarely-signed artifacts per SP 800-208) signing key when the signing tool supports it; publish both signatures during overlap; update `root.json` trust root with the new key type when the registry supports it.
- Evaluation: run the API test suite against the repository's mock OIDC provider modified to sign with ML-DSA; measure token size (ML-DSA-65 signatures are about 3.3 KB) against header limits at the proxy and in the WebSocket upgrade path.

### Phase 4 — Validation and retirement of classical-only paths

- Verify every TLS endpoint negotiates a hybrid or PQC group; verify every accepted token is ML-DSA-signed; verify release artifacts carry PQC signatures.
- Remove RSA/EC keys from the IdP JWKS; remove classical `alg` values from the API allowlist; retire classical-only cipher configuration at the proxy.
- Re-run the scanner; the Shor-class count for non-test scope should be zero except for documented exceptions.
- Timeline anchors: NIST IR 8547 (initial public draft) proposes that 112-bit-security quantum-vulnerable algorithms are deprecated after 2030 and all quantum-vulnerable algorithms are disallowed after 2035; NSM-10 sets 2035 as the national migration goal. The system's own dates must be set by the Government (Decision D7).

## 9. Risks, interoperability constraints, operational impacts

| Risk / constraint | Effect | Mitigation |
|---|---|---|
| IdP ML-DSA support arrives late | Phase 3 slips; token forgery exposure persists | Track upstream; keep hybrid TLS (Phase 2) as the near-term control; consider IdP alternatives only with Government approval |
| `jsonwebtoken` has no PQC roadmap | Library swap needed | Evaluate `jose` releases implementing the ML-DSA draft in a test branch; no production change until authorized |
| Larger tokens and handshakes | ML-DSA signatures and ML-KEM key shares increase header and handshake sizes | Test proxy header limits and WebSocket upgrade; measure latency in Phase 2/3 T&E |
| Mutable `lts` tag | Evaluation results not reproducible; behavior changes on 2026-10-28 | Pin by digest for evaluation; decide production pinning (D5) |
| MySQL server lags | Database link stays classical | Accept as documented exception or upgrade server; often on private network |
| Security level 2 rejects RSA-1024 | Any legacy RSA-1024 material fails on Node 24 | Replace test fixtures now (Phase 1) |
| Reverse proxy owns TLS policy | Repository cannot enforce TLS floor or HSTS | Document the required proxy policy as a deployment control and verify in T&E |
| Hybrid vs. pure PQC | Browsers ship the hybrid group, not a pure ML-KEM group | Recommend hybrid in Phase 2; revisit for Phase 4 (D2) |
| Test fixtures model RSA only | Tests will not catch ML-DSA regressions | Extend `test/utils/mockOidc.js` when a library is chosen (Phase 3) |

## 10. Decisions requiring Government approval

- **D1 — Algorithm selection.** Adopt CNSA 2.0 targets as written in the inventory: ML-KEM-768 or ML-KEM-1024 for key establishment; ML-DSA-65 or ML-DSA-87 for signatures; LMS/XMSS for firmware-like release artifacts; SHA-384 for new hash uses. Confirm parameter sets for the system's classification level.
- **D2 — Hybrid versus pure PQC.** Recommend hybrid X25519MLKEM768 for Phase 2 and pure ML-DSA (no composite) for token signatures in Phase 3, with a dual-key overlap. Confirm or direct otherwise.
- **D3 — IdP roadmap dependency.** Accept that Phase 3 is gated on the IdP vendor's ML-DSA release, or direct evaluation of alternatives.
- **D4 — JWT library change.** Authorize a test-branch evaluation of a PQC-capable JOSE library and an explicit `algorithms` allowlist. No production change without a separate approval.
- **D5 — Runtime pinning.** Pin `node:lts-alpine` and CI `lts/*` to a concrete Node 24 version/digest, or keep the mutable tag and accept re-verification on each move.
- **D6 — TLS policy ownership.** Confirm that TLS version/cipher floor and HSTS are set at the reverse proxy (deployment control), or authorize adding TLS options in the application.
- **D7 — Timelines.** Set target dates for Phases 1–4 against the NSM-10 2035 goal and the NIST IR 8547 draft 2030/2035 transition points.
- **D8 — Test fixture replacement.** Authorize replacing RSA-1024 test keys/certificates with RSA-3072 or P-256 (test-only change).
- **D9 — Release-signing key type.** Confirm the OpenPGP key algorithm behind `STIGMAN_PRIVATE_KEY` and decide when to add a PQC signature.

## 11. Traceability appendix

### 11.1 Recommendation → source → evidence

| Recommendation | Standard / source | Repository evidence |
|---|---|---|
| Baseline inventory, re-run per release | OMB M-23-02 (inventory of cryptographic systems); NSM-10 | `scripts/crypto_inventory.py`; `crypto-inventory.json` |
| Replace RSA-1024 fixtures | SP 800-131A Rev. 2 (RSA < 2048 disallowed); Node.js v22→v24 guide (security level 2) | `test/utils/mockOidc.js:21,48`; `test/api/mock-keycloak*/.../certs:1` |
| TLS 1.2 floor, TLS 1.3 preferred, approved suites | SP 800-52 Rev. 2; RFC 8446 | `api/source/bootstrap/server.js:45` (no options set); absence rows |
| HSTS at proxy | SP 800-52 Rev. 2 (server configuration) | absence row anchored at `server.js:45` |
| HTTPS-only IdP URL; audience check | RFC 7636 (PKCE) and OIDC practice; SP 800-52 Rev. 2 | `api/source/utils/config.js:95`; `jwksCache.js:92`; `auth.js:77` |
| Hybrid X25519MLKEM768 at TLS termination | FIPS 203; draft-ietf-tls-ecdhe-mlkem; CNSA 2.0 (ML-KEM) | `server.js:45`; `service/utils.js:198`; `Dockerfile:15` |
| ML-DSA token signatures when IdP supports it | FIPS 204; draft-ietf-cose-dilithium; CNSA 2.0 (ML-DSA) | `auth.js:77`; `jwksCache.js:188` |
| ML-DSA or LMS/XMSS for release signing | FIPS 204; FIPS 205; SP 800-208; CNSA 2.0 | `.github/workflows/build-binary-artifacts.yml:49-82`; `root.json:1` |
| Pin runtime for evaluation | Node.js release schedule; OpenSSL 3.5 LTS announcement | `Dockerfile:15`; `.github/workflows/api-container-tests.yml:40`; `api/pkg.config.json:14` |
| 2030/2035 transition anchors | NIST IR 8547 ipd; NSM-10 | Section 8, Phase 4 |
| SHA-256 acceptable; SHA-384 for new designs | SP 800-131A Rev. 2; CNSA 2.0 | `STIGService.js:799,802`; `Attachments.js:141`; `oidc-worker.js:157,267` |

### 11.2 Sources (each URL was opened and confirmed during this assessment)

- NSM-10, National Security Memorandum on Promoting United States Leadership in Quantum Computing While Mitigating Risks to Vulnerable Cryptographic Systems (May 4, 2022): https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/
- OMB M-23-02, Migrating to Post-Quantum Cryptography (Nov 18, 2022): https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
- NSA Post-Quantum Cybersecurity Resources (CNSA 2.0; points to CNSSP 15, released March 4, 2025): https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/
- CNSS Policies index (CNSSP 15): https://www.cnss.gov/CNSS/issuances/Policies.cfm (requires a DoD root certificate in the browser)
- FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard: https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204, Module-Lattice-Based Digital Signature Standard: https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205, Stateless Hash-Based Digital Signature Standard: https://csrc.nist.gov/pubs/fips/205/final
- NIST SP 800-131A Rev. 2, Transitioning the Use of Cryptographic Algorithms and Key Lengths: https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- NIST SP 800-52 Rev. 2, Guidelines for the Selection, Configuration, and Use of TLS Implementations: https://csrc.nist.gov/pubs/sp/800/52/r2/final
- NIST SP 800-208, Recommendation for Stateful Hash-Based Signature Schemes: https://csrc.nist.gov/pubs/sp/800/208/final
- NIST IR 8547 (initial public draft), Transition to Post-Quantum Cryptography Standards: https://csrc.nist.gov/pubs/ir/8547/ipd
- RFC 7518, JSON Web Algorithms: https://www.rfc-editor.org/rfc/rfc7518
- RFC 8037, CFRG Elliptic Curve Signatures in JOSE (OKP key type): https://www.rfc-editor.org/rfc/rfc8037
- RFC 7636, Proof Key for Code Exchange: https://www.rfc-editor.org/rfc/rfc7636
- RFC 8446, TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768 and related hybrids): https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- draft-ietf-cose-dilithium (ML-DSA for JOSE/COSE): https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
- Node.js 24.5.0 release notes (OpenSSL 3.5 upgrade): https://nodejs.org/en/blog/release/v24.5.0
- Node.js v22 to v24 migration guide (OpenSSL 3.5, security level 2): https://nodejs.org/en/blog/migrations/v22-to-v24
- Node.js release schedule: https://github.com/nodejs/Release
- OpenSSL 3.5 final release (ML-KEM, ML-DSA, SLH-DSA; LTS to April 2030): https://openssl-library.org/post/2025-04-08-openssl-35-final-release/
- Google Security Blog, "A new path for Kyber on the web" (Chrome 131 switches to X25519MLKEM768): https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html
- Node.js `crypto` and `tls` API documentation: https://nodejs.org/api/crypto.html and https://nodejs.org/api/tls.html
- `jsonwebtoken` (supported algorithms): https://github.com/auth0/node-jsonwebtoken
- Keycloak Server Administration Guide (signing keys, active/passive rotation): https://www.keycloak.org/docs/latest/server_admin/index.html
- Keycloak pull request for ML-DSA OIDC support (open, unmerged at time of writing): https://github.com/keycloak/keycloak/pull/50358

### 11.3 Inventory row → evidence

Every row in `Cryptographic-Inventory.xlsx` (`Inventory` sheet) and `crypto-inventory.json` carries `file`, `line`, `rule` and a redacted `evidence` string. Rows that record the absence of a control (`ABSENT-*`) are anchored to the TLS server setup line and state the pattern that was not found.
