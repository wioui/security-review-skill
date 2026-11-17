<!--
Security review pull request template (security-review skill).
Install: copy this file to .github/pull_request_template.md (GitHub)
or .gitlab/merge_request_templates/Security.md (GitLab).
Tick only the domains this change touches; everything else is N/A.
Expand and complete the touched domains. IDs match the security-review checklist.
Standards: OWASP Top 10:2025, OWASP ASVS 5.0.0, OWASP API Security Top 10:2023, MITRE CWE.
-->

## Summary

<!-- What changes and why. Link the issue or ticket and its security requirements. -->

Closes #

## Provenance

- [ ] Human-authored
- [ ] AI-assisted or agent-authored (tool or agent: ______). The AI checks below are mandatory.

## Security scope

<!-- Tick the domains this diff touches. Unticked domains are N/A. Secrets is always in scope. -->

- [ ] AUTHN · Authentication (A07:2025 · ASVS V6)
- [ ] AUTHZ · Authorization and multi-tenant isolation (A01:2025 · ASVS V8)
- [ ] SESSION · Sessions and self-contained tokens (ASVS V7 · V9 · V3)
- [ ] INJECTION · Input validation and injection (A05:2025 · ASVS V1 · V2)
- [ ] API · API surface and schema (API Top 10:2023 · ASVS V4)
- [ ] FILES · File upload, path, and parser safety (A01 · A02:2025 · ASVS V5)
- [ ] LOGIC · Business logic and concurrency (A06:2025 · ASVS V2 · V15)
- [ ] CRYPTO · Cryptography and TLS (A04:2025 · ASVS V11 · V12)
- [x] SECRETS · Secrets in code and Git history (A07:2025 · ASVS V13), always in scope
- [ ] ERRORS · Error handling and security logging (A09 · A10:2025 · ASVS V16)
- [ ] DATA · Data protection and LLM privacy (A04:2025 · ASVS V14)
- [ ] DEPS · Dependencies and reachability (A03:2025 · ASVS V15)
- [ ] CONFIG · Configuration, containers, and CI/CD (A02 · A03:2025 · ASVS V3 · V13)

## Stage 1 automated gate

- [ ] SAST and injection dataflow clean, or every hit triaged
- [ ] Secret scan over every commit on the branch (`base..head`) clean
- [ ] New packages verified on their registry; SCA alerts triaged with reachability evidence
- [ ] IaC, container, and CI linters clean
- [ ] Cookie and token flags, crypto misuse, and path and parser sinks checked

## Domain checks

<details>
<summary><b>AUTHN · Authentication</b> · A07:2025 · ASVS V6</summary>

- [ ] AUTHN-01 New routes are authenticated by default; public endpoints use a documented opt-out (CWE-306)
- [ ] AUTHN-02 Identity verification uses an established framework or identity provider
- [ ] AUTHN-03 Passwords use Argon2id, bcrypt, or scrypt with current work factors (CWE-916)
- [ ] AUTHN-04 Login, reset, and MFA endpoints rate-limit per account and per IP (CWE-307)
- [ ] AUTHN-05 MFA cannot be skipped by calling downstream endpoints directly (CWE-287, CWE-288)
- [ ] AUTHN-06 Reset tokens are random, short-lived, and single-use (CWE-640)

</details>

<details>
<summary><b>AUTHZ · Authorization and multi-tenant isolation</b> · A01:2025 · ASVS V8</summary>

- [ ] AUTHZ-01 Every new route, controller method, and resolver runs a server-side permission check (CWE-862)
- [ ] AUTHZ-02 The policy denies by default when no rule matches
- [ ] AUTHZ-03 Privileged operations check permissions in the service layer, not only route middleware (CWE-285)
- [ ] AUTHZ-04 Lookups by ID are scoped to the authenticated owner (CWE-639)
- [ ] AUTHZ-05 `tenant_id` comes from the verified session or token claims, never from the request (CWE-639)
- [ ] AUTHZ-06 List, search, and export queries apply the same tenant and ownership filters
- [ ] AUTHZ-07 Update, patch, and delete paths verify ownership as strictly as reads (CWE-863)
- [ ] AUTHZ-08 Workers, queue consumers, and webhook processors re-verify tenant and ownership (CWE-863)
- [ ] AUTHZ-09 Cookie-authenticated mutations enforce CSRF tokens or strict SameSite (CWE-352)

</details>

<details>
<summary><b>SESSION · Sessions and self-contained tokens</b> · ASVS V7 · V9 · V3</summary>

- [ ] SESSION-01 Session IDs rotate on login and privilege elevation (CWE-384)
- [ ] SESSION-02 Session cookies set HttpOnly, Secure, and an explicit SameSite (CWE-1004, CWE-614, CWE-1275)
- [ ] SESSION-03 JWTs are verified against an algorithm allowlist, reject `none`, and check `exp`, `aud`, `iss` (CWE-347)
- [ ] SESSION-04 No tokens, session IDs, or OAuth codes in URLs or logs (CWE-598)
- [ ] SESSION-05 Logout, password reset, and suspension revoke server-side sessions (CWE-613)
- [ ] SESSION-06 Refresh tokens rotate, and reuse revokes the token family

</details>

<details>
<summary><b>INJECTION · Input validation and injection</b> · A05:2025 · ASVS V1 · V2</summary>

- [ ] INJECTION-01 Queries use parameter binding with no string interpolation (CWE-89)
- [ ] INJECTION-02 Output encoding matches the sink context (CWE-79)
- [ ] INJECTION-03 Subprocesses use argument arrays with the shell disabled (CWE-78)
- [ ] INJECTION-04 User-driven outbound requests use scheme and host allowlists and block private IPs after DNS resolution (CWE-918)
- [ ] INJECTION-05 No native deserialization of untrusted data (CWE-502)
- [ ] INJECTION-06 Server-side allowlist validation for type, length, range, and format (CWE-20)

</details>

<details>
<summary><b>API · API surface and schema</b> · API Top 10:2023 · ASVS V4</summary>

- [ ] API-01 Legacy, versioned, and internal endpoints enforce authentication (API2:2023, API9:2023)
- [ ] API-02 Every identifier in path, query, and nested body is authorized (API1:2023, CWE-639)
- [ ] API-03 Request bodies bind to explicit DTOs; privileged fields are not writable (API3:2023, CWE-915)
- [ ] API-04 Schemas reject unknown fields and type mismatches (CWE-20)
- [ ] API-05 Page sizes are capped and expensive endpoints are rate- or cost-limited (API4:2023, CWE-770)
- [ ] API-06 GraphQL depth, complexity, and introspection are controlled (API4:2023)
- [ ] API-07 Webhooks verify signatures over raw bytes with timestamp freshness (CWE-345)

</details>

<details>
<summary><b>FILES · File upload, path, and parser safety</b> · A01 · A02:2025 · ASVS V5</summary>

- [ ] FILES-01 Paths from input are canonicalized and confined to a base directory (CWE-22)
- [ ] FILES-02 Archive extraction rejects entries and symlinks that escape the target (CWE-22)
- [ ] FILES-03 Uploads are size-capped and content-sniffed, not trusted by extension or Content-Type (CWE-434)
- [ ] FILES-04 Uploads are stored outside the webroot under generated names (CWE-434)
- [ ] FILES-05 XML parsers disable DTDs and external entities (CWE-611)

</details>

<details>
<summary><b>LOGIC · Business logic and concurrency</b> · A06:2025 · ASVS V2 · V15</summary>

- [ ] LOGIC-01 Workflow state transitions are enforced server-side (CWE-841)
- [ ] LOGIC-02 Amounts and quantities reject negatives, zero where invalid, NaN, and overflow (CWE-20, CWE-1284)
- [ ] LOGIC-03 Balance, quota, and inventory changes are atomic (CWE-362, CWE-367)
- [ ] LOGIC-04 Payments, transfers, and provisioning require idempotency keys or nonces
- [ ] LOGIC-05 Business limits are enforced in a shared domain layer across all entry points (API6:2023)

</details>

<details>
<summary><b>CRYPTO · Cryptography and TLS</b> · A04:2025 · ASVS V11 · V12</summary>

- [ ] CRYPTO-01 No custom cryptographic primitives or protocols (CWE-327)
- [ ] CRYPTO-02 Authenticated modes (AES-256-GCM, ChaCha20-Poly1305); no ECB, DES, MD5, or SHA-1 for security (CWE-327)
- [ ] CRYPTO-03 IVs and nonces are unique per operation (CWE-329, CWE-323)
- [ ] CRYPTO-04 Security tokens and codes use a CSPRNG (CWE-338)
- [ ] CRYPTO-05 TLS certificate and hostname verification stay enabled (CWE-295)
- [ ] CRYPTO-06 Keys load at runtime from a KMS or secrets manager (CWE-321)

</details>

<details>
<summary><b>SECRETS · Secrets in code and Git history</b> · A07:2025 · ASVS V13</summary>

- [ ] SECRETS-01 No real credentials in code, tests, fixtures, Dockerfiles, CI YAML, or `.env.example` (CWE-798)
- [ ] SECRETS-02 Secrets committed earlier on the branch are revoked and rotated, not just deleted (CWE-798)
- [ ] SECRETS-03 `.env`, credential JSON, and `.tfvars` files are in `.gitignore` and `.dockerignore`
- [ ] SECRETS-04 New secrets are injected at runtime, not through build-time ARG or ENV (CWE-526)

</details>

<details>
<summary><b>ERRORS · Error handling and security logging</b> · A09 · A10:2025 · ASVS V16</summary>

- [ ] ERRORS-01 Error responses are generic with correlation IDs; no stack traces or SQL (CWE-209)
- [ ] ERRORS-02 Exceptions in auth, authorization, rate limiting, and policy paths fail closed (CWE-636)
- [ ] ERRORS-03 Security events emit structured audit logs with actor, tenant, target, and time (CWE-778)
- [ ] ERRORS-04 No secrets or raw PII in logs (CWE-532)
- [ ] ERRORS-05 Untrusted values are neutralized before logging (CWE-117)

</details>

<details>
<summary><b>DATA · Data protection and LLM privacy</b> · A04:2025 · ASVS V14</summary>

- [ ] DATA-01 New sensitive fields are classified per policy
- [ ] DATA-02 New stored data is minimal and has a retention or deletion lifecycle (CWE-359)
- [ ] DATA-03 Responses use explicit schemas, not raw models (API3:2023, CWE-213)
- [ ] DATA-04 New sensitive stores are encrypted at rest (CWE-311)
- [ ] DATA-05 Personal data, customer code, and confidential records reach analytics or LLM vendors only with documented approval and zero data retention

</details>

<details>
<summary><b>DEPS · Dependencies and reachability</b> · A03:2025 · ASVS V15</summary>

- [ ] DEPS-01 Each new dependency is justified and actively maintained (CWE-1104)
- [ ] DEPS-02 Package names match the canonical project exactly (CWE-1357)
- [ ] DEPS-03 Lockfiles change with manifests and keep integrity hashes
- [ ] DEPS-04 Install-time scripts of new packages are inspected or disabled (CWE-829)
- [ ] DEPS-05 Licences comply with policy
- [ ] DEPS-06 CVE alerts are triaged with function-level reachability (CWE-1395)

</details>

<details>
<summary><b>CONFIG · Configuration, containers, and CI/CD</b> · A02 · A03:2025 · ASVS V3 · V13</summary>

- [ ] CONFIG-01 Debug modes are off in production profiles (CWE-489)
- [ ] CONFIG-02 CORS never pairs a wildcard or reflected origin with credentials (CWE-942)
- [ ] CONFIG-03 CSP, HSTS, nosniff, and frame-ancestors are in place
- [ ] CONFIG-04 No public buckets and no 0.0.0.0/0 ingress on admin or database ports (CWE-732)
- [ ] CONFIG-05 IAM grants specific actions on specific resources (CWE-250)
- [ ] CONFIG-06 Containers run as non-root with capabilities dropped (CWE-250)
- [ ] CONFIG-07 CI uses least-privilege tokens, SHA-pinned actions, and no untrusted `${{ }}` in `run:` (CWE-78)

</details>

## AI-generated PR checks

<!-- Mandatory when the change is AI-assisted or agent-authored. -->

- [ ] AI-01 Every new package exists on its registry with real history, repository, and maintainer (anti-slopsquatting, CWE-1357)
- [ ] AI-02 No security control was dropped across commits (compared with the ticket and the first commit)
- [ ] AI-03 No placeholder credentials or fallback secret defaults (CWE-798)
- [ ] AI-04 No stubbed authorization or TODO security bypasses (CWE-862)
- [ ] AI-05 Tests assert 401, 403 or 404, 422, and 429 paths, not only 200

## Human reviewer (Stage 2)

- [ ] Authorization semantics match real business roles
- [ ] Multi-tenant isolation design for shared tables, caches, and queues reviewed
- [ ] New sensitive fields classified with a retention window
- [ ] New dependencies are worth their risk
- [ ] Business logic and concurrency abuse considered (state skipping, negative amounts, races)
- [ ] External and LLM data egress approved
- [ ] Control-regression audit confirmed against the ticket
- [ ] Policy exceptions (public routes, waivers) approved and documented
