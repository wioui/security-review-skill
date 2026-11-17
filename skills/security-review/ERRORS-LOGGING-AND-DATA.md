# Errors, Logging, and Data Protection Review

#### When to use this file

Use the `ERRORS` part when the diff touches exception handlers, error responses, `try/catch` blocks around security decisions, logging statements, audit events, or logger configuration. Use the `DATA` part when the diff introduces database columns or models, modifies API serializers, adds storage (buckets, caches, queues, backups), or wires application data into analytics SDKs or Large Language Model (LLM) APIs.

It covers `ERRORS` (A09:2025 and A10:2025, ASVS V16) and `DATA` (A04:2025, ASVS V14). OWASP Top 10:2025 elevated A10:2025 Mishandling of Exceptional Conditions to a standalone category and renamed A09:2025 to emphasize alerting alongside logging. Verbose exception traces and unapproved data sharing turn local bugs into regulatory incidents.

## Core discipline (include in every reviewer prompt for this file)

```
- Errors fail closed. An exception, timeout, or malformed response in an authentication, authorization, signature, rate-limit, or policy path denies.
- Everything that leaves the process is a disclosure decision: error bodies, logs, traces, analytics events, LLM prompts.
- Log security events, not secrets: actor, tenant, action, target, outcome, time. Never credentials, tokens, or raw bodies.
- Every new data field has a classification, a purpose, and a deletion path.
- Every new external recipient of data is a sub-processor. Its approval lives outside the repository unless documented in it, so record needs_validation instead of assuming.
```

## ERRORS — Error Handling and Security Logging · A09:2025 · A10:2025 · ASVS V16 (subagent_type: `general`)

Cheat sheets: Error Handling, Logging, Logging Vocabulary.

**ERRORS-01 — Sanitized User-Facing Error Responses**
- **Check:** External error payloads return generic messages with correlation IDs, stripping stack traces, SQL syntax, filesystem paths, and internal hostnames.
- **Why:** Detailed exception dumps map framework versions, table schemas, and internal topology for attackers.
- **Ref:** `A10:2025` · `ASVS V16` · `CWE-209`
- **Verify:** Check new error handlers, exception middleware, and API error responses: no `str(e)`, `e.message`, stack traces, SQL errors, or paths returned to clients; production profiles disable verbose errors; responses carry a correlation ID that maps to server-side logs.

**ERRORS-02 — Fail-Closed Exception Paths**
- **Check:** `try/catch` blocks wrapping authentication, authorization, rate limiting, or policy engines deny access whenever an exception occurs.
- **Why:** Catch blocks that log an error and fall through (or return `true`) turn downstream timeouts into complete authentication bypasses.
- **Ref:** `A10:2025` · `ASVS V16` · `CWE-636`
- **Verify:** Read every `try/except` and `catch` around authentication, authorization, signature verification, rate limiting, entitlements, and policy calls. On exception the code denies (raises, returns 401, 403, or 503); it never passes, returns `True`, calls `next()`, or falls through to the protected action.

**ERRORS-03 — Structured Audit Logging on Security Events**
- **Check:** Authentication failures, access denials, privilege changes, and administrative mutations emit structured logs capturing actor identity, tenant, target resource, and timestamp.
- **Why:** Incident responders cannot scope or prove unauthorized access without an immutable audit trail.
- **Ref:** `A09:2025` · `ASVS V16` · `CWE-778`
- **Verify:** For new authentication flows, permission changes, admin actions, data exports, and key or secret operations, confirm a structured audit event with actor, tenant, action, target, outcome, timestamp, and correlation ID, written to the security log sink rather than debug output.

**ERRORS-04 — Zero Secrets or Raw PII in Logs**
- **Check:** Log statements never serialize `Authorization` headers, cookies, passwords, payment card numbers, or unredacted request bodies.
- **Why:** Centralized log aggregators are readable by far more engineers and third-party processors than production databases.
- **Ref:** `A09:2025` · `ASVS V16` · `CWE-532`
- **Verify:** Flag logging of request and response bodies, headers, cookies, tokens, passwords, OTPs, card numbers, and whole user objects, and exception logging that dumps local variables. Confirm redaction filters cover new sensitive fields.

**ERRORS-05 — Log Injection Neutralization**
- **Check:** Untrusted strings written to logs use structured JSON fields or strip carriage returns, newlines, and ANSI control characters.
- **Why:** Raw `\r\n` sequences in text logs let attackers forge fake audit entries and corrupt SIEM parsers.
- **Ref:** `A09:2025` · `ASVS V16` · `CWE-117`
- **Verify:** Confirm untrusted values reach logs as structured fields (JSON loggers) or with `\r`, `\n`, and ANSI escape sequences stripped. Flag string-concatenated log lines carrying user input in text-format logs.

A fail-open red flag, and its fail-closed replacement:

```python
# RED FLAG: an outage in the policy engine silently grants access (CWE-636)
try:
    allowed = policy_client.is_allowed(principal, "invoice:export", invoice)
except Exception:
    logger.exception("policy check failed")
    allowed = True

# SECURE: fail closed with an error the caller cannot mistake for success
try:
    allowed = policy_client.is_allowed(principal, "invoice:export", invoice)
except PolicyUnavailableError:
    logger.warning("policy check unavailable", extra={"actor": principal.user_id, "tenant": principal.tenant_id})
    raise HTTPException(status_code=503, detail="Authorization temporarily unavailable")
if not allowed:
    raise HTTPException(status_code=403, detail="Forbidden")
```

## DATA — Data Protection and LLM Privacy Boundaries · A04:2025 · ASVS V14 (subagent_type: `general`)

Cheat sheets: User Privacy Protection, Cryptographic Storage. Approvals in this domain are human decisions: draft the question, do not answer it.

**DATA-01 — Explicit Data Classification**
- **Check:** New personal, financial, health, or tenant-confidential fields are documented and tagged according to your data classification policy.
- **Why:** Unclassified columns bypass automated masking, encryption, and regional residency guardrails.
- **Ref:** `ASVS V14`
- **Verify:** For new columns, models, events, or API fields holding personal, financial, health, credential, or tenant-confidential data, confirm the classification is recorded where the policy expects it (schema annotations, data catalog entries, PII tags, a privacy register). When the policy lives outside the repository, ask.

**DATA-02 — Data Minimization and Defined Retention**
- **Check:** Newly stored attributes collect only what the feature strictly requires and attach to a concrete TTL or deletion lifecycle.
- **Why:** Sensitive records you never retain cannot be exfiltrated in a future breach.
- **Ref:** `ASVS V14` · `CWE-359`
- **Verify:** Question every new stored attribute: does the feature need it? Confirm a TTL, retention job, or deletion path that also reaches backups, caches, search indexes, and analytics copies, and that account deletion covers the new field.

**DATA-03 — Minimal Response Serialization**
- **Check:** API endpoints serialize explicit response schemas containing only client-required fields rather than returning raw database models.
- **Why:** Returning full user objects often leaks password hashes, internal notes, or MFA secrets in browser network tabs (`API3:2023`).
- **Ref:** `API3:2023` · `ASVS V14` · `CWE-213`
- **Verify:** Confirm responses use explicit output schemas (serializers with field allowlists, DTOs, `response_model`) rather than `to_dict()`, `toJSON()`, or `SELECT *` passthrough of ORM entities. Hashes, tokens, MFA secrets, internal notes, and other users' data never appear.

**DATA-04 — Encryption at Rest for Regulated Stores**
- **Check:** New storage buckets, caches, and database volumes holding sensitive data enforce encryption at rest.
- **Why:** Unencrypted snapshots, read replicas, and backups outlive application-level access controls.
- **Ref:** `A04:2025` · `ASVS V14` · `CWE-311`
- **Verify:** For new buckets, volumes, databases, caches, queues, and backups defined in IaC, confirm encryption at rest is enabled, with customer-managed keys where policy requires them. For highly sensitive fields, consider application-level encryption.

**DATA-05 — Approved Third-Party and LLM Data Egress**
- **Check:** Personal data, customer source code, and confidential records are never transmitted to external analytics trackers or third-party LLM prompts without documented privacy approval and zero-data-retention agreements.
- **Why:** Every external API call establishes a new sub-processor boundary and potential training-data leak.
- **Ref:** `ASVS V14`
- **Verify:** Flag new calls to analytics, telemetry, and error-tracking SDKs and to LLM or AI APIs that send personal data, customer content, secrets, or source code. List what each call sends and to whom, check for redaction before egress, and record approval and zero-data-retention terms as `needs_validation` unless the repository documents them. If model output reaches a sink, review that sink under INJECTION.

## Review moves (apply across the above)

- For each `try/catch` near a security decision, ask what happens on exception, on timeout, and on a malformed response.
- Follow each new field from column to model, serializer, API response, logs, analytics, LLM prompts, and backups.
- For LLM calls, list exactly what enters the prompt (user content, other tenants' data, secrets, source code) and whether the output is trusted later.
- Compare production and development profiles for error verbosity and log levels.

## Validation rules (apply before reporting ANY finding here)

1. Error disclosure: show which sensitive detail reaches an untrusted client in a production profile. Framework or version names alone are `low`.
2. Fail-open: show the exception path and the access it grants.
3. Logging: show the sensitive value, the log sink, and who can read that sink.
4. Classification, retention, and egress approvals are human decisions. Record `needs_validation` or a `data_governance` or `data_egress` human_review question instead of deciding.
5. Calibrate: fail-open authentication or authorization is `high`; secrets in logs are `medium` or `high` depending on readers and scope; verbose errors are `low` or `medium`.
