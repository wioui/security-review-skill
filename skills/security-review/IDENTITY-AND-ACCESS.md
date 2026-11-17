# Identity and Access Review

#### When to use this file

Use this file when the diff adds or changes routes, controllers, resolvers, or RPC handlers; login, recovery, or MFA flows; credential handling; permission checks; lookups by identifier; tenant or owner scoping; background consumers that act on IDs; cookie-authenticated mutations; session configuration; or token issuance and verification.

It covers three domains: `AUTHN` (A07:2025, ASVS V6), `AUTHZ` (A01:2025, ASVS V8), and `SESSION` (ASVS V7 and V9, with cookie attributes in V3). Identity and access boundaries account for more than a third of the ASVS 5.0 requirements and are the highest-impact area of a security review. Use [INPUT-API-AND-FILES.md](INPUT-API-AND-FILES.md) for identifiers nested in API payloads (API-02) and mass assignment (API-03).

When `AUTHZ` is active, review it before every other domain.

## Core discipline (include in every reviewer prompt for this file)

```
- A role check is not an ownership check. "Caller has role user" says nothing about whether the caller owns invoice 4812 or belongs to tenant acme-corp.
- Owner and tenant identity come from the verified server-side session or token claims, never from the body, query string, path, or headers.
- Authentication is on by default. Every public route is an explicit, documented exception.
- Enforce permissions in the service function that performs the action. Route middleware alone misses GraphQL, CLI, RPC, worker, and webhook entry points.
- Compare every sibling path to the same data: versions, bulk and export endpoints, write paths, background jobs. Require equivalent controls, not merely present ones.
- A gateway, identity provider, or row-level security policy that the repository does not contain is unknown, not present. Use needs_validation when it is decisive.
```

## AUTHN — Authentication · A07:2025 · ASVS V6 (subagent_type: `general`)

Apply whenever the diff introduces routes, modifies login flows, handles credentials, or touches account recovery. Cheat sheets: Authentication, Password Storage, Multifactor Authentication, Forgot Password, Credential Stuffing Prevention.

**AUTHN-01 — Default-Authenticated Routing**
- **Check:** New routes require authentication by default, and any public endpoint uses an explicit, documented opt-out decorator.
- **Why:** A forgotten route annotation silently exposes internal handlers to unauthenticated callers.
- **Ref:** `A07:2025` · `ASVS V6` · `CWE-306`
- **Verify:** List every route, controller, resolver, and RPC method the diff registers. The guard must come from a default (global middleware, base class, router-level dependency) rather than a per-route decorator that can be forgotten. Every public route carries an explicit opt-out (`@public`, `[AllowAnonymous]`, `permitAll()`, `security: []`) and a reason in the PR description.

**AUTHN-02 — Standardized Authentication Libraries**
- **Check:** Identity verification delegates to an established framework or identity provider rather than custom authentication logic.
- **Why:** Hand-rolled authentication routines routinely reintroduce timing leaks, parsing flaws, and edge-case bypasses solved years ago in vetted libraries.
- **Ref:** `ASVS V6`
- **Verify:** Flag new code that parses credentials, compares passwords or tokens with `==`, issues sessions, or verifies signatures by hand. Expect calls into the framework or identity-provider SDK (Django auth, Spring Security, Passport, Auth.js, Devise, ASP.NET Core Identity, an OIDC client) instead.

**AUTHN-03 — Memory-Hard Password Hashing**
- **Check:** Passwords use `Argon2id`, `bcrypt`, or `scrypt` configured with current work factors.
- **Why:** Fast general-purpose digests such as `SHA-256` collapse rapidly under offline GPU cracking.
- **Ref:** `A04:2025` · `ASVS V11` · `CWE-916`
- **Verify:** Find where passwords are hashed and compared. Accept Argon2id (OWASP baseline: 19 MiB memory, 2 iterations, parallelism 1), bcrypt (cost 10 or more), or scrypt (N=2^17, r=8, p=1) with the library's constant-time verify. Flag `sha256(password)`, MD5, unsalted or single-iteration digests, and lowered cost parameters.

**AUTHN-04 — Brute-Force Rate Limiting**
- **Check:** Login, password reset, and Multi-Factor Authentication (MFA) verification endpoints enforce strict per-account and per-IP rate limits.
- **Why:** Unthrottled authentication endpoints enable automated credential stuffing and six-digit code exhaustion.
- **Ref:** `A07:2025` · `ASVS V6` · `CWE-307`
- **Verify:** For each login, registration, reset, OTP, MFA, and token endpoint the diff touches, find the limiter (decorator, middleware, or gateway configuration in the repository) and confirm it keys on both the account identifier and the client IP. A limiter on the web login but not on its API or mobile twin fails.

**AUTHN-05 — Enforced Multi-Step MFA State**
- **Check:** MFA verification steps cannot be bypassed by invoking downstream authenticated endpoints directly.
- **Why:** Failing to track partial authentication state server-side lets attackers skip the second factor entirely.
- **Ref:** `A07:2025` · `ASVS V6` · `CWE-287` · `CWE-288`
- **Verify:** Trace the session after password verification. It must carry a partial-authentication marker (for example `mfa_pending`) that every protected endpoint rejects until the second factor succeeds. Ask: what happens if the client calls a protected endpoint with the post-password session?

**AUTHN-06 — Short-Lived Single-Use Reset Tokens**
- **Check:** Password recovery tokens come from a cryptographic generator, expire within minutes, and invalidate immediately upon single use.
- **Why:** Long-lived or reusable recovery tokens grant persistent account takeover paths.
- **Ref:** `ASVS V6` · `CWE-640`
- **Verify:** Confirm tokens come from `secrets.token_urlsafe`, `crypto.randomBytes`, or an equivalent CSPRNG (128 bits or more), are stored hashed, expire in minutes, are bound to one account, and are invalidated on use and on password change. Flag tokens derived from user IDs, emails, timestamps, or `uuid1`.

## AUTHZ — Authorization and Multi-Tenant Isolation · A01:2025 · ASVS V8 (subagent_type: `general`)

Authorization receives the deepest scrutiny because Broken Access Control (A01:2025) produces the highest volume of severe production breaches, and regex scanners cannot express ownership. In the Moltbook breach, missing row-level security exposed 1.5 million API keys: functional queries without object-level and tenant-level scoping turn ordinary API credentials into full-database read and write access. Cheat sheets: Authorization, Insecure Direct Object Reference Prevention, Multi Tenant Security, Cross-Site Request Forgery Prevention.

### Function-level access

**AUTHZ-01 — Server-Side Action Enforcement**
- **Check:** Every new route, controller method, and GraphQL resolver executes an explicit server-side permission check.
- **Why:** Hiding administrative buttons in frontend code never stops direct HTTP requests.
- **Ref:** `A01:2025` · `ASVS V8` · `CWE-862`
- **Verify:** For each new route, controller method, resolver, RPC method, or admin action, cite the permission check that runs on the server before the action. Hidden buttons, frontend feature flags, and disabled form fields are not checks.

**AUTHZ-02 — Deny-by-Default Policy**
- **Check:** Access control evaluators reject requests whenever no explicit allow rule matches.
- **Why:** Allow-by-default logic converts every unmapped route or newly added action into an unauthorized exposure.
- **Ref:** `A01:2025` · `ASVS V8`
- **Verify:** Read the policy evaluator or permission map the diff extends. A new action or route with no rule must be denied. Flag `default: allow`, fall-through `return True`, empty role lists treated as "everyone", and catch-all `permitAll()` rules.

**AUTHZ-03 — Service-Layer Role Checks**
- **Check:** Privileged operations verify caller permissions inside the core service function rather than relying solely on route middleware for one HTTP path.
- **Why:** Secondary entry points such as GraphQL mutations, CLI jobs, or internal RPCs frequently invoke the same service method without the original route middleware.
- **Ref:** `A01:2025` · `CWE-285`
- **Verify:** Find every caller of each service function the diff adds or changes (`git grep -n '<symbol>' <head>`): routes, resolvers, CLI commands, jobs, RPC handlers, admin tools. If the permission check lives only in one route's middleware, the other callers fail this check.

### Object-level and tenant-level access

**AUTHZ-04 — Caller-Scoped Object Lookups**
- **Check:** Queries fetching records by primary key constrain results to the authenticated owner (for example, `WHERE id = $1 AND owner_id = $2`).
- **Why:** Fetching by primary key alone creates an Insecure Direct Object Reference (IDOR).
- **Ref:** `A01:2025` · `ASVS V8` · `CWE-639`
- **Verify:** Trace every lookup by identifier (`get`, `find_by_id`, `findUnique`, `filter(id=...)`, `WHERE id = ?`) to its predicate. It must include the owner or tenant column bound to the authenticated principal, or be followed by an explicit ownership check before any data leaves the function.

**AUTHZ-05 — Session-Derived Tenant Context**
- **Check:** Multi-tenant queries extract `tenant_id` strictly from the verified server-side session or token claims, never from request bodies, query strings, or URL headers.
- **Why:** Trusting a client-supplied tenant identifier lets one customer read or mutate another organization's records.
- **Ref:** `A01:2025` · `ASVS V8` · `CWE-639`
- **Verify:** For each changed query, find where `tenant_id`, `org_id`, `account_id`, or `workspace_id` comes from. Accept only the verified session, token claims, or a server-side membership lookup. Flag body fields, query strings, path parameters, and headers such as `X-Tenant-ID` unless the value is checked against the caller's memberships.

**AUTHZ-06 — Scoped Bulk, Search, and Export Queries**
- **Check:** Collection endpoints, search indexes, and CSV/PDF export handlers apply identical tenant and ownership filters.
- **Why:** Unscoped bulk endpoints exfiltrate entire tables in a single call rather than one row at a time.
- **Ref:** `A01:2025` · `ASVS V8`
- **Verify:** Review list, search, count, aggregate, report, and export paths in the diff. Each applies the same tenant and ownership filter as the single-record path, including search-index queries, cached results, and files generated asynchronously.

**AUTHZ-07 — Write-Path Ownership Checks**
- **Check:** `UPDATE`, `PATCH`, and `DELETE` mutations verify record ownership just as strictly as `GET` handlers.
- **Why:** Write-side IDOR flaws allow attackers to corrupt or destroy another tenant's data.
- **Ref:** `A01:2025` · `CWE-863`
- **Verify:** For every update, delete, upsert, or bulk mutation, confirm the ownership predicate sits in the write statement itself (`UPDATE ... WHERE id = $1 AND tenant_id = $2`) or is verified on a record fetched and locked in the same transaction.

**AUTHZ-08 — Asynchronous Consumer Re-Verification**
- **Check:** Background workers, queue consumers, and webhook processors re-verify tenant and object ownership before acting on queued IDs.
- **Why:** Asynchronous jobs execute outside the HTTP middleware context and may process stale or tampered job payloads.
- **Ref:** `A01:2025` · `CWE-863`
- **Verify:** Trace job payloads from enqueue to consumer. The consumer must reload the record scoped to a tenant carried in a trusted envelope and re-check permissions. A bare `record_id` in a payload is not authority. When the consumer lives in another repository, record needs_validation.

**AUTHZ-09 — CSRF Defences on Cookie-Authenticated Mutations**
- **Check:** State-changing endpoints accepting browser cookies enforce Cross-Site Request Forgery (CSRF) tokens or strict `SameSite` policies.
- **Why:** Browsers automatically attach session cookies to cross-origin forged requests unless explicitly restricted.
- **Ref:** `A01:2025` · `ASVS V3` · `CWE-352`
- **Verify:** For cookie-authenticated state changes (POST, PUT, PATCH, DELETE, and any GET that mutates), confirm CSRF middleware is enabled and not bypassed (`@csrf_exempt`, `csrf: false`, ignored paths), or that the session cookie is `SameSite=Strict` or `Lax` and no state changes on GET.

Compare an unscoped AI-generated endpoint with a session-scoped one:

```python
# RED FLAG IN PR DIFF: trusts a client-supplied tenant_id and performs an unscoped ID lookup
@router.get("/invoices/{invoice_id}")
async def get_invoice_vulnerable(invoice_id: int, tenant_id: str, db: Session = Depends(get_db)):
    # Vulnerable to IDOR and cross-tenant bypass (CWE-639 / A01:2025)
    return db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.tenant_id == tenant_id
    ).first()

# SECURE PATTERN: binds both user_id and tenant_id from the verified session context
@router.get("/invoices/{invoice_id}")
async def get_invoice_secure(
    invoice_id: int,
    principal: AuthPrincipal = Depends(require_authenticated_principal),
    db: Session = Depends(get_db),
):
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.tenant_id == principal.tenant_id,
        Invoice.owner_id == principal.user_id,
    ).one_or_none()
    if invoice is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return InvoiceReadSchema.model_validate(invoice)
```

## SESSION — Sessions and Self-Contained Tokens · ASVS V7 · V9 · V3 (subagent_type: `general`)

In ASVS 5.0, stateful sessions live in V7, JSON Web Tokens and other self-contained tokens in V9, OAuth and OIDC in V10, and cookie attributes are reinforced in V3. Cheat sheets: Session Management, JSON Web Token, OAuth2, Cookie Theft Mitigation.

**SESSION-01 — Session Identifier Rotation**
- **Check:** Server-side session identifiers regenerate upon login and upon any privilege elevation.
- **Why:** Retaining a pre-authentication session ID enables session fixation attacks.
- **Ref:** `A07:2025` · `ASVS V7` · `CWE-384`
- **Verify:** In login, step-up, impersonation, and role-change handlers, expect `session.regenerate()`, `request.session.cycle_key()`, `changeSessionId()`, or the framework equivalent after authentication succeeds.

**SESSION-02 — Hardened Cookie Attributes**
- **Check:** Session cookies set `HttpOnly`, `Secure`, and an explicit `SameSite=Lax` or `SameSite=Strict` attribute.
- **Why:** Missing flags expose session cookies to Cross-Site Scripting (XSS) theft and cross-origin request attachment.
- **Ref:** `ASVS V3` · `ASVS V7` · `CWE-1004` · `CWE-614` · `CWE-1275`
- **Verify:** Inspect every `Set-Cookie`, `res.cookie`, `response.set_cookie`, and session-cookie setting the diff adds or changes. Session and authentication cookies need `HttpOnly`, `Secure`, and an explicit `SameSite`. Flag `SameSite=None` without a documented cross-site need, and production profiles that turn the flags off.

**SESSION-03 — Strict JWT Cryptographic and Claim Validation**
- **Check:** JWT verifiers enforce cryptographic signature checks against a pinned algorithm allowlist, reject `alg: none`, and validate `exp`, `aud`, and `iss` claims.
- **Why:** Skipping algorithm allowlists or audience checks allows attackers to forge claims or replay tokens minted for another service.
- **Ref:** `ASVS V9` · `CWE-347`
- **Verify:** Find every `decode` and `verify` call. Require an explicit `algorithms=[...]` allowlist, a key that matches the algorithm family (never HMAC verification with an RSA public key), and checks on `exp`, `aud`, and `iss` (plus `nbf` when used). Flag `verify=False`, `options={"verify_signature": False}`, decode-without-verify helpers, and `none` in the allowlist.

**SESSION-04 — Zero Tokens in URLs or Logs**
- **Check:** Bearer tokens, session IDs, and OAuth codes never travel in URL query parameters or application log payloads.
- **Why:** Query strings persist in browser history, proxy access logs, and `Referer` headers.
- **Ref:** `ASVS V7` · `CWE-598`
- **Verify:** Search added redirects, links, and client calls for tokens in query strings (`?token=`, `?access_token=`, `?session=`, `?jwt=`), and logging statements that print headers, cookies, or full URLs carrying codes.

**SESSION-05 — Server-Side Session Revocation**
- **Check:** Logout, password reset, and account suspension immediately invalidate active server-side sessions.
- **Why:** Stolen session credentials remain usable until natural expiry if logout only clears browser storage.
- **Ref:** `ASVS V7` · `CWE-613`
- **Verify:** Confirm logout, password change or reset, MFA reset, and account suspension delete or invalidate server-side sessions and refresh tokens (session-store deletion, token-version bump, or denylist), not only client storage.

**SESSION-06 — Refresh Token Rotation and Reuse Detection**
- **Check:** Refresh tokens rotate on every exchange, and presenting a previously consumed refresh token revokes the entire token family.
- **Why:** Rotation and reuse detection bound the blast radius of a compromised long-lived refresh token.
- **Ref:** `ASVS V9` · `ASVS V10`
- **Verify:** In refresh handlers, confirm each exchange issues a new refresh token, marks the old one consumed atomically, and, on reuse of a consumed token, revokes the whole family and forces re-authentication.

## Review moves (apply across the above)

- Draw the path for every new entry point: route, middleware and decorators, handler, service, query. Mark where identity is established and where it scopes data.
- Run the two-tenant thought experiment: user A in tenant X, user B in tenant Y. For each changed query, what does B receive when sending A's identifiers, with and without a forged tenant parameter?
- Search for every other caller of each changed service function and compare their checks: resolvers, CLI commands, jobs, RPC handlers, admin tools.
- For authentication changes, write the state machine (anonymous, password verified, MFA verified, session) and confirm no later endpoint accepts an earlier state.
- Read the framework version pinned in the lockfile before asserting what the framework does by default.

## Validation rules (apply before reporting ANY finding here)

1. Name the principal (role and tenant), the foreign object or tenant, the entry point, and the unauthorized read or write.
2. Cite the missing predicate or check at `file:line` and show that no global middleware, base class, ORM default scope, or row-level security policy in the repository already enforces it.
3. An existing role check that does not bind ownership fails AUTHZ-04, AUTHZ-05, or AUTHZ-07. It never satisfies them.
4. Rate limiting, MFA, or authentication that may be enforced by a gateway or identity provider not present in the repository is `needs_validation` when it is decisive.
5. Calibrate: authentication bypass and cross-tenant read or write of sensitive data are `high` (`critical` when unauthenticated and broad). A missing hardening layer with no reachable bypass is `hardening`.
