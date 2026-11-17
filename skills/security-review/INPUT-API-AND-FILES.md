# Input, API, and File Review

#### When to use this file

Use this file when untrusted input crosses an application boundary into an interpreter (SQL or NoSQL, shell, template, deserializer), an outbound HTTP client, an API parser or schema, a webhook receiver, a filesystem call, an archive extractor, or an XML parser.

It covers three domains: `INJECTION` (A05:2025, ASVS V1 and V2), `API` (OWASP API Security Top 10:2023, ASVS V4), and `FILES` (A01:2025 and A02:2025, ASVS V5). OWASP Top 10:2025 moved Server-Side Request Forgery (SSRF) under A01:2025 Broken Access Control while keeping injection and XSS under A05:2025. Use [IDENTITY-AND-ACCESS.md](IDENTITY-AND-ACCESS.md) for ownership of the top-level resource and [BUSINESS-LOGIC.md](BUSINESS-LOGIC.md) for domain rules on amounts and workflows.

## Core discipline (include in every reviewer prompt for this file)

```
- Keep structure and data apart: bound parameters, argument arrays, context-aware encoders, schema-validated input objects. Hand-written escaping is a smell, not a control.
- Trace input to the sink across files, including second-order values that are stored safely and reused later, and input carried in field names, keys, headers, and metadata.
- Validate on the server with allowlists. Client-side validation and static types are not controls.
- Every identifier in a request is a claim to authorize: path, query, body, nested arrays, headers.
- Canonicalize, then check, then use the canonical value: paths after resolution, URLs after parsing, hostnames after DNS resolution.
```

## INJECTION — Input Validation and Injection Prevention · A05:2025 · ASVS V1 · V2 (subagent_type: `general`)

Apply whenever user-controlled or external data reaches SQL databases, OS shells, HTML templates, outbound HTTP clients, or object deserializers. Cheat sheets: Query Parameterization, SQL Injection Prevention, Cross Site Scripting Prevention, OS Command Injection Defense, Server Side Request Forgery Prevention, Deserialization, Input Validation.

**INJECTION-01 — Parameterized Queries Only**
- **Check:** Database access uses prepared statements or safe Object-Relational Mapping (ORM) parameter binding with zero string interpolation.
- **Why:** Concatenating untrusted strings into SQL or NoSQL queries allows attackers to rewrite query syntax.
- **Ref:** `A05:2025` · `ASVS V1` · `CWE-89`
- **Verify:** Flag every query built with f-strings, template literals, `+`, `%`, or `.format`, and raw ORM fragments carrying input (`raw()`, `extra()`, `text()`, `$queryRawUnsafe`, `Sequelize.literal`, `knex.raw`). Identifiers such as column names and sort directions cannot be bound and need an allowlist. For NoSQL, reject operator objects from JSON bodies (`$where`, `$ne`, `$regex`).

**INJECTION-02 — Context-Aware Output Encoding**
- **Check:** Dynamic values rendered to browsers use encoding matched to the exact sink context (HTML body, HTML attribute, JavaScript literal, CSS, or URL).
- **Why:** Applying HTML entity encoding inside an inline JavaScript block leaves XSS exploitable.
- **Ref:** `A05:2025` · `ASVS V1` · `CWE-79`
- **Verify:** Check new template output and DOM writes: `|safe`, `mark_safe`, `{{{ }}}`, `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `bypassSecurityTrust*`, `html_safe`, `Html.Raw`. Confirm the encoder matches the sink and that user-supplied URLs reject `javascript:` and `data:` schemes.

**INJECTION-03 — Shell-Free Subprocess Execution**
- **Check:** Subprocess calls pass argument arrays with shell invocation disabled (`shell=False` or `execFile`) or use native language APIs instead of OS commands.
- **Why:** Passing concatenated strings to `/bin/sh -c` turns a single semicolon or subshell token into Remote Code Execution (RCE).
- **Ref:** `A05:2025` · `ASVS V1` · `CWE-78`
- **Verify:** Flag `shell=True`, `os.system`, `os.popen`, `child_process.exec` and `execSync`, `Runtime.exec(String)`, backticks, and `sh -c` with interpolated input. Accept argument arrays (`subprocess.run([...])`, `execFile`, `spawn` without `shell: true`), with `--` before user-supplied arguments where option injection is possible.

**INJECTION-04 — Allowlisted Outbound URL Fetchers**
- **Check:** Server-side HTTP requests driven by user input restrict schemes (`https` only), validate destination hostnames against an allowlist, and block private/link-local IP ranges after DNS resolution.
- **Why:** Unrestricted URL fetchers reach internal microservices and cloud instance metadata endpoints (`169.254.169.254`).
- **Ref:** `A01:2025` · `ASVS V1` · `CWE-918`
- **Verify:** For outbound requests whose URL, host, or path derives from input (webhook targets, link previews, imports, image fetchers, PDF renderers), confirm a scheme allowlist, a host allowlist, an IP check after resolution that blocks loopback, RFC 1918, link-local, and their IPv6 equivalents, re-validation on every redirect, and no forwarding of internal credentials.

**INJECTION-05 — Safe Deserialization Formats**
- **Check:** Untrusted payloads never pass into native object deserializers such as Python `pickle`, Java `ObjectInputStream`, PHP `unserialize()`, or `yaml.load()` without `SafeLoader`.
- **Why:** Gadget chains in native deserializers execute arbitrary code before application validation runs.
- **Ref:** `A08:2025` · `ASVS V1` · `CWE-502`
- **Verify:** Flag `pickle.loads`, `dill`, `joblib.load`, `torch.load` without `weights_only=True`, `yaml.load` without `SafeLoader`, `marshal`, Java `ObjectInputStream` and `XMLDecoder`, .NET `BinaryFormatter`, PHP `unserialize`, Ruby `Marshal.load`, and polymorphic JSON typing (`enableDefaultTyping`, `TypeNameHandling.All`) on data that is not fully trusted, including model files and cache entries.

**INJECTION-06 — Positive Server-Side Input Validation**
- **Check:** Server handlers enforce strict allowlists for data type, byte length, numeric range, and format.
- **Why:** Client-side form validation is bypassed with a single `curl` command.
- **Ref:** `ASVS V2` · `CWE-20`
- **Verify:** Confirm each new handler validates input on the server with a schema or validator (Pydantic, Zod, Joi, Bean Validation, JSON Schema) that enforces type, length, range, format, and enumerations before business logic runs. TypeScript types and frontend form rules alone do not count.

A classic injection red flag you can spot in two seconds inside any Python diff:

```python
# RED FLAG: f-string interpolation directly inside SQL execution (CWE-89)
cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")

# SECURE: driver-level parameter binding separates SQL structure from data
cursor.execute("SELECT * FROM orders WHERE id = %s AND tenant_id = %s", (order_id, tenant_id))
```

## API — API Surface and Schema Security · OWASP API Top 10:2023 · ASVS V4 (subagent_type: `general`)

Apply when reviewing REST, GraphQL, gRPC, or webhook endpoints. Cheat sheets: REST Security, Mass Assignment, GraphQL, gRPC Security, Webhook Security.

**API-01 — Authenticated Internal and Versioned Endpoints**
- **Check:** Legacy routes (`/v1/`) and internal service endpoints enforce authentication alongside primary public routes.
- **Why:** Copied controller versions and "internal" prefixes frequently lose authentication middleware during refactors.
- **Ref:** `API2:2023` · `API9:2023`
- **Verify:** Look for new or copied route groups (`/v1`, `/legacy`, `/internal`, `/admin`, `/debug`, `/_`) and confirm they mount the same authentication middleware as the primary router. Check OpenAPI specifications for operations with `security: []`.

**API-02 — Per-Identifier Object Authorization**
- **Check:** Every resource ID present in path parameters, query filters, and nested JSON arrays undergoes Broken Object Level Authorization (BOLA) verification.
- **Why:** Checking ownership on the parent URL ID while ignoring secondary IDs inside the JSON payload leaks foreign records.
- **Ref:** `API1:2023` · `ASVS V8` · `CWE-639`
- **Verify:** Enumerate every identifier the endpoint accepts: path, query, body, nested arrays (`items[].product_id`, `attachments[].file_id`), and headers. Each one is authorized against the caller, not only the parent resource in the URL.

**API-03 — Explicit Input DTOs Against Mass Assignment**
- **Check:** Request payloads bind to explicit Data Transfer Objects (DTOs) or field allowlists rather than directly mutating ORM entities.
- **Why:** Direct model binding lets callers inject privileged fields such as `role`, `is_admin`, or `plan_tier` (Broken Object Property Level Authorization, or BOPLA).
- **Ref:** `API3:2023` · `ASVS V15` · `CWE-915`
- **Verify:** Flag `Model(**request.json)`, `Object.assign(entity, req.body)`, `entity.update(params)`, `permit!`, entity-bound `@ModelAttribute`, and request bodies spread into ORM `create` or `update`. Expect explicit input schemas; privileged fields (`role`, `is_admin`, `tenant_id`, `owner_id`, `plan_tier`, `balance`, `verified`) are never writable by the caller.

**API-04 — Strict Request Schema Enforcement**
- **Check:** API gateways or framework validators enforce JSON/protobuf schemas and reject unexpected fields or type mismatches.
- **Why:** Unvalidated nested objects trigger type confusion and unhandled downstream exceptions.
- **Ref:** `ASVS V4` · `CWE-20`
- **Verify:** Confirm request schemas reject unknown fields (`extra="forbid"`, `additionalProperties: false`, Zod `.strict()`, `FAIL_ON_UNKNOWN_PROPERTIES`) and type mismatches, and that validation runs before business logic.

**API-05 — Pagination Caps and Cost Throttling**
- **Check:** Collection endpoints enforce a hard maximum page size (`limit <= 100`) and rate limits.
- **Why:** Unbounded `limit=1000000` queries enable denial of service and rapid dataset scraping.
- **Ref:** `API4:2023` · `CWE-770`
- **Verify:** For list endpoints, confirm `limit`, `page_size`, or `first` is clamped on the server with a default, cursors are validated, and expensive operations (search, export, reports, LLM calls) carry rate or cost limits.

**API-06 — GraphQL Depth, Complexity, and Introspection Controls**
- **Check:** GraphQL servers enforce query depth and cost limits and disable schema introspection in production unless intentionally public.
- **Why:** Deeply nested cyclical GraphQL queries exhaust CPU and memory in a single HTTP POST.
- **Ref:** `API4:2023` · `ASVS V4`
- **Verify:** When the GraphQL schema or server configuration changes, confirm a depth limit, complexity or cost analysis, alias and batching limits, timeouts, and introspection disabled in production profiles.

**API-07 — Cryptographic Webhook Signature Verification**
- **Check:** Inbound webhook receivers verify HMAC signatures over the raw request bytes and check timestamp freshness before parsing business logic.
- **Why:** Webhook URLs are publicly reachable endpoints that anyone on the internet can POST forged events to.
- **Ref:** `ASVS V4` · `CWE-345`
- **Verify:** In webhook receivers, confirm the signature is computed over the raw body before JSON parsing, compared in constant time (`hmac.compare_digest`, `crypto.timingSafeEqual`) or through the provider SDK (`stripe.Webhook.construct_event`), with a timestamp tolerance and event-ID replay protection, and with the secret loaded from configuration.

## FILES — File Upload, Path, and Parser Safety · A01:2025 · A02:2025 · ASVS V5 (subagent_type: `general`)

Apply whenever code reads filenames, extracts archives, accepts uploads, or parses XML documents. Cheat sheets: File Upload, Path Traversal Prevention, XML External Entity Prevention, XML Security.

**FILES-01 — Canonicalized Path Confinement**
- **Check:** Filesystem paths derived from external input resolve via `realpath` / `Path.resolve()` and verify that the canonical path starts with the intended base directory.
- **Why:** Unchecked `../` traversal sequences expose `/etc/passwd`, environment files, or application source code.
- **Ref:** `A01:2025` · `ASVS V5` · `CWE-22`
- **Verify:** Trace filenames and paths from input to `open`, `send_file`, `res.sendFile`, `Files.*`, and `fs.*`. Expect canonicalization (`os.path.realpath`, `Path.resolve()`, `path.resolve`, `getCanonicalPath`) followed by a containment check that is not a naive string prefix (`/data/app` also prefixes `/data/app-secrets`; use `is_relative_to`, `path.relative`, or a trailing separator).

**FILES-02 — Zip Slip Archive Extraction Guards**
- **Check:** TAR and ZIP extraction routines resolve each archive entry path and abort if any entry escapes the target extraction folder or introduces symlinks outside the root.
- **Why:** Malicious archive entries containing `../../` overwrite arbitrary files on disk ("Zip Slip").
- **Ref:** `ASVS V5` · `CWE-22`
- **Verify:** For `zipfile`, `tarfile`, `adm-zip`, `unzipper`, `java.util.zip`, and similar, confirm per-entry canonical path checks, rejection of symlinks and hard links, and limits on total size and entry count (archive bombs). In Python, `tarfile.extractall` needs `filter="data"` or explicit member validation.

**FILES-03 — Content-Type and Byte-Size Upload Validation**
- **Check:** File uploads enforce strict byte-size caps and verify magic bytes / MIME content rather than trusting client-supplied filename extensions or `Content-Type` headers.
- **Why:** A polyglot or double-extension file such as `invoice.pdf.php` executes as code if served by an unhardened web server.
- **Ref:** `ASVS V5` · `CWE-434`
- **Verify:** Confirm server-side size caps (framework body limit and per-file limit), content sniffing on magic bytes, an extension allowlist applied to the final stored name, and re-encoding of images where applicable. The client's `Content-Type` and filename are untrusted.

**FILES-04 — Out-of-Webroot Storage with Generated Filenames**
- **Check:** Uploaded blobs land in object storage or a non-executable directory outside the webroot using server-generated UUID keys.
- **Why:** Storing user-named uploads inside static web directories enables direct script execution and file overwrites.
- **Ref:** `ASVS V5` · `CWE-434`
- **Verify:** Confirm uploads go to object storage or a non-executable directory outside the webroot under server-generated keys, and are served with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, or from a separate sandbox domain.

**FILES-05 — Hardened XML Parsers Against XXE**
- **Check:** XML parsers explicitly disable Document Type Definitions (DTDs) and external entity resolution.
- **Why:** Default XML configurations in several ecosystems remain vulnerable to XML External Entity (XXE) local file disclosure and SSRF.
- **Ref:** `A02:2025` · `ASVS V1` · `CWE-611`
- **Verify:** Flag `lxml` parsers without `resolve_entities=False` and `no_network=True`, standard-library XML parsing of untrusted input where `defusedxml` should be used, Java `DocumentBuilderFactory`, `SAXParserFactory`, or `XMLInputFactory` without `disallow-doctype-decl`, .NET `DtdProcessing.Parse`, and PHP `LIBXML_NOENT` or `LIBXML_DTDLOAD`. Include SVG, DOCX, XLSX, and SAML parsing paths.

## Review moves (apply across the above)

- For each new input, write the chain source, transformations, sink, and the control at the sink. Then search for the same sink reached from other entry points (imports, admin tools, workers, webhooks).
- For URL fetchers, test the logic mentally against `http://169.254.169.254/`, `http://[::1]/`, decimal and octal IP encodings, hostnames that resolve to private addresses, and redirects to internal hosts.
- For APIs, enumerate the accepted fields from the server-side schema, not from the client code: the UI constrains users, the API does not.
- For files, consider `../../etc/passwd`, encoded traversal (`..%2f`), absolute paths, `invoice.pdf.php`, symlinks inside archives, and huge or deeply nested archives.

## Validation rules (apply before reporting ANY finding here)

1. Name the attacker-controlled input, the sink at `file:line`, and the concrete result: query rewrite, script execution in another user's browser, command execution, an internal request, or a file read or write.
2. Confirm that no visible layer already neutralizes it: ORM binding, auto-escaping templates, schema validation, an egress proxy configured in the repository.
3. Self-XSS with no cross-user path is not a finding. Reflected XSS that needs a victim's click is.
4. SSRF protection that depends on network egress policy outside the repository is `needs_validation`.
5. Calibrate: unauthenticated RCE, or SQL injection reaching sensitive data, is `critical`; authenticated injection with cross-user impact is `high`; constrained effects are `medium` or lower.
