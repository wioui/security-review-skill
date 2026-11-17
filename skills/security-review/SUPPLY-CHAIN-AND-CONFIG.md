# Supply Chain and Configuration Review

#### When to use this file

Use the `DEPS` part when the diff adds, upgrades, or removes packages in manifests or lockfiles (`package.json`, `pyproject.toml`, `requirements*.txt`, `go.mod`, `pom.xml`, `build.gradle`, `Cargo.toml`, `Gemfile`, `composer.json`), vendors code, or installs packages in Dockerfiles or scripts. Use the `CONFIG` part when the diff touches Dockerfiles, Compose files, Kubernetes manifests, Helm charts, Terraform or OpenTofu, CloudFormation, Pulumi, Bicep, web-server configuration, framework settings and profiles, CORS or security-header middleware, or CI/CD workflows.

It covers `DEPS` (A03:2025, ASVS V15) and `CONFIG` (A02:2025 and A03:2025, ASVS V3 and V13). In OWASP Top 10:2025, Security Misconfiguration and Software Supply Chain Failures sit at #2 and #3, right behind Broken Access Control: modern compromises enter through `package.json`, Terraform, and `.github/workflows/`. For agent-authored changes, also run AI-01 in [AI-GENERATED-PRS.md](AI-GENERATED-PRS.md).

## Core discipline (include in every reviewer prompt for this file)

```
- Configuration and CI definitions are code with authority. Review them like authorization code.
- Every new dependency is new code running with your privileges: verify that it exists, is the intended project, is maintained, and does not run unreviewed install scripts.
- A CVE alert is a lead. Reachability decides whether it blocks the merge.
- Never install, build, or run the change to review it. Lifecycle scripts are part of what you review.
- Default deny for network exposure, IAM, container privileges, and CI token permissions.
```

## DEPS — Software Dependencies and Reachability Analysis · A03:2025 · ASVS V15 (subagent_type: `general`)

Cheat sheets: Vulnerable Dependency Management, Software Supply Chain Security, NPM Security, Dependency Graph SBOM.

**DEPS-01 — Justified and Actively Maintained Packages**
- **Check:** Every newly introduced dependency solves a non-trivial problem and shows active upstream maintenance and security response practices.
- **Why:** Pulling in abandoned micro-packages for five-line helpers leaves unpatched transitive trees in your build.
- **Ref:** `A03:2025` · `ASVS V15` · `CWE-1104`
- **Verify:** For each new direct dependency, compare what it does with the code it replaces, and check its last release, open security issues, maintainer count, and adoption. Flag micro-packages for trivial helpers and packages without releases for more than a year. Whether a dependency is worth its risk is a `dependency_necessity` human_review question.

**DEPS-02 — Verified Exact Package Naming**
- **Check:** Package names and scopes match the canonical upstream project character-for-character with zero near-miss spellings.
- **Why:** Typosquatting packages execute malicious payloads during dependency installation.
- **Ref:** `A03:2025` · `CWE-1357`
- **Verify:** Compare each new name character by character with the intended project: scopes (`@types/...` versus `@type/...`), hyphen and underscore swaps, pluralization, homoglyphs, and `-js`, `-py`, or `-dev` suffixes. Confirm the registry entry links back to the canonical repository.

**DEPS-03 — Committed Lockfiles and Pinned Versions**
- **Check:** Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `poetry.lock`) update in lockstep with manifests using deterministic cryptographic hashes.
- **Why:** Floating version ranges (`*` or unpinned caret ranges without lockfile enforcement) pull freshly compromised upstream releases straight into CI builds.
- **Ref:** `A03:2025` · `ASVS V15`
- **Verify:** Confirm manifest changes ship with lockfile changes in the same PR, lockfiles keep integrity hashes, CI installs from the lockfile (`npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`, `uv sync --locked`, `pip install --require-hashes`, `cargo build --locked`), and no `*`, `latest`, Git branch, or tarball URL references are added. Check that `resolved` registry URLs did not change.

**DEPS-04 — Audited Package Lifecycle Scripts**
- **Check:** Any `preinstall`, `install`, or `postinstall` hooks inside newly added packages have been inspected or disabled by policy.
- **Why:** Malicious lifecycle scripts exfiltrate cloud credentials from developer machines and CI runners the instant `npm install` or `pip install` runs.
- **Ref:** `A03:2025` · `CWE-829`
- **Verify:** For new packages, inspect `preinstall`, `install`, `postinstall`, and `prepare` scripts, `setup.py` code, `build.rs`, and native extensions from registry metadata or the published file listing, without installing. Check whether policy disables install scripts (`ignore-scripts=true`, pnpm `onlyBuiltDependencies`, allowlists).

**DEPS-05 — Policy-Compliant Open-Source Licences**
- **Check:** New direct and transitive dependencies carry licences compatible with organizational legal policy (for example, avoiding unexpected `AGPL-3.0` copyleft obligations in proprietary services).
- **Why:** Licence violations discovered post-release force costly emergency rewrites.
- **Ref:** `ASVS V15`
- **Verify:** Read the licence of each new direct dependency and notable transitive ones from the lockfile diff and compare it with the organization's policy. Strong copyleft in proprietary or network-served code, unknown licences, and missing licences go to the policy owner as `needs_validation`.

**DEPS-06 — Function-Level Reachability Triage for CVEs**
- **Check:** When Software Composition Analysis (SCA) flags a vulnerability in an added or bumped dependency, verify whether application code calls a path reaching the vulnerable function before blocking or waiving the PR.
- **Why:** A parsing bug inside an unused helper module carries fundamentally different risk than a deserialization CVE wired directly into a public HTTP handler.
- **Ref:** `A03:2025` · `CWE-1395`
- **Verify:** For each SCA alert on an added or bumped package, identify the vulnerable function or module from the advisory and search for call paths from application code (direct imports, framework hooks, transitive use). Reachable from an untrusted entry point: block according to severity. Not reachable: backlog follow-up with the call-path evidence. Unknown: `needs_validation`.

## CONFIG — Application Configuration, Containers, and CI/CD Workflows · A02:2025 · A03:2025 · ASVS V3 · V13 (subagent_type: `general`)

Cheat sheets: Infrastructure as Code Security, Docker Security, Kubernetes Security, CI CD Security, GitHub Actions Security, CORS Security, HTTP Headers, Content Security Policy. See also the OWASP Top 10 CI/CD Security Risks.

**CONFIG-01 — Disabled Production Debug Modes**
- **Check:** Framework debug flags (`DEBUG=True`, Werkzeug debugger, Spring Boot Actuator sensitive endpoints, pprof) are strictly off in production profiles.
- **Why:** Exposed debug consoles frequently provide interactive Remote Code Execution out of the box.
- **Ref:** `A02:2025` · `ASVS V13` · `CWE-489`
- **Verify:** Check production profiles and deployment manifests for `DEBUG=True`, `app.run(debug=True)`, the Werkzeug debugger, `management.endpoints.web.exposure.include=*`, exposed `pprof` or `expvar`, public GraphiQL or Swagger UI, and debug switches controllable by request parameters or headers.

**CONFIG-02 — Safe CORS Origin Policies**
- **Check:** Cross-Origin Resource Sharing (CORS) configurations never pair wildcard (`*`) or blindly reflected `Origin` headers with `Access-Control-Allow-Credentials: true`.
- **Why:** Reflecting arbitrary origins alongside credentials lets any malicious webpage read authenticated API responses from the victim's browser.
- **Ref:** `A02:2025` · `ASVS V3` · `CWE-942`
- **Verify:** Inspect CORS configuration the diff touches: no `*` or reflected `Origin` with credentials; allowlists use exact origins (no `endsWith("example.com")` or unanchored regular expressions); the `null` origin is rejected.

**CONFIG-03 — Hardened Browser Security Headers**
- **Check:** Web responses enforce Content Security Policy (`CSP`), HTTP Strict Transport Security (`HSTS`), `X-Content-Type-Options: nosniff`, and `frame-ancestors` restrictions.
- **Why:** Missing response headers leave browsers exposed to XSS gadget execution, MIME sniffing, clickjacking, and TLS stripping.
- **Ref:** `A02:2025` · `ASVS V3`
- **Verify:** When response middleware, web-server configuration, or framework security settings change, confirm CSP (no new `unsafe-inline` or `unsafe-eval` without justification), HSTS, `nosniff`, and `frame-ancestors` (or `X-Frame-Options`) remain in place. Flag removals.

**CONFIG-04 — Private Storage and Restricted Network Ingress in IaC**
- **Check:** Terraform, CloudFormation, and Kubernetes manifests create zero public object-storage buckets and zero `0.0.0.0/0` ingress rules on SSH (`22`), RDP (`3389`), or database ports.
- **Why:** Automated internet scanners discover and ransack public cloud buckets and exposed admin ports within minutes of deployment.
- **Ref:** `A02:2025` · `CWE-732`
- **Verify:** Flag public buckets and objects (`public-read` ACLs, disabled public-access blocks, `allUsers` or `allAuthenticatedUsers` bindings), `0.0.0.0/0` or `::/0` ingress on 22, 3389, database, and admin ports, publicly accessible databases, and `LoadBalancer` or `NodePort` services exposing internal workloads.

**CONFIG-05 — Least-Privilege Cloud IAM Policies**
- **Check:** Identity and Access Management (IAM) roles scope permissions to specific actions and resource ARNs/URIs, avoiding `"Action": "*"` or `"Resource": "*"`.
- **Why:** Wildcard IAM roles convert a single compromised pod into full cloud-account takeover.
- **Ref:** `A01:2025` · `CWE-250`
- **Verify:** Flag `"Action": "*"`, `"Resource": "*"`, `iam:PassRole` on `*`, primitive roles (`roles/owner`, `roles/editor`), `cluster-admin` bindings, and wildcard Kubernetes RBAC verbs or resources. Prefer workload identity over static keys.

**CONFIG-06 — Non-Root Container Execution**
- **Check:** Dockerfiles and Kubernetes `securityContext` specs run processes as an explicit non-root UID, drop `ALL` Linux capabilities, and use minimal base images where feasible.
- **Why:** Running container processes as `UID 0` dramatically lowers the barrier to host kernel escape and lateral movement.
- **Ref:** `A02:2025` · `CWE-250`
- **Verify:** Confirm a numeric non-root `USER` in Dockerfiles, and `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, and `readOnlyRootFilesystem: true` where feasible in pod specs. Flag `privileged: true`, `hostPath`, `hostNetwork`, `hostPID`, Docker socket mounts, and base images referenced by mutable tags instead of digests.

**CONFIG-07 — Minimal CI Token Permissions and Safe Expression Handling**
- **Check:** GitHub Actions and GitLab CI workflows declare explicit `permissions: contents: read` defaults, pin third-party actions to full 40-character commit SHAs, and never interpolate untrusted PR metadata (`${{ github.event.pull_request.title }}` or head branch names) directly into `run:` shell scripts.
- **Why:** Shell injection inside privileged `pull_request_target` workflows exfiltrates repository secrets and write tokens.
- **Ref:** `A03:2025` · `CWE-78`
- **Verify:** In workflow files, confirm least-privilege top-level `permissions:`, third-party actions pinned to full SHAs, no `${{ github.event.* }}` or `github.head_ref` inside `run:` (pass values through `env:`), no checkout or execution of PR head code in `pull_request_target` or `workflow_run` jobs that hold secrets, and `persist-credentials: false` on checkout. In GitLab CI, keep secrets in protected and masked variables, and quote merge-request metadata used in scripts.

A workflow-injection red flag:

```yaml
# RED FLAG: privileged trigger, PR head checked out, PR title interpolated into a shell (CWE-78)
on: pull_request_target
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "Triaging ${{ github.event.pull_request.title }}"
```

The secure version of the same job:

```yaml
# SECURE: unprivileged trigger, read-only token, SHA-pinned action, metadata passed through env
on: pull_request
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-40-character-commit-sha> # vX.Y.Z
        with:
          persist-credentials: false
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "Triaging $PR_TITLE"
```

## Review moves (apply across the above)

- Diff the lockfile, not only the manifest: new transitive packages, changed `resolved` registry URLs, removed integrity hashes, and Git or tarball sources.
- For each new package, read registry metadata (the AI-01 procedure) and its install scripts without installing it.
- For CI changes, list triggers, permissions, secrets, and which code is checked out and executed. Mark every place where untrusted input crosses into a privileged context, including caches and artifacts shared between jobs.
- For IaC, work out the effective exposure: who can reach the resource (network), who can act on it (IAM), and what it stores (encryption).
- For containers, check base-image source and pinning, the runtime user, capabilities, and mounts.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust actor (internet client, fork contributor, package maintainer, tenant), the misconfiguration, and the resulting access: data exposure, code execution in CI, secret exfiltration, or cloud takeover.
2. Check the built-in defaults of the pinned tool or platform version before asserting behavior.
3. Branch protection, environment protection rules, organization policies, registry settings, and cloud organization policies that the repository does not contain are `needs_validation` when decisive.
4. A vulnerable dependency without a reachable call path is a follow-up with evidence, not a blocker.
5. Calibrate: workflow injection that reaches secrets or a write token is `high` or `critical`; a public bucket with sensitive data is `high` or `critical`; missing headers on a static page are `low` or `hardening`.
