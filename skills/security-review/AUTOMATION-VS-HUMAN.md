# Automation vs Human Judgment

### Phase 2: Run the Stage 1 gate, then reserve human attention

Reviewer attention is the scarcest security resource. Do not spend it hunting for `MD5` calls or missing cookie flags that a machine can find; spend it on tenant isolation, business workflows, and whether controls match intent. Pattern-only SAST floods reviewers with false positives and still misses IDOR, because no regular expression can express "this user does not own record 4812". Dataflow-aware SAST and evidence-grounded agent harnesses can move mechanical object-lookup tracing into Stage 1, but no scanner knows whether a customer-support role should read across tenants under your contract terms. Policy, intent, and architecture stay human responsibilities.

## Stage 1: automate on every pull request

Run what is already installed, scoped to the diff. Record each tool in the `stage1` array of `review.json` with status `ran`, `unavailable` (not installed), `skipped` (needs network access or approval), or `failed`. A tool hit is a lead for the mapped checks; it becomes a finding only after the candidate gate in [REVIEWING.md](REVIEWING.md).

| Gate | Checks | Typical tools (only if already installed) |
|---|---|---|
| Injection dataflow: SQLi, command injection, XSS, SSRF, unsafe deserialization | INJECTION-01 to INJECTION-05 | Semgrep with local rules, CodeQL with an existing database, Bandit, gosec, Brakeman |
| Traced unscoped queries: request IDs reaching ORM lookups without owner or tenant joins | AUTHZ-04 to AUTHZ-07, API-02 | Dataflow SAST with custom rules; otherwise the domain reviewer traces them |
| Secrets and history: hardcoded credentials, fallback tokens, `.env` commits anywhere in the branch | SECRETS-01, SECRETS-02, AI-03 | Gitleaks, TruffleHog, detect-secrets |
| Supply chain and reachability: non-existent packages, typosquats, install scripts, reachable CVEs | DEPS-01 to DEPS-06, AI-01 | Registry metadata lookups, OSV-Scanner, Trivy, reachability-capable SCA |
| Cryptographic API misuse: weak ciphers, static nonces, `verify=False` | CRYPTO-01 to CRYPTO-05 | Semgrep or CodeQL crypto rules, Bandit |
| IaC, container, and CI misconfiguration: public buckets, `Action: *`, root containers, workflow injection | CONFIG-01 to CONFIG-07, SECRETS-04 | Checkov, Trivy config, KICS, Hadolint, actionlint, zizmor |
| Token and cookie flags: missing `HttpOnly` or `Secure`, `alg: none`, unverified JWT signatures | SESSION-02, SESSION-03 | Semgrep or CodeQL rules |
| File path and parser sinks: unconfined path joins, Zip Slip, XXE-enabled parsers | FILES-01, FILES-02, FILES-05 | Semgrep, CodeQL |

Safe invocations (adapt to the installed versions):

```sh
semgrep scan --metrics=off --config <local-rules-dir> --baseline-commit <base>
gitleaks git --redact --log-opts="<base>..<head>"     # gitleaks before 8.19: gitleaks detect --redact --log-opts="<base>..<head>"
trufflehog git file://. --since-commit <base> --branch <head> --no-verification
zizmor --offline .github/workflows/
actionlint
hadolint <Dockerfile>
checkov --directory <changed-iac-dir> --compact --quiet
```

- Do not install a tool, pull a container image, or download rules or vulnerability databases without approval. Remote rule packs (`semgrep --config auto`), `npm audit`, `pip-audit`, OSV queries, and database updates contact third parties: ask first, otherwise record the tool as `skipped`.
- Never enable live secret verification: it sends the discovered credential to its provider.
- Scanners that only read files are safe on the host. Anything that resolves, installs, or builds the project is target execution and needs the sandbox described in SKILL.md.

### Pattern sweep (always run)

When no scanner is installed, the pattern sweep is the minimum Stage 1; record it as tool `pattern-sweep`. Search the added lines of the diff, and for AI-02 the removed lines too. Every hit is a lead for the listed checks, never a finding by itself, and some patterns are deliberately noisy.

```sh
# Leads on added lines (shows the diff line, not the file line number)
git diff --unified=0 --no-color <base>...<head> | grep -E '^\+[^+]' | grep -E '<pattern>'
# File:line leads at the head commit, limited to the changed files
git diff -z --name-only --diff-filter=d <base>...<head> | xargs -0 git grep -nE '<pattern>' <head> --
# Controls removed anywhere in the diff (AI-02)
git diff --unified=0 --no-color <base>...<head> | grep -E '^-[^-]' | grep -E '<control-pattern>'
```

Starter patterns (POSIX extended regular expressions, case-sensitive; adapt to the stack):

```text
# INJECTION-01  string-built queries
(execute|query|raw|text)\((f"|f'|`)|\$queryRawUnsafe|Sequelize\.literal|knex\.raw|\.extra\(|\.format\(.*(SELECT|INSERT|UPDATE|DELETE)

# INJECTION-02  unescaped output
dangerouslySetInnerHTML|v-html|innerHTML *=|\|safe|mark_safe|html_safe|Html\.Raw|bypassSecurityTrust|\{\{\{

# INJECTION-03  shell execution
shell *= *True|os\.system\(|os\.popen\(|child_process|execSync\(|Runtime\.getRuntime\(\)\.exec|sh -c

# INJECTION-05  unsafe deserialization
pickle\.loads?\(|dill\.load|joblib\.load|torch\.load\(|yaml\.load\(|ObjectInputStream|XMLDecoder|BinaryFormatter|unserialize\(|Marshal\.load|enableDefaultTyping|TypeNameHandling

# FILES-01, FILES-02, FILES-05  path, archive, and XML sinks
send_file|sendFile|send_from_directory|extractall|ZipFile|tarfile|adm-zip|DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|lxml|minidom

# CRYPTO-02, CRYPTO-03, CRYPTO-04  weak primitives, static IVs, weak randomness
MD5|md5|SHA-?1|sha1|DESede|RC4|ECB|Math\.random|random\.(random|randint|choice)\(|java\.util\.Random|mt_rand|uuid1|(iv|nonce|IV) *= *b?["']

# CRYPTO-05  TLS verification disabled
verify *= *False|rejectUnauthorized *: *false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify *: *true|CERT_NONE|check_hostname *= *False|_create_unverified_context|--insecure|CURLOPT_SSL_VERIFYPEER

# SESSION-02, SESSION-03  cookie flags and JWT verification
set_cookie|res\.cookie|Set-Cookie|[Hh]ttp[Oo]nly *[:=] *[Ff]alse|[Ss]ecure *[:=] *[Ff]alse|[Ss]ame[Ss]ite *[:=] *["']?[Nn]one|verify_signature|algorithms *=|["']none["']|jwt\.decode

# SECRETS-01, CRYPTO-06, AI-03  credentials, keys, and fallback defaults
BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[abpr]-|sk_live_|sk-test-|(password|passwd|secret|token|api_?key) *[:=] *["'][^"']{6,}|getenv\([^)]*,|environ\.get\([^)]*,|process\.env\.[A-Z0-9_]+ *(\|\||\?\?)|changeme|default-secret

# SECRETS-04  build-time secrets
(ARG|ENV) +[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|KEY)|--build-arg +[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|KEY)

# ERRORS-01, ERRORS-02  leaked errors and fail-open handlers
traceback|printStackTrace|str\(e\)|e\.message|except[^:]*: *pass|catch *\([^)]*\) *\{ *\}

# AI-04  stubs and bypasses
TODO|FIXME|HACK|XXX|skip_?auth|SKIP_AUTH|disable_?auth|DISABLE_AUTH|AUTH_ENABLED|csrf_exempt|AllowAnonymous|permitAll|security: *\[\]

# CONFIG-01 to CONFIG-06  debug, CORS, exposure, privileges
DEBUG *= *True|debug *= *True|exposure\.include *= *\*|Access-Control-Allow-Origin|allow_origins|origin *: *true|0\.0\.0\.0/0|::/0|public-read|allUsers|"Action" *: *"\*"|"Resource" *: *"\*"|USER +root|privileged *: *true|allowPrivilegeEscalation *: *true|hostPath|docker\.sock

# CONFIG-07  workflow triggers, interpolation, permissions, unpinned actions
pull_request_target|workflow_run|\$\{\{ *github\.(event\.(pull_request|issue|comment|review|head_commit)|head_ref)|permissions *: *write-all|uses: +[^@ ]+@(v[0-9][^ ]*|[0-9]+(\.[0-9]+)*|main|master)( |$)

# DEPS-04  install-time code
"(pre|post)?install" *:|"prepare" *:|setup\.py|build\.rs
```

The AI-02 control pattern lives in [AI-GENERATED-PRS.md](AI-GENERATED-PRS.md).

## Stage 2: reserve for human judgment

Some decisions depend on business intent, contracts, or policy. The agent finds the evidence and drafts the question; a human decides. Record each question in the `human_review` array of `review.json` with its topic. Never answer these on the human's behalf, and never record a waiver yourself.

| Reserve for human judgment | What the agent contributes | `topic` |
|---|---|---|
| Authorization semantics: whether permission rules match real business roles | New roles, permissions, and cross-tenant capabilities, with the specific question | `authorization_semantics` |
| Multi-tenant architecture: isolation design for shared tables, caches, and queues | Shared keys, caches, queues, and indexes without tenant scoping | `multi_tenant_architecture` |
| Data governance: classifying new sensitive fields and setting retention windows | New sensitive fields and missing retention | `data_governance` |
| Dependency necessity: whether adding a third-party library is worth the risk | What the dependency replaces, its maintenance, and its footprint | `dependency_necessity` |
| Business logic and concurrency: state skipping, negative amounts, race flows | Candidate abuse flows with `file:line` | `business_logic` |
| External and LLM data egress: whether PII or code may cross to a vendor | Each new egress with data categories and destination | `data_egress` |
| Control-regression audit: confirming agents kept the controls tickets require | Controls removed or never implemented, with commits | `control_regression` |
| Policy exceptions: deliberate public routes or waivers | Each exception and whether it is documented | `policy_exception` |

The same division configures CI merge gates: the left column of the first table runs automatically on every PR; the right column above is where reviewers spend their minutes.

## Wiring the gate in CI

Gate mode runs the skill headless and lets `validate-review.cjs --gate` decide the job status: exit 0 when the review is valid and nothing blocks, 1 when `review.json` is invalid, 2 when the decision is `request_changes`.

```yaml
name: security-review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-40-character-commit-sha> # vX.Y.Z
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Security review (headless agent)
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          <agent-cli> "Use the security-review skill in gate mode on $BASE_SHA...$HEAD_SHA. Write review.json and REVIEW.md to ./security-review/."
      - name: Enforce the gate
        run: node <skill-dir>/validate-review.cjs security-review/review.json --gate
```

- Trigger on `pull_request`, not `pull_request_target`, so code from forks never runs with secrets or write tokens.
- Keep `permissions: contents: read`. If results must be posted, do it from a separate job that does not read untrusted code.
- Pin every third-party action to a full 40-character commit SHA.
- Use `fetch-depth: 0` so the review sees every commit on the branch (SECRETS-02, AI-02).
- Pass PR metadata through `env:`, never through `${{ }}` inside `run:`.
- The reviewing agent reads untrusted code and text: give it no write access and no secrets beyond its own model credentials, so a prompt injection in the PR has nothing to steal or change.
