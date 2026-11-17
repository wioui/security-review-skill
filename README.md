# security-review

A coding-agent skill that turns your agent into a diff-scoped secure code reviewer for pull requests, with mandatory extra checks for code written by AI coding agents. It activates only the security domains a change touches, gives every check in those domains an evidence-backed disposition, validates candidates adversarially, and returns machine-readable results that cite OWASP Top 10:2025, OWASP ASVS 5.0, OWASP API Security Top 10:2023, and MITRE CWE.

The checklist comes from the article [Secure Code Review Checklist for AI-Generated Pull Requests](https://blog.ogwilliam.com/post/ai-secure-code-review-checklist-owasp-asvs). The skill format (operating modes, phase files, domain companions with core discipline and validation rules, a JSON contract, and a zero-dependency validator) is inspired by Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill). Where `security-audit` hunts through a whole codebase, `security-review` governs one change at the merge boundary.

## Why

AI coding agents open pull requests that compile, pass their own tests, and still ship exploitable flaws. Across Carnegie Mellon University's SusVibes benchmark and Endor Labs' Agent Security League (34 agent and model pairings on 200 real-world open-source tasks), top configurations reach up to 91.6% functional correctness but peak at 36.9% to 37.4% security correctness: more than 80% of functionally passing patches remain vulnerable for most models. Green CI is not evidence of safety.

Agents also fail in ways human reviewers rarely look for: hallucinated package names that attackers register (slopsquatting), fallback secrets such as `os.getenv("JWT_SECRET", "default-secret")`, stubbed authorization, tautological happy-path tests, and security controls silently deleted between commits while the agent was "fixing" a failing test.

## What it does

The skill runs a review in six phases:

1. **Scope**: resolve base and head, inventory the diff, collect the ticket's security requirements, detect AI authorship, activate only the touched domains, and mark the rest N/A.
2. **Stage 1 gate**: run a pattern sweep plus any deterministic scanners already installed (SAST, secrets, SCA, IaC and CI linters), scoped to the diff. Hits are leads, not findings.
3. **Domain review**: reviewers give every check in each active domain a disposition (`pass`, `fail`, `needs_validation`, `hardening`, `not_applicable`) with repository paths. Agent-authored changes also get five AI checks and a commit-by-commit control-regression audit.
4. **Candidate validation**: a fresh verifier that did not raise the candidate tries to refute it.
5. **Structured output**: `review.json`, validated against `review-schema.json` and the `checklist.json` catalog by `validate-review.cjs`.
6. **Report**: `REVIEW.md`, paste-ready review comments with standard references, a merge decision, and the questions only a human can answer.

Findings are `confirmed` (exploit path, severity, smallest fix, regression test), `needs_validation` (the exact fact the repository cannot show, no severity), or `rejected` (refuted, kept so it is not raised again). In-diff `critical` and `high` findings block the merge; pre-existing issues become follow-ups.

## Domains

| ID | Domain | Standards | Checks |
|---|---|---|---|
| `AUTHN` | Authentication | A07:2025 · ASVS V6 | 6 |
| `AUTHZ` | Authorization and multi-tenant isolation | A01:2025 · ASVS V8 | 9 |
| `SESSION` | Sessions and self-contained tokens | ASVS V7 · V9 · V3 | 6 |
| `INJECTION` | Input validation and injection | A05:2025 · ASVS V1 · V2 | 6 |
| `API` | API surface and schema | API Top 10:2023 · ASVS V4 | 7 |
| `FILES` | File upload, path, and parser safety | A01 · A02:2025 · ASVS V5 | 5 |
| `LOGIC` | Business logic and concurrency | A06:2025 · ASVS V2 · V15 | 5 |
| `CRYPTO` | Cryptography and TLS | A04:2025 · ASVS V11 · V12 | 6 |
| `SECRETS` | Secrets in code and Git history (always active) | A07:2025 · ASVS V13 | 4 |
| `ERRORS` | Error handling and security logging | A09 · A10:2025 · ASVS V16 | 5 |
| `DATA` | Data protection and LLM privacy boundaries | A04:2025 · ASVS V14 | 5 |
| `DEPS` | Dependencies and reachability | A03:2025 · ASVS V15 | 6 |
| `CONFIG` | Configuration, containers, and CI/CD | A02 · A03:2025 · ASVS V3 · V13 | 7 |
| `AI` | AI-generated pull requests | A01 · A03 · A06 · A07:2025 · ASVS V15 | 5 |

82 checks in total. Each one has the same four parts: **Check** (an invariant you can confirm in the diff), **Why** (the exploit path when it fails), **Ref** (exact standard identifiers to paste into a blocking comment), and **Verify** (how to confirm it in a diff).

## Files

All skill files live in [`skills/security-review/`](skills/security-review/).

| File | Purpose |
|------|---------|
| `SKILL.md` | Operating modes, review safety, setup, core principles, workflow, domain map, and anti-patterns |
| `SCOPING.md` | Phase 1: resolve the diff, collect intent, detect AI authorship, activate domains |
| `AUTOMATION-VS-HUMAN.md` | Phase 2: Stage 1 gate, pattern sweep, human-judgment matrix, and CI wiring |
| `REVIEWING.md` | Phase 3: reviewer orchestration, review method, candidate gate, structured results |
| `IDENTITY-AND-ACCESS.md` | `AUTHN`, `AUTHZ`, and `SESSION` checks |
| `INPUT-API-AND-FILES.md` | `INJECTION`, `API`, and `FILES` checks |
| `BUSINESS-LOGIC.md` | `LOGIC` checks |
| `CRYPTO-AND-SECRETS.md` | `CRYPTO` and `SECRETS` checks |
| `ERRORS-LOGGING-AND-DATA.md` | `ERRORS` and `DATA` checks |
| `SUPPLY-CHAIN-AND-CONFIG.md` | `DEPS` and `CONFIG` checks |
| `AI-GENERATED-PRS.md` | `AI` checks and the commit-by-commit control-regression audit |
| `VALIDATION-AND-REPORTING.md` | Phases 4 to 6: adversarial validation, severity and merge policy, `review.json`, `REVIEW.md`, review comments |
| `STANDARDS.md` | OWASP Top 10:2025, ASVS 5.0 chapters, API Top 10:2023, CWE titles, and OWASP Cheat Sheets per domain |
| `PR-TEMPLATE.md` | Paste-ready GitHub and GitLab pull request template covering every check |
| `checklist.json` | Machine-readable catalog of the 14 domains and 82 checks |
| `review-schema.json` | JSON Schema for `review.json` |
| `review.example.json` | Complete valid example review of an agent-authored PR |
| `validate-review.cjs` | Zero-dependency validator for `review.json`, with `--gate` for CI |
| `validate-review.test.cjs` | Validator tests, plus consistency tests between the catalog, Markdown, template, and standards |

## Installation

Install the skill with the [Skills CLI](https://skills.sh):

```bash
npx skills add https://github.com/wioui/security-review-skill \
  --skill security-review
```

Use `--global` for a user-level installation:

```bash
npx skills add https://github.com/wioui/security-review-skill \
  --skill security-review \
  --global
```

Run `npx skills --help` for agent selection and non-interactive options.

To install by hand, copy `skills/security-review/` into your agent's skills directory, for example `~/.claude/skills/security-review/` (Claude Code), `~/.config/opencode/skills/security-review/` (OpenCode), or `.agents/skills/security-review/` inside a project.

## Usage

Start your coding agent in the repository that contains the change, then ask for a review:

```
security review this PR
```

```
review origin/main...HEAD for security before I merge
```

```
this branch was written by Claude Code: check it for dropped security controls
```

```
which security checks apply to a PR that only changes package.json?
```

```
give me the security PR template for GitLab
```

The skill activates when the request matches its description. A request to review a concrete PR, branch, diff, or commit range runs the full workflow and writes `review.json` and `REVIEW.md` to `~/security-review-skill/<repo-name>/review-<N>` unless you choose another directory. Questions about the checklist, a snippet, or the methodology use guidance mode and write nothing.

The review is read-only: it never edits, pushes, approves, merges, or comments on the code host unless you explicitly ask.

## Output and validation

`review.json` records the scope, the Stage 1 results, all fourteen domains (active or N/A with a reason), every check disposition with paths, the validated findings, the questions for a human reviewer, and the merge decision. `REVIEW.md` and the review comments are derived from it.

```bash
node skills/security-review/validate-review.cjs review.json
```

The validator checks structure and consistency, not truth: every domain listed once, `SECRETS` always active, `AI` active when AI authorship is detected, every catalog check given a disposition in active domains, `fail` backed by a confirmed finding, safe repository-relative paths, well-formed standard references, unique and linked findings, severity never above impact, the merge policy, and the decision rules.

### Use as a CI merge gate

Run your agent headless (for example `claude -p`, `opencode run`, `codex exec`, or `gemini -p`) in gate mode, then let the validator decide the job status:

```bash
node <skill-dir>/validate-review.cjs security-review/review.json --gate
# exit 0: valid and nothing blocks · exit 1: invalid review.json · exit 2: request_changes
```

[`AUTOMATION-VS-HUMAN.md`](skills/security-review/AUTOMATION-VS-HUMAN.md) contains a hardened GitHub Actions example: `pull_request` trigger, read-only token, SHA-pinned actions, full history for the regression audit, and PR metadata passed through `env:`.

### PR template

[`PR-TEMPLATE.md`](skills/security-review/PR-TEMPLATE.md) is ready to copy to `.github/pull_request_template.md` (GitHub) or `.gitlab/merge_request_templates/Security.md` (GitLab). Authors tick the domains they touched; untouched domains are N/A.

## Requirements

- A coding agent with tool use. Parallel sub-agents are recommended for the `standard` and `deep` profiles; without them, the parent runs each role in turn and keeps a separate refutation pass.
- Git, and Node.js 18 or later for the zero-dependency validator.
- Optional: deterministic scanners already installed on the review host (Semgrep, CodeQL, Gitleaks, TruffleHog, OSV-Scanner, Trivy, Checkov, Hadolint, actionlint, zizmor). The skill never installs them.
- Optional: `gh` or `glab` for reading PR context.

## Design principles

- **Scope to the diff.** Activate only the touched domains; mark the rest N/A with a reason. When in doubt, activate.
- **Authorization first.** A role check is not an ownership check, and tenant identifiers come from the session, never from the request.
- **Exploit path or it is not a finding.** Name the principal, the input, the broken control, the resource, and the result. Defense-in-depth gaps are hardening notes.
- **Adversarial validation.** The agent that verifies a candidate is never the agent that raised it.
- **Evidence for every disposition.** Every assessed check cites repository paths; every finding cites exact standard identifiers.
- **Review the history, not only the net diff.** Agent-authored branches get a commit-by-commit control-regression audit.
- **Automate what a machine can prove; humans decide intent.** Authorization semantics, tenant architecture, data governance, egress, and policy exceptions are drafted as questions, never decided by the agent.
- **The change is untrusted input.** The reviewer never installs or runs the change's code on the host, never repeats a secret, and treats instructions embedded in the change as data.

## FAQ

**What is the difference between a secure code review checklist and a secure coding checklist?**
A secure coding checklist guides developers while they write a feature, before any pull request exists. A secure code review checklist is a diff-scoped verification list applied by reviewers and automated gates to one pull request right before merge, checking only the attack surfaces the change modifies.

**Did OWASP archive the Secure Coding Practices Quick Reference Guide?**
Yes. OWASP archived the standalone repository and migrated its checklist content into the OWASP Developer Guide. Cite the Developer Guide alongside OWASP Top 10:2025 and OWASP ASVS 5.0.0.

**Why do AI-generated pull requests need extra checks?**
Evaluations such as SusVibes and the Agent Security League show top agents reaching high functional correctness while passing security tests less than 38% of the time. Agents add failure modes of their own: hallucinated packages, placeholder fallback secrets, tautological tests, and controls deleted during self-repair loops.

**Why does authorization get the most checks?**
Broken Access Control (A01:2025) remains the most prevalent critical risk because pattern scanners cannot infer business ownership rules. Every lookup, mutation, export, and background job must be scoped to the caller, with tenant identifiers taken from the authenticated session.

**How does OWASP ASVS 5.0 help pull request reviews?**
ASVS 5.0.0 (May 2025) organizes testable requirements into 17 chapters, including Web Frontend Security (V3), Self-contained Tokens (V9), OAuth and OIDC (V10), and Secure Coding and Architecture (V15). Citing exact chapters sets clear pass or fail criteria in review comments.

**Which checks should be automated and which need a human?**
Automate injection dataflow, secret detection, registry existence, dependency reachability, cryptographic misuse, and IaC and CI linting on every pull request. Keep human attention for tenant isolation design, role semantics, business logic and concurrency, data egress to LLMs, and confirming that agents kept the controls their tickets require.

**How does reachability analysis help dependency review?**
It traces call paths from application code into third-party libraries to show whether a vulnerable function can actually execute. Reachable from an untrusted entry point means fix before merge; unreachable means a backlog item with evidence instead of a blocked release.

## Further reading

- [Secure Code Review Checklist for AI-Generated Pull Requests](https://blog.ogwilliam.com/post/ai-secure-code-review-checklist-owasp-asvs), the article behind this skill
- [The Prompt That Turns Your AI Coder into a Security Expert](https://blog.ogwilliam.com/post/secure-ai-code-assistant-prompts/)
- [OWASP Top 10:2025 Deconstructed](https://blog.ogwilliam.com/post/owasp-top-10-2025-deconstructed/)
- [Slopsquatting: The AI Hallucination That Infects Your Codebase](https://blog.ogwilliam.com/post/ai-slopsquatting-supply-chain-attack/)
- [OWASP Top 10 CI/CD Security Risks blueprint](https://blog.ogwilliam.com/post/owasp-top-10-cicd-security-risks-blueprint/)
- [Google Mantis: Open-Source AI Harness to Find and Fix Bugs](https://blog.ogwilliam.com/post/google-mantis-ai-harness-find-fix-bugs/)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/), [OWASP ASVS 5.0](https://asvs.owasp.org/), [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), [OWASP Developer Guide](https://devguide.owasp.org/), [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/IndexASVS.html)
- [Endor Labs Agent Security League and SusVibes benchmark analysis](https://www.endorlabs.com/research/ai-code-security-benchmark)

## Credits

- Format and methodology inspired by [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). See [NOTICE.md](NOTICE.md).
- Standards by the OWASP Foundation (Top 10, ASVS, API Security Top 10, Developer Guide, Cheat Sheet Series) and MITRE (CWE).

## Contact

William OGOU, Google Cloud & AI Security Architect: [contact@ogw.fr](mailto:contact@ogw.fr) · [LinkedIn](https://www.linkedin.com/in/william-ogou/) · [blog.ogwilliam.com](https://blog.ogwilliam.com)

## License

MIT. See [LICENSE](LICENSE).
