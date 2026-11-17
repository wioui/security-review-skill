"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const {
  LIMITS,
  collectSchemaErrors,
  isSafeRelativePath,
  loadCatalog,
  loadSchema,
  validateDocument,
} = require("./validate-review.cjs");

const SKILL_DIR = __dirname;
const VALIDATOR = path.join(SKILL_DIR, "validate-review.cjs");
const EXAMPLE = path.join(SKILL_DIR, "review.example.json");
const CLI_TIMEOUT_MS = 15000;

const schema = loadSchema();
const catalog = loadCatalog();

function example() {
  return JSON.parse(fs.readFileSync(EXAMPLE, "utf8"));
}

function cleanReview() {
  const review = example();
  const kept = new Set(review.findings.filter((finding) => finding.verdict === "rejected").map((finding) => finding.fingerprint));
  review.findings = review.findings.filter((finding) => kept.has(finding.fingerprint));
  for (const domain of review.domains) {
    for (const check of domain.checks) {
      check.findings = check.findings.filter((fingerprint) => kept.has(fingerprint));
      if (check.result === "fail" || check.result === "needs_validation") {
        check.result = "pass";
        check.note = "Fixed and re-verified in this fixture.";
      }
    }
  }
  review.decision = "approve";
  return review;
}

function errorsFor(review) {
  return validateDocument(review, schema, catalog);
}

function assertValid(review) {
  const errors = errorsFor(review);
  assert.deepEqual(errors, [], `expected no errors, got:\n${errors.join("\n")}`);
}

function assertError(review, fragment) {
  const errors = errorsFor(review);
  assert.ok(
    errors.some((message) => message.includes(fragment)),
    `expected an error containing ${JSON.stringify(fragment)}, got:\n${errors.join("\n") || "(no errors)"}`,
  );
}

function domainOf(review, id) {
  const domain = review.domains.find((entry) => entry.id === id);
  assert.ok(domain, `fixture has no domain ${id}`);
  return domain;
}

function checkOf(review, id) {
  for (const domain of review.domains) {
    const check = domain.checks.find((entry) => entry.id === id);
    if (check) return check;
  }
  throw new Error(`fixture has no check ${id}`);
}

function findingOf(review, checkId) {
  const finding = review.findings.find((entry) => entry.check_id === checkId);
  assert.ok(finding, `fixture has no finding for ${checkId}`);
  return finding;
}

function readSkillFile(name) {
  return fs.readFileSync(path.join(SKILL_DIR, name), "utf8");
}

function parseMarkdownChecks(markdown) {
  const checks = new Map();
  let current = null;
  for (const line of markdown.split(/\r?\n/)) {
    const header = /^\*\*([A-Z]+-[0-9]{2}) — (.+)\*\*$/.exec(line);
    if (header) {
      assert.ok(!checks.has(header[1]), `duplicate check header ${header[1]}`);
      current = { id: header[1], title: header[2], refs: null, parts: new Set() };
      checks.set(current.id, current);
      continue;
    }
    const part = /^- \*\*(Check|Why|Ref|Verify):\*\* (.+)$/.exec(line);
    if (part && current) {
      current.parts.add(part[1]);
      if (part[1] === "Ref" && current.refs === null) {
        current.refs = part[2].split(" · ").map((ref) => ref.replace(/`/g, "").trim());
      }
    }
  }
  return checks;
}

function runCli(args, contents) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-review-"));
  try {
    const file = path.join(directory, "review.json");
    if (contents !== undefined) fs.writeFileSync(file, contents);
    const result = spawnSync(process.execPath, [VALIDATOR, ...args.map((arg) => (arg === "{file}" ? file : arg))], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    return { status: result.status, output: `${result.stdout}${result.stderr}` };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

// Catalog, schema, and documentation consistency

test("catalog defines 14 domains and 82 checks", () => {
  assert.equal(catalog.domains.length, 14);
  assert.equal(catalog.checkById.size, 82);
});

test("schema uses only keywords the validator interprets", () => {
  assert.deepEqual(collectSchemaErrors(schema), []);
});

test("schema enumerations and patterns match the catalog", () => {
  assert.deepEqual(schema.$defs.domain_id.enum, catalog.domains.map((domain) => domain.id));
  const checkPattern = new RegExp(schema.$defs.check_id.pattern, "u");
  const refPattern = new RegExp(schema.$defs.standard_ref.pattern, "u");
  for (const check of catalog.checkById.values()) {
    assert.ok(checkPattern.test(check.id), `${check.id} does not match the check_id pattern`);
    for (const ref of check.refs) assert.ok(refPattern.test(ref), `${check.id} has a malformed reference ${ref}`);
  }
});

test("the example review is valid", () => {
  assertValid(example());
});

test("every catalog check appears in its companion file with the same title and references", () => {
  for (const domain of catalog.domains) {
    const markdown = readSkillFile(domain.file);
    assert.ok(
      markdown.split(/\r?\n/).some((line) => line.startsWith(`## ${domain.id} — ${domain.name}`)),
      `${domain.file} has no heading for ${domain.id}`,
    );
    const checks = parseMarkdownChecks(markdown);
    for (const check of domain.checks) {
      const parsed = checks.get(check.id);
      assert.ok(parsed, `${domain.file} does not define ${check.id}`);
      assert.equal(parsed.title, check.title, `${check.id} title differs from checklist.json`);
      assert.deepEqual(parsed.refs, check.refs, `${check.id} references differ from checklist.json`);
      assert.deepEqual([...parsed.parts].sort(), ["Check", "Ref", "Verify", "Why"], `${check.id} needs Check, Why, Ref, and Verify`);
    }
  }
});

test("companion files define no checks outside the catalog", () => {
  for (const file of new Set(catalog.domains.map((domain) => domain.file))) {
    for (const id of parseMarkdownChecks(readSkillFile(file)).keys()) {
      const check = catalog.checkById.get(id);
      assert.ok(check, `${file} defines ${id}, which checklist.json does not list`);
      assert.equal(catalog.domainById.get(check.domain).file, file, `${id} is defined in the wrong companion file`);
    }
  }
});

test("the PR template covers every check", () => {
  const template = readSkillFile("PR-TEMPLATE.md");
  for (const id of catalog.checkById.keys()) {
    assert.ok(new RegExp(`(^|[^A-Z])${id}([^0-9]|$)`, "m").test(template), `PR-TEMPLATE.md does not mention ${id}`);
  }
});

test("STANDARDS.md names every reference the catalog uses", () => {
  const standards = readSkillFile("STANDARDS.md");
  for (const check of catalog.checkById.values()) {
    for (const ref of check.refs) {
      const needle = ref.startsWith("CWE-") ? `[${ref}]` : ref.startsWith("ASVS ") ? `| ${ref.slice(5)} |` : `| ${ref} |`;
      assert.ok(standards.includes(needle), `STANDARDS.md does not list ${ref}`);
    }
  }
});

test("SKILL.md front matter follows the skills format", () => {
  const skill = readSkillFile("SKILL.md");
  const match = /^---\nname: ([^\n]+)\ndescription: ([^\n]+)\n---\n/.exec(skill);
  assert.ok(match, "SKILL.md must start with name and description front matter");
  assert.equal(match[1], path.basename(SKILL_DIR));
  assert.match(match[1], /^[a-z0-9-]{1,64}$/);
  assert.ok(match[2].length <= 1024, "description must be at most 1024 characters");
  assert.ok(!/[<>]/.test(match[2]), "description must not contain angle brackets");
});

test("relative Markdown links resolve inside the skill", () => {
  for (const name of fs.readdirSync(SKILL_DIR).filter((file) => file.endsWith(".md"))) {
    for (const [, target] of readSkillFile(name).matchAll(/\]\(([^)#\s]+)(#[^)]*)?\)/g)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      assert.ok(fs.existsSync(path.join(SKILL_DIR, target)), `${name} links to missing ${target}`);
    }
  }
});

// Coverage rules

test("rejects a missing domain", () => {
  const review = example();
  review.domains = review.domains.filter((domain) => domain.id !== "DATA");
  assertError(review, "missing DATA");
});

test("rejects a duplicate domain", () => {
  const review = example();
  review.domains.push(structuredClone(domainOf(review, "DATA")));
  assertError(review, "duplicate domain DATA");
});

test("a not_applicable domain lists no checks", () => {
  const review = example();
  domainOf(review, "DATA").checks.push({ id: "DATA-01", result: "pass", note: "Checked.", paths: ["app/models.py"], findings: [] });
  assertError(review, "a not_applicable domain must not list checks");
});

test("SECRETS is always active", () => {
  const review = example();
  Object.assign(domainOf(review, "SECRETS"), { status: "not_applicable", checks: [] });
  assertError(review, "SECRETS is always active");
});

test("SECRETS-01 and AI-02 cannot be not_applicable", () => {
  for (const id of ["SECRETS-01", "AI-02"]) {
    const review = example();
    Object.assign(checkOf(review, id), { result: "not_applicable", paths: [], findings: [] });
    assertError(review, `${id} must be assessed on every review`);
  }
});

test("AI is active when AI authorship is detected", () => {
  const review = example();
  Object.assign(domainOf(review, "AI"), { status: "not_applicable", checks: [] });
  assertError(review, "AI must be active when review.ai_generated.detected is true");
});

test("detected AI authorship records its signals", () => {
  const review = example();
  review.review.ai_generated.signals = [];
  assertError(review, "record at least one signal");
});

test("an active domain gives every catalog check a disposition", () => {
  const review = example();
  const authn = domainOf(review, "AUTHN");
  authn.checks = authn.checks.filter((check) => check.id !== "AUTHN-06");
  assertError(review, "missing AUTHN-06");
});

test("rejects a check filed under the wrong domain", () => {
  const review = example();
  domainOf(review, "AUTHN").checks.push({ id: "AUTHZ-01", result: "pass", note: "Checked.", paths: ["app/api/invoices.py"], findings: [] });
  assertError(review, "AUTHZ-01 belongs to AUTHZ, not AUTHN");
});

test("a fail check links a confirmed finding", () => {
  const review = example();
  checkOf(review, "AUTHN-02").result = "fail";
  assertError(review, "a fail check must link at least one confirmed finding");
});

test("a pass check links only rejected findings", () => {
  const review = example();
  checkOf(review, "AUTHN-02").findings.push(findingOf(review, "API-07").fingerprint);
  assertError(review, "a pass check may link only rejected findings");
});

test("a needs_validation check links a needs_validation finding", () => {
  const review = example();
  checkOf(review, "AUTHN-02").result = "needs_validation";
  assertError(review, "a needs_validation check must link at least one needs_validation finding");
});

test("assessed checks cite reviewed paths", () => {
  const review = example();
  checkOf(review, "AUTHN-02").paths = [];
  assertError(review, "a pass check must cite at least one reviewed path");
});

for (const unsafe of ["/etc/passwd", "../secrets.txt", "app/../../x.py", "C:\\app\\x.py", "app\\x.py", "~/x.py", "app//x.py", "app/./x.py", " app/x.py", "app/x.py\u0000"]) {
  test(`rejects the unsafe path ${JSON.stringify(unsafe)}`, () => {
    const review = example();
    checkOf(review, "AUTHN-02").paths = [unsafe];
    assertError(review, "must be a safe repository-relative path");
  });
}

test("accepts ordinary repository paths", () => {
  for (const ok of ["app/api/invoices.py", ".github/workflows/ci.yml", "Dockerfile", "vendor/**", "src/@scope/pkg/index.ts"]) {
    assert.ok(isSafeRelativePath(ok), ok);
  }
});

// Findings rules

test("rejects unknown fingerprints linked from checks", () => {
  const review = example();
  checkOf(review, "AUTHN-02").findings.push("AUTHN-02:app/nowhere.py:ghost");
  assertError(review, "unknown finding");
});

test("a confirmed finding is linked from its own check", () => {
  const review = example();
  const { fingerprint } = findingOf(review, "AUTHZ-05");
  checkOf(review, "AUTHZ-05").findings = [];
  checkOf(review, "AUTHZ-05").result = "pass";
  assert.ok(checkOf(review, "AUTHZ-04").findings.includes(fingerprint));
  assertError(review, "must be linked from its own check AUTHZ-05");
});

test("findings belong to active domains", () => {
  const review = example();
  findingOf(review, "AUTHZ-03").check_id = "DATA-01";
  assertError(review, "domain DATA must be active to hold findings");
});

test("findings are sorted and unique", () => {
  const unsorted = example();
  unsorted.findings.reverse();
  assertError(unsorted, "findings must be sorted by fingerprint");
  const duplicated = example();
  duplicated.findings.push(structuredClone(duplicated.findings[duplicated.findings.length - 1]));
  assertError(duplicated, "duplicate of $.findings");
});

test("rejects unknown check IDs on findings", () => {
  const review = example();
  findingOf(review, "AUTHZ-03").check_id = "AUTHZ-99";
  assertError(review, 'unknown check "AUTHZ-99"');
});

test("overall severity cannot exceed impact", () => {
  const review = example();
  findingOf(review, "AUTHZ-05").severity.impact.score = "medium";
  assertError(review, "cannot exceed the demonstrated impact");
});

test("in-diff high findings block the merge", () => {
  const review = example();
  findingOf(review, "AUTHZ-05").merge_blocking = false;
  assertError(review, "an in-diff high finding must block the merge");
});

test("pre-existing findings never block the merge", () => {
  const review = example();
  findingOf(review, "AUTHZ-05").in_diff = false;
  assertError(review, "only findings introduced, modified, or newly exposed");
});

test("low findings never block the merge", () => {
  const review = example();
  findingOf(review, "AUTHZ-05").severity = {
    likelihood: { score: "low", reason: "Requires an unusual setup." },
    impact: { score: "low", reason: "Discloses non-secret metadata." },
    overall_severity: "low",
  };
  assertError(review, "a low finding must not block the merge");
});

test("needs_validation findings carry no severity", () => {
  const review = example();
  findingOf(review, "AUTHZ-08").severity = structuredClone(findingOf(review, "AUTHZ-05").severity);
  assertError(review, 'unexpected field "severity"');
});

test("needs_validation findings carry a validation plan", () => {
  const review = example();
  findingOf(review, "AUTHZ-08").validation_plan = {};
  assertError(review, "provide a local or owner validation plan");
});

test("rejects malformed standard references", () => {
  const review = example();
  findingOf(review, "AUTHZ-05").refs = ["A01:2021"];
  assertError(review, "refs[0]: must match");
});

test("traces run from entrypoint to sink", () => {
  const review = example();
  findingOf(review, "AUTHZ-05").trace.reverse();
  assertError(review, 'kind: must be "entrypoint"');
  assertError(review, 'kind: must be "sink"');
});

test("rejects unknown fields and other schema versions", () => {
  const review = example();
  review.extra = true;
  review.schema_version = "2.0";
  assertError(review, 'unexpected field "extra"');
  assertError(review, 'schema_version: must equal "1.0"');
});

// Decision rules

test("merge-blocking findings require request_changes", () => {
  const review = example();
  review.decision = "comment";
  assertError(review, 'merge-blocking finding(s) require "request_changes"');
});

test("approve is refused with open questions or confirmed in-diff findings", () => {
  const review = example();
  review.decision = "approve";
  assertError(review, '"approve" is not allowed while needs_validation findings are open');
  assertError(review, '"approve" is not allowed with confirmed in-diff findings');
});

test("a clean review can be approved", () => {
  assertValid(cleanReview());
});

test("request_changes needs a blocking or open finding", () => {
  const review = cleanReview();
  review.decision = "request_changes";
  assertError(review, '"request_changes" needs a merge-blocking or needs_validation finding');
});

// Command-line behavior

test("CLI accepts the example", () => {
  const result = runCli(["{file}"], fs.readFileSync(EXAMPLE, "utf8"));
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /^PASS: review valid; decision request_changes; 2 blocking/m);
});

test("CLI gate exits 2 on request_changes and 0 otherwise", () => {
  const blocked = runCli(["{file}", "--gate"], fs.readFileSync(EXAMPLE, "utf8"));
  assert.equal(blocked.status, 2, blocked.output);
  assert.match(blocked.output, /GATE: merge blocked/);
  const approved = runCli(["--gate", "{file}"], JSON.stringify(cleanReview()));
  assert.equal(approved.status, 0, approved.output);
  assert.match(approved.output, /GATE: no merge-blocking decision/);
});

test("CLI reports invalid documents with exit code 1", () => {
  const review = example();
  review.decision = "approve";
  const result = runCli(["{file}"], JSON.stringify(review));
  assert.equal(result.status, 1);
  assert.match(result.output, /^ERROR: /m);
  assert.match(result.output, /^FAIL: \d+ validation error/m);
});

test("CLI rejects bad arguments, malformed JSON, oversized input, and deep nesting", () => {
  assert.match(runCli([]).output, /Usage:/);
  assert.equal(runCli([]).status, 1);
  assert.equal(runCli(["{file}"], "{").status, 1);
  const oversized = runCli(["{file}"], " ".repeat(LIMITS.inputBytes + 1));
  assert.equal(oversized.status, 1);
  assert.match(oversized.output, /byte limit/);
  const nested = runCli(["{file}"], `${"[".repeat(LIMITS.nestingDepth + 1)}${"]".repeat(LIMITS.nestingDepth + 1)}`);
  assert.equal(nested.status, 1);
  assert.match(nested.output, /nesting limit/);
});

test("CLI refuses symlinked input", { skip: process.platform === "win32" }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-review-"));
  try {
    const target = path.join(directory, "target.json");
    const link = path.join(directory, "review.json");
    fs.writeFileSync(target, fs.readFileSync(EXAMPLE));
    fs.symlinkSync(target, link);
    const result = spawnSync(process.execPath, [VALIDATOR, link], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
    assert.equal(result.status, 1);
    assert.match(`${result.stdout}${result.stderr}`, /symlink/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI escapes terminal control characters in diagnostics", () => {
  const review = example();
  review.decision = "approve\u001b[2J\u202e";
  const result = runCli(["{file}"], JSON.stringify(review));
  assert.equal(result.status, 1);
  assert.ok(!result.output.includes("\u001b"), "a raw ESC byte reached the terminal");
  assert.ok(!result.output.includes("\u202e"), "a raw bidi override reached the terminal");
  assert.match(result.output, /\\u001b/);
});
