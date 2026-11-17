#!/usr/bin/env node

/**
 * Validates a security-review review.json document.
 * Usage: node validate-review.cjs <path-to-review.json> [--gate]
 *
 * Zero dependencies. Interprets the JSON Schema subset used by review-schema.json,
 * then applies the checklist.json catalog and the review consistency rules that are
 * clearer in code than in schema.
 *
 * Exit codes:
 *   0  valid (with --gate: valid and the decision does not block the merge)
 *   1  invalid, unreadable, or bad arguments
 *   2  with --gate only: valid and the decision is request_changes
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { TextDecoder } = require("util");

const SCHEMA_PATH = path.join(__dirname, "review-schema.json");
const CATALOG_PATH = path.join(__dirname, "checklist.json");

const LIMITS = Object.freeze({
  inputBytes: 5 * 1024 * 1024,
  nestingDepth: 64,
  arrayItems: 2000,
  validationErrors: 100,
  diagnosticChars: 200,
});

const SUPPORTED_TYPES = new Set(["object", "array", "string", "integer", "number", "boolean", "null"]);
const SUPPORTED_KEYWORDS = new Set([
  "$schema",
  "$id",
  "$comment",
  "$defs",
  "$ref",
  "title",
  "description",
  "type",
  "properties",
  "required",
  "additionalProperties",
  "const",
  "enum",
  "pattern",
  "minLength",
  "maxLength",
  "items",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minimum",
  "maximum",
  "oneOf",
  "visibleContent",
]);
const ACTIVATIONS = new Set(["diff_signals", "always", "ai_generated"]);
const SEVERITY_RANK = new Map([
  ["informational", 0],
  ["low", 1],
  ["medium", 2],
  ["high", 3],
  ["critical", 4],
]);

const VISIBLE_CONTENT = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const PATH_FORBIDDEN_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
const UNSAFE_DIAGNOSTIC_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const LONE_SURROGATE = /\p{Cs}/u;
const WINDOWS_RESERVED_SEGMENT = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

class InputError extends Error {}

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

function typeName(value) {
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  return typeof value;
}

function matchesType(value, type) {
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  return typeName(value) === type;
}

function isWellFormed(text) {
  return typeof text.isWellFormed === "function" ? text.isWellFormed() : !LONE_SURROGATE.test(text);
}

function hasVisibleContent(text) {
  return isWellFormed(text) && VISIBLE_CONTENT.test(text);
}

function escapeDiagnostic(text) {
  return String(text).replace(UNSAFE_DIAGNOSTIC_CHARACTER, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, "0")}`
      : `\\u{${codePoint.toString(16)}}`;
  });
}

function quote(value) {
  if (typeof value === "string") {
    const clipped = value.length > LIMITS.diagnosticChars ? `${value.slice(0, LIMITS.diagnosticChars)}...` : value;
    return escapeDiagnostic(JSON.stringify(clipped));
  }
  if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) {
    return String(value);
  }
  return `<${typeName(value)}>`;
}

function propertyPath(base, key) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? `${base}.${key}` : `${base}[${quote(key)}]`;
}

class ErrorList {
  constructor() {
    this.messages = [];
  }

  add(message) {
    if (this.messages.length < LIMITS.validationErrors) this.messages.push(escapeDiagnostic(message));
  }

  get full() {
    return this.messages.length >= LIMITS.validationErrors;
  }
}

function stableKey(value) {
  if (Array.isArray(value)) return `[${value.map(stableKey).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableKey(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const patternCache = new Map();
function compiledPattern(pattern) {
  if (!patternCache.has(pattern)) patternCache.set(pattern, new RegExp(pattern, "u"));
  return patternCache.get(pattern);
}

function resolveRef(root, ref) {
  const match = typeof ref === "string" ? /^#\/\$defs\/([A-Za-z0-9_]+)$/.exec(ref) : null;
  if (!match || !isPlainObject(root.$defs) || !hasOwn(root.$defs, match[1])) return null;
  return root.$defs[match[1]];
}

function collectSchemaErrors(root) {
  const errors = new ErrorList();

  function visit(node, at) {
    if (!isPlainObject(node)) {
      errors.add(`${at}: schema node must be an object`);
      return;
    }
    for (const key of Object.keys(node)) {
      if (!SUPPORTED_KEYWORDS.has(key)) errors.add(`${at}: unsupported schema keyword ${quote(key)}`);
    }
    if (hasOwn(node, "$ref") && resolveRef(root, node.$ref) === null) {
      errors.add(`${at}.$ref: only resolvable "#/$defs/<name>" references are supported`);
    }
    if (hasOwn(node, "$defs")) {
      if (node !== root) errors.add(`${at}.$defs: only allowed at the schema root`);
      if (!isPlainObject(node.$defs)) errors.add(`${at}.$defs: expected an object`);
      else for (const [name, child] of Object.entries(node.$defs)) visit(child, `${at}.$defs.${name}`);
    }
    if (hasOwn(node, "type") && !SUPPORTED_TYPES.has(node.type)) {
      errors.add(`${at}.type: unsupported type ${quote(node.type)}`);
    }
    if (hasOwn(node, "properties")) {
      if (!isPlainObject(node.properties)) errors.add(`${at}.properties: expected an object`);
      else for (const [name, child] of Object.entries(node.properties)) visit(child, propertyPath(`${at}.properties`, name));
    }
    if (hasOwn(node, "required")) {
      if (!Array.isArray(node.required) || node.required.some((key) => typeof key !== "string")) {
        errors.add(`${at}.required: expected an array of strings`);
      } else if (new Set(node.required).size !== node.required.length) {
        errors.add(`${at}.required: entries must be unique`);
      } else if (isPlainObject(node.properties)) {
        for (const key of node.required) {
          if (!hasOwn(node.properties, key)) errors.add(`${at}.required: ${quote(key)} is not declared in properties`);
        }
      }
    }
    if (hasOwn(node, "additionalProperties") && typeof node.additionalProperties !== "boolean") {
      errors.add(`${at}.additionalProperties: only boolean values are supported`);
    }
    if (hasOwn(node, "enum") && (!Array.isArray(node.enum) || node.enum.length === 0)) {
      errors.add(`${at}.enum: expected a non-empty array`);
    }
    for (const keyword of ["minLength", "maxLength", "minItems", "maxItems"]) {
      if (hasOwn(node, keyword) && (!Number.isInteger(node[keyword]) || node[keyword] < 0)) {
        errors.add(`${at}.${keyword}: expected a non-negative integer`);
      }
    }
    for (const keyword of ["minimum", "maximum"]) {
      if (hasOwn(node, keyword) && !matchesType(node[keyword], "number")) errors.add(`${at}.${keyword}: expected a finite number`);
    }
    if (hasOwn(node, "pattern")) {
      if (typeof node.pattern !== "string") {
        errors.add(`${at}.pattern: expected a string`);
      } else {
        try {
          compiledPattern(node.pattern);
        } catch {
          errors.add(`${at}.pattern: invalid regular expression`);
        }
      }
    }
    if (hasOwn(node, "uniqueItems") && typeof node.uniqueItems !== "boolean") {
      errors.add(`${at}.uniqueItems: expected a boolean`);
    }
    if (hasOwn(node, "visibleContent") && (typeof node.visibleContent !== "boolean" || (node.visibleContent && node.type !== "string"))) {
      errors.add(`${at}.visibleContent: expected a boolean on a string schema`);
    }
    if (hasOwn(node, "items")) visit(node.items, `${at}.items`);
    if (hasOwn(node, "oneOf")) {
      if (!Array.isArray(node.oneOf) || node.oneOf.length === 0) errors.add(`${at}.oneOf: expected a non-empty array`);
      else node.oneOf.forEach((branch, index) => visit(branch, `${at}.oneOf[${index}]`));
    }
  }

  visit(root, "schema");
  return errors.messages;
}

function discriminatorIndex(value, branches, root) {
  if (!isPlainObject(value)) return -1;
  const matches = [];
  branches.forEach((branch, index) => {
    const target = hasOwn(branch, "$ref") ? resolveRef(root, branch.$ref) : branch;
    if (!isPlainObject(target) || !isPlainObject(target.properties)) return;
    for (const [key, property] of Object.entries(target.properties)) {
      if (isPlainObject(property) && hasOwn(property, "const") && hasOwn(value, key) && stableKey(value[key]) === stableKey(property.const)) {
        matches.push(index);
        return;
      }
    }
  });
  return matches.length === 1 ? matches[0] : -1;
}

function validateNode(value, schema, root, at, errors) {
  if (errors.full) return;
  if (hasOwn(schema, "$ref")) validateNode(value, resolveRef(root, schema.$ref), root, at, errors);
  if (hasOwn(schema, "oneOf")) {
    const outcomes = schema.oneOf.map((branch) => {
      const branchErrors = new ErrorList();
      validateNode(value, branch, root, at, branchErrors);
      return branchErrors.messages;
    });
    const passing = outcomes.filter((messages) => messages.length === 0).length;
    if (passing !== 1) {
      const index = passing === 0 ? discriminatorIndex(value, schema.oneOf, root) : -1;
      if (index !== -1) outcomes[index].forEach((message) => errors.add(message));
      else errors.add(`${at}: must match exactly one schema in oneOf; matched ${passing}`);
    }
  }
  if (hasOwn(schema, "const") && stableKey(value) !== stableKey(schema.const)) {
    errors.add(`${at}: must equal ${quote(schema.const)}`);
  }
  if (hasOwn(schema, "enum") && !schema.enum.some((option) => stableKey(option) === stableKey(value))) {
    errors.add(`${at}: must be one of ${schema.enum.map(quote).join(", ")}; got ${quote(value)}`);
  }
  if (hasOwn(schema, "type") && !matchesType(value, schema.type)) {
    errors.add(`${at}: expected ${schema.type}, got ${typeName(value)}`);
    return;
  }

  if (isPlainObject(value)) {
    if (Array.isArray(schema.required)) {
      for (const key of schema.required) if (!hasOwn(value, key)) errors.add(`${at}: missing required field ${quote(key)}`);
    }
    for (const key of Object.keys(value)) {
      if (isPlainObject(schema.properties) && hasOwn(schema.properties, key)) {
        validateNode(value[key], schema.properties[key], root, propertyPath(at, key), errors);
      } else if (schema.additionalProperties === false) {
        errors.add(`${at}: unexpected field ${quote(key)}`);
      }
    }
  }

  if (Array.isArray(value)) {
    if (hasOwn(schema, "minItems") && value.length < schema.minItems) errors.add(`${at}: must contain at least ${schema.minItems} item(s)`);
    if (hasOwn(schema, "maxItems") && value.length > schema.maxItems) errors.add(`${at}: must contain at most ${schema.maxItems} item(s)`);
    if (schema.uniqueItems === true) {
      const seen = new Map();
      value.forEach((item, index) => {
        const key = stableKey(item);
        if (seen.has(key)) errors.add(`${at}[${index}]: duplicate of ${at}[${seen.get(key)}]`);
        else seen.set(key, index);
      });
    }
    if (hasOwn(schema, "items")) value.forEach((item, index) => validateNode(item, schema.items, root, `${at}[${index}]`, errors));
  }

  if (typeof value === "string") {
    const length = Array.from(value).length;
    if (hasOwn(schema, "minLength") && length < schema.minLength) errors.add(`${at}: must contain at least ${schema.minLength} character(s)`);
    if (hasOwn(schema, "maxLength") && length > schema.maxLength) errors.add(`${at}: must contain at most ${schema.maxLength} character(s)`);
    if (hasOwn(schema, "pattern") && !compiledPattern(schema.pattern).test(value)) errors.add(`${at}: must match ${JSON.stringify(schema.pattern)}`);
    if (schema.visibleContent === true && !hasVisibleContent(value)) errors.add(`${at}: must contain visible, well-formed text`);
  }

  if (typeof value === "number") {
    if (hasOwn(schema, "minimum") && value < schema.minimum) errors.add(`${at}: must be at least ${schema.minimum}`);
    if (hasOwn(schema, "maximum") && value > schema.maximum) errors.add(`${at}: must be at most ${schema.maximum}`);
  }
}

function collectDataLimitErrors(value) {
  const stack = [{ value, at: "$", depth: 1 }];
  while (stack.length > 0) {
    const { value: current, at, depth } = stack.pop();
    if (current === null || typeof current !== "object") continue;
    if (depth > LIMITS.nestingDepth) return [escapeDiagnostic(`${at}: exceeds the ${LIMITS.nestingDepth}-level nesting limit`)];
    if (Array.isArray(current)) {
      if (current.length > LIMITS.arrayItems) return [escapeDiagnostic(`${at}: exceeds the ${LIMITS.arrayItems}-item array limit`)];
      current.forEach((child, index) => stack.push({ value: child, at: `${at}[${index}]`, depth: depth + 1 }));
    } else {
      for (const [key, child] of Object.entries(current)) stack.push({ value: child, at: propertyPath(at, key), depth: depth + 1 });
    }
  }
  return [];
}

function isSafeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) return false;
  if (!isWellFormed(value) || value.trim() !== value || PATH_FORBIDDEN_CHARACTER.test(value)) return false;
  if (value.includes("\\") || value.includes(":") || value.startsWith("/") || value.startsWith("~")) return false;
  return value
    .split("/")
    .every(
      (segment) =>
        segment !== "" &&
        segment !== "." &&
        segment !== ".." &&
        !/[ .]$/u.test(segment) &&
        !WINDOWS_RESERVED_SEGMENT.test(segment),
    );
}

function checkTraceOrder(trace, at, errors) {
  if (trace.length === 1) {
    if (trace[0].kind === "propagation") errors.add(`${at}[0].kind: a one-step trace must be "entrypoint" or "sink"`);
    return;
  }
  const last = trace.length - 1;
  if (trace[0].kind !== "entrypoint") errors.add(`${at}[0].kind: must be "entrypoint"`);
  if (trace[last].kind !== "sink") errors.add(`${at}[${last}].kind: must be "sink"`);
  for (let index = 1; index < last; index += 1) {
    if (trace[index].kind !== "propagation") errors.add(`${at}[${index}].kind: must be "propagation"`);
  }
}

function collectReviewErrors(review, catalog) {
  const errors = new ErrorList();
  const { domains: catalogDomains, domainById, checkById } = catalog;
  const meta = review.review;

  if (meta.ai_generated.detected && meta.ai_generated.signals.length === 0) {
    errors.add("$.review.ai_generated.signals: record at least one signal when AI authorship is detected");
  }
  (meta.excluded_paths || []).forEach((entry, index) => {
    if (!isSafeRelativePath(entry.path)) errors.add(`$.review.excluded_paths[${index}].path: must be a safe repository-relative path`);
  });

  const findings = new Map();
  let previous = null;
  review.findings.forEach((finding, index) => {
    const at = `$.findings[${index}]`;
    if (findings.has(finding.fingerprint)) errors.add(`${at}.fingerprint: duplicate of $.findings[${findings.get(finding.fingerprint).index}]`);
    else findings.set(finding.fingerprint, { finding, index });
    if (previous !== null && previous > finding.fingerprint) errors.add(`${at}.fingerprint: findings must be sorted by fingerprint`);
    previous = finding.fingerprint;
  });

  const seenDomains = new Map();
  const activeDomains = new Set();
  const links = new Map();
  review.domains.forEach((domain, index) => {
    const at = `$.domains[${index}]`;
    if (seenDomains.has(domain.id)) {
      errors.add(`${at}.id: duplicate domain ${domain.id} (first at $.domains[${seenDomains.get(domain.id)}])`);
      return;
    }
    seenDomains.set(domain.id, index);
    const catalogDomain = domainById.get(domain.id);
    if (!catalogDomain) {
      errors.add(`${at}.id: unknown domain ${quote(domain.id)}`);
      return;
    }

    if (domain.status === "not_applicable") {
      if (catalogDomain.activation === "always") errors.add(`${at}.status: ${domain.id} is always active and cannot be not_applicable`);
      if (catalogDomain.activation === "ai_generated" && meta.ai_generated.detected) {
        errors.add(`${at}.status: ${domain.id} must be active when review.ai_generated.detected is true`);
      }
      if (domain.checks.length > 0) errors.add(`${at}.checks: a not_applicable domain must not list checks`);
      return;
    }

    activeDomains.add(domain.id);
    const seenChecks = new Set();
    domain.checks.forEach((check, checkIndex) => {
      const checkAt = `${at}.checks[${checkIndex}]`;
      const catalogCheck = checkById.get(check.id);
      if (!catalogCheck) {
        errors.add(`${checkAt}.id: unknown check ${quote(check.id)}`);
        return;
      }
      if (catalogCheck.domain !== domain.id) {
        errors.add(`${checkAt}.id: ${check.id} belongs to ${catalogCheck.domain}, not ${domain.id}`);
        return;
      }
      if (seenChecks.has(check.id)) {
        errors.add(`${checkAt}.id: duplicate check ${check.id}`);
        return;
      }
      seenChecks.add(check.id);

      check.paths.forEach((value, pathIndex) => {
        if (!isSafeRelativePath(value)) errors.add(`${checkAt}.paths[${pathIndex}]: must be a safe repository-relative path`);
      });
      if (check.result === "not_applicable") {
        if (catalogCheck.not_applicable_allowed === false) {
          errors.add(`${checkAt}.result: ${check.id} must be assessed on every review and cannot be not_applicable`);
        }
        if (check.findings.length > 0) errors.add(`${checkAt}.findings: a not_applicable check must not link findings`);
      } else if (check.paths.length === 0) {
        errors.add(`${checkAt}.paths: a ${check.result} check must cite at least one reviewed path`);
      }

      let confirmed = 0;
      let needsValidation = 0;
      check.findings.forEach((fingerprint, findingIndex) => {
        const entry = findings.get(fingerprint);
        if (!entry) {
          errors.add(`${checkAt}.findings[${findingIndex}]: unknown finding ${quote(fingerprint)}`);
          return;
        }
        if (entry.finding.verdict === "confirmed") confirmed += 1;
        if (entry.finding.verdict === "needs_validation") needsValidation += 1;
        if (!links.has(fingerprint)) links.set(fingerprint, new Set());
        links.get(fingerprint).add(check.id);
      });
      if (check.result === "fail" && confirmed === 0) {
        errors.add(`${checkAt}.result: a fail check must link at least one confirmed finding`);
      }
      if (check.result === "needs_validation") {
        if (confirmed > 0) errors.add(`${checkAt}.result: a check linked to a confirmed finding must be fail`);
        else if (needsValidation === 0) errors.add(`${checkAt}.result: a needs_validation check must link at least one needs_validation finding`);
      }
      if ((check.result === "pass" || check.result === "hardening") && (confirmed > 0 || needsValidation > 0)) {
        errors.add(`${checkAt}.result: a ${check.result} check may link only rejected findings`);
      }
    });
    for (const catalogCheck of catalogDomain.checks) {
      if (!seenChecks.has(catalogCheck.id)) {
        errors.add(`${at}.checks: missing ${catalogCheck.id}; an active domain must give every catalog check a disposition`);
      }
    }
  });
  for (const catalogDomain of catalogDomains) {
    if (!seenDomains.has(catalogDomain.id)) {
      errors.add(`$.domains: missing ${catalogDomain.id}; list every domain, using not_applicable with a reason when the diff does not touch it`);
    }
  }

  let blocking = 0;
  let openQuestions = 0;
  let confirmedInDiff = 0;
  review.findings.forEach((finding, index) => {
    const at = `$.findings[${index}]`;
    const catalogCheck = checkById.get(finding.check_id);
    if (!catalogCheck) errors.add(`${at}.check_id: unknown check ${quote(finding.check_id)}`);
    else if (!activeDomains.has(catalogCheck.domain)) errors.add(`${at}.check_id: domain ${catalogCheck.domain} must be active to hold findings`);
    if (finding.verdict !== "rejected" && !(links.get(finding.fingerprint) || new Set()).has(finding.check_id)) {
      errors.add(`${at}: a ${finding.verdict} finding must be linked from its own check ${finding.check_id}`);
    }

    for (const field of ["trace", "evidence"]) {
      finding[field].forEach((entry, entryIndex) => {
        if (!isSafeRelativePath(entry.file)) errors.add(`${at}.${field}[${entryIndex}].file: must be a safe repository-relative path`);
      });
    }
    checkTraceOrder(finding.trace, `${at}.trace`, errors);

    if (finding.verdict === "confirmed") {
      const overallName = finding.severity.overall_severity;
      const overall = SEVERITY_RANK.get(overallName);
      const impact = SEVERITY_RANK.get(finding.severity.impact.score);
      if (overall > impact) {
        errors.add(`${at}.severity.overall_severity: cannot exceed the demonstrated impact ${quote(finding.severity.impact.score)}`);
      }
      if (finding.merge_blocking && !finding.in_diff) {
        errors.add(`${at}.merge_blocking: only findings introduced, modified, or newly exposed by this change (in_diff: true) can block the merge`);
      }
      if (finding.in_diff && overall >= SEVERITY_RANK.get("high") && !finding.merge_blocking) {
        errors.add(`${at}.merge_blocking: an in-diff ${overallName} finding must block the merge`);
      }
      if (overall <= SEVERITY_RANK.get("low") && finding.merge_blocking) {
        errors.add(`${at}.merge_blocking: a ${overallName} finding must not block the merge`);
      }
      if (finding.merge_blocking) blocking += 1;
      if (finding.in_diff) confirmedInDiff += 1;
    } else if (finding.verdict === "needs_validation") {
      openQuestions += 1;
      if (!hasOwn(finding.validation_plan, "local") && !hasOwn(finding.validation_plan, "owner")) {
        errors.add(`${at}.validation_plan: provide a local or owner validation plan`);
      }
    }
  });

  const decision = review.decision;
  if (blocking > 0 && decision !== "request_changes") {
    errors.add(`$.decision: ${blocking} merge-blocking finding(s) require "request_changes"`);
  }
  if (decision === "request_changes" && blocking === 0 && openQuestions === 0) {
    errors.add('$.decision: "request_changes" needs a merge-blocking or needs_validation finding');
  }
  if (decision === "approve" && openQuestions > 0) {
    errors.add('$.decision: "approve" is not allowed while needs_validation findings are open');
  }
  if (decision === "approve" && confirmedInDiff > 0) {
    errors.add('$.decision: "approve" is not allowed with confirmed in-diff findings; use "comment" for non-blocking ones');
  }

  return errors.messages;
}

function validateDocument(review, schema, catalog) {
  const limitErrors = collectDataLimitErrors(review);
  if (limitErrors.length > 0) return limitErrors;
  const errors = new ErrorList();
  validateNode(review, schema, schema, "$", errors);
  if (errors.messages.length > 0) return errors.messages;
  return collectReviewErrors(review, catalog);
}

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function loadSchema(schemaPath = SCHEMA_PATH) {
  const schema = loadJson(schemaPath);
  const errors = collectSchemaErrors(schema);
  if (errors.length > 0) throw new Error(`unsupported or invalid review schema:\n${errors.join("\n")}`);
  return schema;
}

function loadCatalog(catalogPath = CATALOG_PATH) {
  const catalog = loadJson(catalogPath);
  if (!isPlainObject(catalog) || !Array.isArray(catalog.domains) || catalog.domains.length === 0) {
    throw new Error("invalid checklist.json: domains must be a non-empty array");
  }
  const problems = [];
  const domainById = new Map();
  const checkById = new Map();
  catalog.domains.forEach((domain, index) => {
    const at = `domains[${index}]`;
    if (!isPlainObject(domain) || typeof domain.id !== "string" || !/^[A-Z]+$/.test(domain.id)) {
      problems.push(`${at}.id: expected an uppercase identifier`);
      return;
    }
    if (domainById.has(domain.id)) problems.push(`${at}.id: duplicate domain ${domain.id}`);
    if (typeof domain.name !== "string" || domain.name.length === 0) problems.push(`${at}.name: required`);
    if (typeof domain.file !== "string" || !/^[A-Z0-9-]+\.md$/.test(domain.file)) problems.push(`${at}.file: expected a companion Markdown file name`);
    if (!ACTIVATIONS.has(domain.activation)) problems.push(`${at}.activation: expected one of ${[...ACTIVATIONS].join(", ")}`);
    if (!Array.isArray(domain.checks) || domain.checks.length === 0) {
      problems.push(`${at}.checks: expected a non-empty array`);
      return;
    }
    domainById.set(domain.id, domain);
    domain.checks.forEach((check, checkIndex) => {
      const checkAt = `${at}.checks[${checkIndex}]`;
      if (!isPlainObject(check) || typeof check.id !== "string" || !new RegExp(`^${domain.id}-[0-9]{2}$`).test(check.id)) {
        problems.push(`${checkAt}.id: expected ${domain.id}-NN`);
        return;
      }
      if (checkById.has(check.id)) problems.push(`${checkAt}.id: duplicate check ${check.id}`);
      if (typeof check.title !== "string" || check.title.length === 0) problems.push(`${checkAt}.title: required`);
      if (!Array.isArray(check.refs) || check.refs.length === 0 || check.refs.some((ref) => typeof ref !== "string")) {
        problems.push(`${checkAt}.refs: expected a non-empty array of references`);
      }
      if (hasOwn(check, "not_applicable_allowed") && typeof check.not_applicable_allowed !== "boolean") {
        problems.push(`${checkAt}.not_applicable_allowed: expected a boolean`);
      }
      checkById.set(check.id, { ...check, domain: domain.id });
    });
  });
  if (problems.length > 0) throw new Error(`invalid checklist.json:\n${problems.join("\n")}`);
  return { domains: catalog.domains, domainById, checkById };
}

function readFileWithinLimit(file) {
  const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;
  let descriptor;
  if (Number.isInteger(O_NOFOLLOW) && O_NOFOLLOW !== 0) {
    try {
      descriptor = fs.openSync(file, O_RDONLY | O_NOFOLLOW | (O_NONBLOCK || 0));
    } catch (error) {
      if (error && (error.code === "ELOOP" || error.code === "EMLINK")) throw new InputError("input must not be a symlink");
      throw error;
    }
  } else {
    if (fs.lstatSync(file).isSymbolicLink()) throw new InputError("input must not be a symlink");
    descriptor = fs.openSync(file, "r");
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new InputError("input must be a regular file");
    if (stat.size > LIMITS.inputBytes) throw new InputError(`input exceeds the ${LIMITS.inputBytes}-byte limit`);
    const chunks = [];
    const buffer = Buffer.alloc(64 * 1024);
    let total = 0;
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      total += count;
      if (total > LIMITS.inputBytes) throw new InputError(`input exceeds the ${LIMITS.inputBytes}-byte limit`);
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    try {
      return UTF8.decode(Buffer.concat(chunks, total));
    } catch {
      throw new InputError("input is not valid UTF-8");
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function enforceJsonTextLimits(text) {
  const containers = [];
  let inString = false;
  let escaped = false;

  function countArrayItem() {
    const top = containers[containers.length - 1];
    if (!top || top.type !== "array" || !top.expectsItem) return;
    top.expectsItem = false;
    top.items += 1;
    if (top.items > LIMITS.arrayItems) throw new InputError(`input exceeds the ${LIMITS.arrayItems}-item array limit`);
  }

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      countArrayItem();
      inString = true;
    } else if (character === "[" || character === "{") {
      countArrayItem();
      if (containers.length >= LIMITS.nestingDepth) throw new InputError(`input exceeds the ${LIMITS.nestingDepth}-level nesting limit`);
      containers.push({ type: character === "[" ? "array" : "object", expectsItem: character === "[", items: 0 });
    } else if (character === "]" || character === "}") {
      containers.pop();
    } else if (character === ",") {
      const top = containers[containers.length - 1];
      if (top && top.type === "array") top.expectsItem = true;
    } else if (!/\s/.test(character)) {
      countArrayItem();
    }
  }
}

function summarize(review) {
  const confirmed = review.findings.filter((finding) => finding.verdict === "confirmed");
  return {
    blocking: confirmed.filter((finding) => finding.merge_blocking).length,
    confirmed: confirmed.length,
    needsValidation: review.findings.filter((finding) => finding.verdict === "needs_validation").length,
    active: review.domains.filter((domain) => domain.status === "active").length,
    domains: review.domains.length,
  };
}

function run(argv, out = console) {
  const args = argv.slice(2);
  const gate = args.includes("--gate");
  const files = args.filter((arg) => arg !== "--gate");
  if (files.length !== 1 || files[0].startsWith("-")) {
    out.error("Usage: node validate-review.cjs <path-to-review.json> [--gate]");
    return 1;
  }

  let schema;
  let catalog;
  try {
    schema = loadSchema();
    catalog = loadCatalog();
  } catch (error) {
    out.error(`Failed to load the skill contracts: ${escapeDiagnostic(error.message)}`);
    return 1;
  }

  let text;
  try {
    text = readFileWithinLimit(files[0]);
  } catch (error) {
    out.error(`Failed to read review JSON: ${error instanceof InputError ? error.message : "the file could not be opened or read safely"}`);
    return 1;
  }

  try {
    enforceJsonTextLimits(text);
  } catch (error) {
    out.error(`Failed to parse review JSON: ${error instanceof InputError ? error.message : "invalid JSON structure"}`);
    return 1;
  }

  let review;
  try {
    review = JSON.parse(text);
  } catch {
    out.error("Failed to parse review JSON: invalid JSON syntax");
    return 1;
  }

  let errors;
  try {
    errors = validateDocument(review, schema, catalog);
  } catch {
    out.error("Failed to validate review JSON: unexpected validation error");
    return 1;
  }
  if (errors.length > 0) {
    for (const message of errors) out.error(`ERROR: ${message}`);
    const capped = errors.length >= LIMITS.validationErrors ? `; output capped at ${LIMITS.validationErrors}` : "";
    out.error(`FAIL: ${errors.length} validation error(s)${capped}`);
    return 1;
  }

  const summary = summarize(review);
  out.log(
    `PASS: review valid; decision ${review.decision}; ${summary.blocking} blocking, ${summary.confirmed} confirmed, ` +
      `${summary.needsValidation} needs_validation; ${summary.active}/${summary.domains} domains active`,
  );
  if (gate && review.decision === "request_changes") {
    out.log("GATE: merge blocked by the security review");
    return 2;
  }
  if (gate) out.log("GATE: no merge-blocking decision");
  return 0;
}

module.exports = {
  LIMITS,
  collectSchemaErrors,
  isSafeRelativePath,
  loadCatalog,
  loadSchema,
  run,
  validateDocument,
};

if (require.main === module) process.exitCode = run(process.argv);
