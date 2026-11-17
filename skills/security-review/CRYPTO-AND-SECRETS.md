# Cryptography and Secrets Review

#### When to use this file

Use the `CRYPTO` part when the diff touches cryptographic libraries, hashing, random token generation, key loading, encryption, signatures, certificates, or TLS and HTTP client configuration. The `SECRETS` part is always active: any change can leak a credential in code, tests, fixtures, documentation, configuration, or Git history.

It covers `CRYPTO` (A04:2025, ASVS V11 and V12) and `SECRETS` (A07:2025, ASVS V13). Cryptographic failures and leaked credentials turn localized bugs into organization-wide compromises. Password hashing is AUTHN-03 in [IDENTITY-AND-ACCESS.md](IDENTITY-AND-ACCESS.md); JWT verification is SESSION-03.

## Core discipline (include in every reviewer prompt for this file)

```
- Use vetted high-level libraries. Never invent primitives, modes, padding, token formats, or protocols.
- Algorithm, mode, key, IV or nonce, randomness source, and tag verification must all be right. One weak link breaks the whole construction.
- TLS verification is never optional in production code, scripts, containers, or CI.
- A secret is compromised the moment it is pushed. Deleting it is not remediation; revoking and rotating it is.
- Never print a secret value. Report path, line, credential type, and at most a four-character prefix.
- Inspect tests, fixtures, docs, notebooks, Dockerfiles, CI YAML, IaC, and sample configuration as carefully as application code.
```

## CRYPTO — Cryptography and TLS Verification · A04:2025 · ASVS V11 · V12 (subagent_type: `general`)

Cheat sheets: Cryptographic Storage, Key Management, Transport Layer Security, Pinning.

**CRYPTO-01 — Zero Custom Cryptographic Primitives**
- **Check:** The diff introduces no bespoke encryption schemes, custom stream ciphers, or homegrown token-signing protocols.
- **Why:** Custom cryptographic constructions fail silently against differential, timing, and padding attacks that functional unit tests never detect.
- **Ref:** `A04:2025` · `ASVS V11` · `CWE-327`
- **Verify:** Flag hand-written XOR or stream ciphers, custom padding, home-made token formats, concatenation-based MACs (`hash(secret + data)`), and custom key derivation. Expect a vetted high-level library (libsodium, Tink, `cryptography` AEAD or Fernet, Web Crypto, a maintained JOSE library).

**CRYPTO-02 — Modern Vetted Algorithms and Authenticated Modes**
- **Check:** Symmetric encryption uses authenticated modes (`AES-256-GCM` or `ChaCha20-Poly1305`), with zero use of `ECB` mode, `DES`, `MD5`, or `SHA-1` for security guarantees.
- **Why:** `ECB` leaks plaintext structure and broken hashes allow chosen-prefix collisions.
- **Ref:** `A04:2025` · `ASVS V11` · `CWE-327`
- **Verify:** Flag `AES/ECB`, `MODE_ECB`, DES, 3DES, RC4, Blowfish, unauthenticated CBC or CTR without a MAC, and MD5 or SHA-1 used for signatures, integrity, or tokens. Accept AES-256-GCM, ChaCha20-Poly1305, SHA-256 or stronger, and HMAC-SHA-256 or stronger. MD5 used only as a cache key is not a security use.

**CRYPTO-03 — Unique Per-Operation IVs and Nonces**
- **Check:** Initialization vectors (IVs) and nonces are generated uniquely per encryption call and never hardcoded or reused under the same key.
- **Why:** A single reused nonce in `AES-GCM` catastrophically destroys both confidentiality and authentication integrity.
- **Ref:** `A04:2025` · `ASVS V11` · `CWE-329` · `CWE-323`
- **Verify:** Confirm IVs and nonces come from a CSPRNG for every encryption, or from a managed counter that cannot repeat under the same key, and are never constants, derived from the data, or reused across messages. GCM nonces are 96 bits; random nonces need key rotation before the collision bound.

**CRYPTO-04 — Cryptographically Secure Randomness**
- **Check:** Security tokens, session IDs, nonces, and verification codes draw from a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) such as Python `secrets` or Node.js `crypto.randomBytes()`.
- **Why:** `Math.random()` and `random.random()` expose internal PRNG state that attackers reconstruct from a handful of outputs.
- **Ref:** `A04:2025` · `ASVS V11` · `CWE-338`
- **Verify:** Flag `Math.random`, `random.random`, `randint`, `choice`, `rand()`, `mt_rand`, `java.util.Random`, `uuid1`, timestamps, and seeded PRNGs used for tokens, codes, access-granting IDs, nonces, or salts. Accept `secrets`, `crypto.randomBytes`, `crypto.randomUUID`, `SecureRandom`, Go `crypto/rand`, and PHP `random_bytes`.

**CRYPTO-05 — Mandatory TLS Certificate Verification**
- **Check:** Outbound Transport Layer Security (TLS) clients keep certificate chain and hostname verification enabled, with zero `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, or `InsecureSkipVerify: true` flags.
- **Why:** "Temporary" TLS bypasses pasted during debugging ship to production and enable trivial Man-in-the-Middle (MitM) interception.
- **Ref:** `ASVS V12` · `CWE-295`
- **Verify:** Flag `verify=False`, `ssl._create_unverified_context`, `CERT_NONE`, `check_hostname = False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`, trust-all `TrustManager` or `HostnameVerifier`, `curl -k` or `--insecure`, and `CURLOPT_SSL_VERIFYPEER` disabled, including in Dockerfiles, scripts, and CI.

**CRYPTO-06 — Externalized Key Management**
- **Check:** Encryption and signing keys load at runtime from a cloud Key Management Service (KMS) or dedicated secrets manager, never from repository files.
- **Why:** Keys committed to source control replicate permanently to every developer laptop, fork, and CI cache.
- **Ref:** `ASVS V11` · `CWE-321`
- **Verify:** Confirm encryption and signing keys are read at runtime from a KMS, Vault, a cloud secret manager, or mounted secrets. Flag PEM blocks, base64 key literals, committed `.pem`, `.key`, `.p12`, or `.jks` files, and keys in configuration files.

## SECRETS — Secrets Hygiene Across Code and Git History · A07:2025 · ASVS V13 (subagent_type: `general`)

Always active. SECRETS-01 and SECRETS-02 are assessed on every review. Cheat sheet: Secrets Management.

**SECRETS-01 — Zero Hardcoded Credentials Anywhere in Diff**
- **Check:** Source files, unit test fixtures, Dockerfiles, GitHub Actions YAML, and `.env.example` templates contain no real API keys, database URIs, or private keys.
- **Why:** Credentials labelled "staging" or "test" frequently share permissions with production cloud accounts.
- **Ref:** `A07:2025` · `ASVS V13` · `CWE-798`
- **Verify:** Run the secret scanner on the diff, then review code, tests, fixtures, docs, notebooks, Dockerfiles, CI YAML, IaC, and `.env.example` for keys, tokens, connection strings with passwords, private keys, and webhook secrets. Report path, line, type, and a redacted prefix only.

**SECRETS-02 — Immediate Rotation of Historically Committed Secrets**
- **Check:** Any secret committed in an earlier commit on the PR branch is revoked and rotated immediately, not merely deleted in a follow-up commit.
- **Why:** Deleting a secret in a later commit leaves the plaintext credential accessible in Git commit history and PR reflogs.
- **Ref:** `ASVS V13` · `CWE-798`
- **Verify:** Scan every commit on the branch, not only the final tree (`gitleaks git --redact --log-opts="<base>..<head>"`). A secret added and later removed is still a finding: require revocation and rotation, and note that rewriting history does not un-leak a pushed secret.

**SECRETS-03 — Ignored Local Environment Files**
- **Check:** `.env`, `.env.local`, service-account JSON keys, and Terraform `.tfvars` files containing secrets are explicitly excluded in `.gitignore` and `.dockerignore`.
- **Why:** Unignored local credential files get swept into repositories by `git add .` or baked into container layers by `COPY . .`.
- **Ref:** `ASVS V13`
- **Verify:** When the diff adds configuration loading, credential files, Terraform, or container builds, confirm `.gitignore` and `.dockerignore` cover `.env*` (except `.env.example`), `*.tfvars`, `*.pem`, `*.key`, service-account JSON, and local credential files, and that none are committed.

**SECRETS-04 — Runtime Secret Injection**
- **Check:** Newly required credentials inject via workload identity or runtime secret mounts rather than build-time container `ARG` or `ENV` directives.
- **Why:** Build-time container arguments persist in `docker history` metadata for anyone with registry pull access.
- **Ref:** `ASVS V13` · `CWE-526`
- **Verify:** Flag `ARG` or `ENV` carrying tokens, passwords, or keys, `--build-arg` secrets in CI, and secrets baked into images or front-end bundles (`NEXT_PUBLIC_*`, `VITE_*`, or `REACT_APP_*` variables holding private values). Expect BuildKit secret mounts (`RUN --mount=type=secret`), workload identity, or runtime-mounted secrets.

## Review moves (apply across the above)

- For every key: where is it generated, stored, loaded, rotated, and revoked?
- For every encryption call: algorithm, mode, IV or nonce source, and authentication-tag verification on decrypt.
- For every token or code: find the random source and the comparison (constant time where it matters).
- Scan the whole branch history, including renamed and deleted files, not only the final tree.
- Compare what the build context copies (`COPY . .`) with `.dockerignore`.

## Validation rules (apply before reporting ANY finding here)

1. For cryptography, name the capability the weakness gives an attacker (forge, decrypt, predict, intercept) on a reachable path. A weak hash used for a non-security purpose is not a finding.
2. For a TLS bypass, confirm the path runs outside tests and local development profiles.
3. For secrets, determine the credential type and likely scope without using it. Treat real-looking credentials as live and require revocation and rotation. Placeholders that cannot work anywhere are at most `hardening` (see AI-03 for fallback defaults).
4. Never validate a secret by calling its provider or using it.
5. Calibrate: production credentials with write scope are `critical`; scoped or read-only credentials are `high` or `medium`; inert placeholders are `hardening`.
