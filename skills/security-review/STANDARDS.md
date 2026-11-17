# Standards Reference

Cite these identifiers verbatim in findings and review comments so remediation expectations are unambiguous. OWASP archived the standalone Secure Coding Practices Quick Reference Guide and migrated its checklists into the OWASP Developer Guide: cite the Developer Guide, ASVS 5.0.0, and the Cheat Sheet Series instead.

| Standard | Edition | Role in a pull request review |
|---|---|---|
| [OWASP Top 10](https://owasp.org/Top10/2025/) | 2025 | High-level risk taxonomy. Folds Server-Side Request Forgery into A01:2025, adds A03:2025 Software Supply Chain Failures and A10:2025 Mishandling of Exceptional Conditions. |
| [OWASP ASVS](https://asvs.owasp.org/) | 5.0.0 (May 2025) | Verifiable pass/fail requirements across 17 chapters, from V1 Encoding and Sanitization to V17 WebRTC, including V9 Self-contained Tokens and V10 OAuth and OIDC. |
| [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) | 2023 | API-specific failure modes such as Broken Object Level Authorization (API1:2023) and Broken Object Property Level Authorization (API3:2023). |
| [MITRE CWE](https://cwe.mitre.org/) | 4.x | Granular root-cause weakness identifiers such as CWE-89 or CWE-639. |
| [OWASP Developer Guide](https://devguide.owasp.org/) and [Cheat Sheet Series](https://cheatsheetseries.owasp.org/IndexASVS.html) | Living documents | Successor to the archived Secure Coding Practices Quick Reference Guide, with implementation patterns indexed by ASVS requirement. |

Reference formats accepted by `review-schema.json`: `A01:2025` to `A10:2025`, `API1:2023` to `API10:2023`, `ASVS V1` to `ASVS V17` (optionally down to a section or requirement, such as `ASVS V8.2` or `ASVS V8.2.1`), and `CWE-<number>`.

## OWASP Top 10:2025

| ID | Name |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

## OWASP ASVS 5.0.0 chapters

| ID | Chapter |
|---|---|
| V1 | Encoding and Sanitization |
| V2 | Validation and Business Logic |
| V3 | Web Frontend Security |
| V4 | API and Web Service |
| V5 | File Handling |
| V6 | Authentication |
| V7 | Session Management |
| V8 | Authorization |
| V9 | Self-contained Tokens |
| V10 | OAuth and OIDC |
| V11 | Cryptography |
| V12 | Secure Communication |
| V13 | Configuration |
| V14 | Data Protection |
| V15 | Secure Coding and Architecture |
| V16 | Security Logging and Error Handling |
| V17 | WebRTC |

## OWASP API Security Top 10:2023

| ID | Name |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

## CWE identifiers used by the checklist

| CWE | Name | Checks |
|---|---|---|
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | INJECTION-06, API-04, LOGIC-02 |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) | FILES-01, FILES-02 |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) | INJECTION-03, CONFIG-07 |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) | INJECTION-02 |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) | INJECTION-01 |
| [CWE-117](https://cwe.mitre.org/data/definitions/117.html) | Improper Output Neutralization for Logs | ERRORS-05 |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Generation of Error Message Containing Sensitive Information | ERRORS-01 |
| [CWE-213](https://cwe.mitre.org/data/definitions/213.html) | Exposure of Sensitive Information Due to Incompatible Policies | DATA-03 |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | Execution with Unnecessary Privileges | CONFIG-05, CONFIG-06 |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | AUTHZ-03 |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | AUTHN-05 |
| [CWE-288](https://cwe.mitre.org/data/definitions/288.html) | Authentication Bypass Using an Alternate Path or Channel | AUTHN-05 |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Improper Certificate Validation | CRYPTO-05 |
| [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | Missing Authentication for Critical Function | AUTHN-01 |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | AUTHN-04 |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Missing Encryption of Sensitive Data | DATA-04 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | CRYPTO-06 |
| [CWE-323](https://cwe.mitre.org/data/definitions/323.html) | Reusing a Nonce, Key Pair in Encryption | CRYPTO-03 |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Use of a Broken or Risky Cryptographic Algorithm | CRYPTO-01, CRYPTO-02 |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Generation of Predictable IV with CBC Mode | CRYPTO-03 |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | CRYPTO-04 |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | API-07 |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Improper Verification of Cryptographic Signature | SESSION-03 |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery (CSRF) | AUTHZ-09 |
| [CWE-359](https://cwe.mitre.org/data/definitions/359.html) | Exposure of Private Personal Information to an Unauthorized Actor | DATA-02 |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) | LOGIC-03 |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Time-of-check Time-of-use (TOCTOU) Race Condition | LOGIC-03 |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | SESSION-01 |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | FILES-03, FILES-04 |
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Active Debug Code | CONFIG-01 |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of Untrusted Data | INJECTION-05 |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Cleartext Storage of Sensitive Information in an Environment Variable | SECRETS-04 |
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Insertion of Sensitive Information into Log File | ERRORS-04 |
| [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Use of GET Request Method With Sensitive Query Strings | SESSION-04 |
| [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Improper Restriction of XML External Entity Reference | FILES-05 |
| [CWE-613](https://cwe.mitre.org/data/definitions/613.html) | Insufficient Session Expiration | SESSION-05 |
| [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Sensitive Cookie in HTTPS Session Without Secure Attribute | SESSION-02 |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely (Failing Open) | ERRORS-02 |
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Authorization Bypass Through User-Controlled Key | AUTHZ-04, AUTHZ-05, API-02 |
| [CWE-640](https://cwe.mitre.org/data/definitions/640.html) | Weak Password Recovery Mechanism for Forgotten Password | AUTHN-06 |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | CONFIG-04 |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of Resources Without Limits or Throttling | API-05 |
| [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | Insufficient Logging | ERRORS-03 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | SECRETS-01, SECRETS-02, AI-03 |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | Inclusion of Functionality from Untrusted Control Sphere | DEPS-04 |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | Improper Enforcement of Behavioral Workflow | LOGIC-01 |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing Authorization | AUTHZ-01, AI-04 |
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect Authorization | AUTHZ-07, AUTHZ-08 |
| [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | Improperly Controlled Modification of Dynamically-Determined Object Attributes | API-03 |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Use of Password Hash With Insufficient Computational Effort | AUTHN-03 |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-Side Request Forgery (SSRF) | INJECTION-04 |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Policy with Untrusted Domains | CONFIG-02 |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Sensitive Cookie Without HttpOnly Flag | SESSION-02 |
| [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | Use of Unmaintained Third Party Components | DEPS-01 |
| [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | Sensitive Cookie with Improper SameSite Attribute | SESSION-02 |
| [CWE-1284](https://cwe.mitre.org/data/definitions/1284.html) | Improper Validation of Specified Quantity in Input | LOGIC-02 |
| [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | Reliance on Insufficiently Trustworthy Component | DEPS-02, AI-01 |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Dependency on Vulnerable Third-Party Component | DEPS-06 |

## OWASP Cheat Sheets by domain

All cheat sheets live under `https://cheatsheetseries.owasp.org/cheatsheets/<Name>.html`.

| Domain | Cheat sheets |
|---|---|
| AUTHN | [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html), [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html), [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html) |
| AUTHZ | [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html), [Multi Tenant Security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html), [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| SESSION | [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html), [Cookie Theft Mitigation](https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html) |
| INJECTION | [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html), [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [Server Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) |
| API | [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [GraphQL](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html), [gRPC Security](https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html), [Webhook Security](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html) |
| FILES | [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html), [Path Traversal Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html), [XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [XML Security](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html) |
| LOGIC | [Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html), [Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html), [Third Party Payment Gateway Integration](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Payment_Gateway_Integration_Cheat_Sheet.html) |
| CRYPTO | [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html), [Transport Layer Security](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html), [Pinning](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) |
| SECRETS | [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| ERRORS | [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html), [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html) |
| DATA | [User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html), [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) |
| DEPS | [Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html), [Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html), [NPM Security](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html), [Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html) |
| CONFIG | [Infrastructure as Code Security](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html), [Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), [Kubernetes Security](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html), [CI CD Security](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html), [GitHub Actions Security](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html), [CORS Security](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html), [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html); also the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) |
| AI | [Secure Coding with AI](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html), [Authorization Regression Testing](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html), [LLM Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) |

General review practice: [Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
