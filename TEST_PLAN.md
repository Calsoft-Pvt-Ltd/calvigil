# Comprehensive Test Plan — calvigil Feature Implementation

## Scope
Testing the 5 features implemented today:
1. License Compliance Scanning
2. SPDX 2.3 SBOM Reporter
3. Offline Vulnerability Cache
4. Helm Chart IaC Scanning
5. Enhanced Secret Scanning (SEC-026 to SEC-029)

---

## 1. License Package (`internal/license/`)

### Unit Tests
| Test ID | Test Name | Description | Type |
|---------|-----------|-------------|------|
| L-01 | TestClassify_Permissive | Classify MIT, Apache-2.0, BSD-3-Clause → permissive | Positive |
| L-02 | TestClassify_Copyleft | Classify GPL-3.0, AGPL-3.0, MPL-2.0 → copyleft | Positive |
| L-03 | TestClassify_Unknown | Classify "CustomLicense", "WTFPL" → unknown | Positive |
| L-04 | TestClassify_Empty | Classify "" → unknown | Edge case |
| L-05 | TestClassify_CaseInsensitive | Classify "mit", "APACHE-2.0", "gpl-3.0" correctly | Robustness |
| L-06 | TestClassify_WhitespaceHandling | Classify " MIT ", "  GPL-3.0  " correctly | Edge case |
| L-07 | TestCheckPackages_MixedLicenses | Mix of permissive, copyleft, empty → correct issues | Integration |
| L-08 | TestCheckPackages_AllPermissive | All MIT packages → no issues returned | Negative |
| L-09 | TestCheckPackages_EmptySlice | Empty package list → no issues | Edge case |
| L-10 | TestCheckPackages_NoLicenseInfo | All packages with empty license → all flagged unknown | Edge case |

## 2. Cache Package (`internal/cache/`)

### Unit Tests
| Test ID | Test Name | Description | Type |
|---------|-----------|-------------|------|
| C-01 | TestPutAndGet | Store vulns, retrieve → matches | Positive |
| C-02 | TestGet_Miss | Get from empty cache → false | Negative |
| C-03 | TestGet_Expired | Store with 1ms TTL, wait, get → expired/false | TTL |
| C-04 | TestGet_CorruptedFile | Write invalid JSON to cache file → removed, false | Error handling |
| C-05 | TestPut_CreatesDirectory | Put into non-existent dir → creates properly | Side effect |
| C-06 | TestClear | Put then Clear → Get returns false | Positive |
| C-07 | TestNew_DefaultTTL | New with 0 TTL → uses DefaultTTL | Default |
| C-08 | TestNew_EmptyDir | New with "" dir → uses DefaultDir | Default |
| C-09 | TestKey_Deterministic | Same inputs → same key; different inputs → different keys | Correctness |
| C-10 | TestPut_EmptyDir | Cache with dir="" → no-op, no error | Edge case |

## 3. SPDX Reporter (`internal/reporter/spdx.go`)

### Unit Tests
| Test ID | Test Name | Description | Type |
|---------|-----------|-------------|------|
| S-01 | TestSPDX_EmptyResult | Empty scan → valid SPDX doc with root package only | Edge case |
| S-02 | TestSPDX_WithPackages | Packages list → all appear as SPDX packages with PURLs | Positive |
| S-03 | TestSPDX_WithVulnerabilities | Vulns → annotations on affected packages | Positive |
| S-04 | TestSPDX_LicenseFields | Packages with licenses → LicenseDeclared populated | Positive |
| S-05 | TestSPDX_NoLicense | Package without license → "NOASSERTION" | Edge case |
| S-06 | TestSPDX_Relationships | Root DEPENDS_ON all packages + DOCUMENT DESCRIBES root | Structure |
| S-07 | TestSPDX_ValidJSON | Output is valid JSON | Format |
| S-08 | TestSPDX_Registry | ForFormat("spdx") returns SPDXReporter | Registration |
| S-09 | TestSPDX_FallbackToVulnPackages | No Packages list, but vulns → extracts from vulns | Fallback |

## 4. Enhanced Secret Patterns (SEC-026 to SEC-029)

### Unit Tests
| Test ID | Test Name | Description | Type |
|---------|-----------|-------------|------|
| P-01 | TestSEC026_PrivateKeys | RSA, EC, PGP, SSH, DSA key headers → match | Positive |
| P-02 | TestSEC026_NoFalsePositive | "private key" in log message → no match | Negative |
| P-03 | TestSEC027_ConnectionStrings | mongodb://, postgres://, mysql://, redis:// with creds → match | Positive |
| P-04 | TestSEC027_NoFalsePositive | mongodb://localhost (no creds) → no match | Negative |
| P-05 | TestSEC028_BearerTokens | Authorization: Bearer + hardcoded token → match | Positive |
| P-06 | TestSEC028_ShortTokens | bearer_token = "short" → no match (< 20 chars) | Negative |
| P-07 | TestSEC029_GenericSecrets | api_key, secret_key with long values → match | Positive |
| P-08 | TestSEC029_ShortValues | api_key = "abc" → no match (< 20 chars) | Negative |

## 5. Helm IaC Rules (IAC-021 to IAC-025)

### Unit Tests
| Test ID | Test Name | Description | Type |
|---------|-----------|-------------|------|
| H-01 | TestScanHelmTiller | Chart referencing tiller → IAC-021 | Positive |
| H-02 | TestScanHelmLatestTag | image: nginx:latest → IAC-022 | Positive |
| H-03 | TestScanHelmNoResources | containers: line → IAC-023 | Positive |
| H-04 | TestScanHelmHostNetwork | hostNetwork: true → IAC-024 | Positive |
| H-05 | TestScanHelmPrivileged | privileged: true → IAC-025 | Positive |
| H-06 | TestIsIaCFile_HelmFiles | Chart.yaml, values.yaml, templates/x.tpl → true | Detection |
| H-07 | TestFileCategory_Helm | Helm files → "Helm" category | Classification |
| H-08 | TestScanHelmTPLFile | .tpl file in templates/ → scanned | File scanning |

## 6. npm License Parsing

### Unit Tests
| Test ID | Test Name | Description | Type |
|---------|-----------|-------------|------|
| N-01 | TestExtractNpmLicense_String | "MIT" → "MIT" | Positive |
| N-02 | TestExtractNpmLicense_Object | {"type":"Apache-2.0"} → "Apache-2.0" | Positive |
| N-03 | TestExtractNpmLicense_Nil | nil → "" | Edge case |
| N-04 | TestExtractNpmLicense_EmptyString | "" → "" | Edge case |
| N-05 | TestNpmParser_WithLicenses | Full lockfile with license fields → packages have licenses | Integration |

## 7. Integration Tests

| Test ID | Test Name | Description |
|---------|-----------|-------------|
| I-01 | TestScanOptions_NewFlags | ScanOptions has CheckLicenses, NoCache, CacheTTL |
| I-02 | TestFormatFlag_SPDX | reporter.ForFormat("spdx") returns SPDXReporter |

---

## Code Quality Issues to Audit
- Duplicate pattern rules between Helm IAC and Kubernetes IAC
- normalizeID O(n) iteration over maps
- Cache key collision potential
- SPDX `seen` map logic when Packages populated
- IAC-022 regex matching ANY image line (false positive risk)
- Thread safety of cache operations
