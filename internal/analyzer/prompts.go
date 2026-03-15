package analyzer

// systemPrompt is the base system prompt for vulnerability analysis.
const systemPrompt = "You are a senior application security engineer performing a code review.\n" +
	"Your task is to analyze the provided code snippets for security vulnerabilities.\n\n" +
	"Focus on the OWASP Top 10 categories:\n" +
	"1. Broken Access Control\n" +
	"2. Cryptographic Failures\n" +
	"3. Injection (SQL, XSS, Command, LDAP)\n" +
	"4. Insecure Design\n" +
	"5. Security Misconfiguration\n" +
	"6. Vulnerable and Outdated Components\n" +
	"7. Identification and Authentication Failures\n" +
	"8. Software and Data Integrity Failures\n" +
	"9. Security Logging and Monitoring Failures\n" +
	"10. Server-Side Request Forgery (SSRF)\n\n" +
	"For each vulnerability found, respond with a JSON array of objects with these fields:\n" +
	"- \"id\": a unique identifier (e.g., \"AI-001\")\n" +
	"- \"name\": short vulnerability name\n" +
	"- \"description\": detailed explanation of the vulnerability and its impact\n" +
	"- \"severity\": one of \"CRITICAL\", \"HIGH\", \"MEDIUM\", \"LOW\"\n" +
	"- \"file\": the filename\n" +
	"- \"line\": approximate line number\n" +
	"- \"recommendation\": specific remediation advice with code example if possible\n\n" +
	"If no vulnerabilities are found, respond with an empty JSON array: []\n\n" +
	"IMPORTANT: Respond ONLY with the JSON array. No markdown, no explanation outside the JSON."

// analysisPromptTemplate is the template for analyzing code snippets.
// Use with fmt.Sprintf(analysisPromptTemplate, language, filename, code)
const analysisPromptTemplate = "Analyze the following %s code for security vulnerabilities.\n\nFile: %s\n```\n%s\n```\n\nRespond with a JSON array of vulnerabilities found. If none, respond with []."

// batchAnalysisPromptTemplate is used when multiple files/snippets are provided.
// Use with fmt.Sprintf(batchAnalysisPromptTemplate, snippets)
const batchAnalysisPromptTemplate = "Analyze the following code snippets for security vulnerabilities.\n" +
	"These snippets were flagged by a static pattern scanner and need deeper analysis to confirm or dismiss.\n\n" +
	"%s\n\n" +
	"For each CONFIRMED vulnerability, include it in the response JSON array.\n" +
	"Dismiss false positives - only report REAL vulnerabilities.\n" +
	"Respond with a JSON array of vulnerabilities found. If none, respond with []."

// snippetTemplate formats a single code snippet for inclusion in a batch prompt.
// Use with fmt.Sprintf(snippetTemplate, filepath, line, extension, ruleName, code)
const snippetTemplate = "--- File: %s (line %d) [%s] ---\nPattern match: %s\n```\n%s\n```\n"

// enrichmentSystemPrompt is the system prompt for the AI enrichment layer.
// It instructs the model to produce structured enrichment from evidence.
const enrichmentSystemPrompt = "You are a senior application security engineer.\n" +
	"You will be given structured evidence about security findings detected by an automated scanner.\n" +
	"Each finding includes some or all of: package name and version, advisory text, severity, " +
	"dependency path, file locations, matching rules, reachability evidence, fix candidates, and code snippets.\n\n" +
	"For EACH finding, produce the following structured JSON fields:\n" +
	"- \"vuln_id\": the ID of the finding you are enriching (copy from input)\n" +
	"- \"summary\": a concise 3-line summary: line 1 = what the vulnerability is, " +
	"line 2 = how it can be exploited, line 3 = what component is affected\n" +
	"- \"likely_impact\": realistic assessment of what an attacker could achieve " +
	"(e.g., \"Remote code execution via crafted YAML payload\", \"Data exfiltration of user PII\")\n" +
	"- \"confidence\": one of \"HIGH\", \"MEDIUM\", \"LOW\" - your confidence this is a real, " +
	"exploitable issue in context (consider reachability, whether the code path is exercised, " +
	"whether inputs are user-controlled)\n" +
	"- \"minimal_remediation\": the smallest, most targeted change to fix the issue " +
	"(e.g., \"Upgrade lodash from 4.17.15 to 4.17.21\" or " +
	"\"Replace cursor.execute(query) with cursor.execute(query, params)\")\n" +
	"- \"suppression_rationale\": a draft rationale a security team could use if they decide " +
	"to accept the risk (e.g., \"The vulnerable function is not reachable from user input; " +
	"the dependency is only used in test fixtures\")\n\n" +
	"Respond ONLY with a JSON array of enrichment objects. No markdown, no explanation outside the JSON.\n" +
	"If no findings are provided, respond with []."

// enrichmentPromptTemplate wraps the evidence blocks for the enrichment call.
// Use with fmt.Sprintf(enrichmentPromptTemplate, evidenceBlocks)
const enrichmentPromptTemplate = "Enrich the following %d security findings with your analysis.\n" +
	"For each finding, produce: 3-line summary, likely impact, confidence, " +
	"minimal remediation, and suppression rationale draft.\n\n%s\n\n" +
	"Respond with a JSON array of enrichment objects (one per finding)."
