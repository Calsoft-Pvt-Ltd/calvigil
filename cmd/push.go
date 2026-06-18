package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/config"
	"github.com/Calsoft-Pvt-Ltd/calvigil/pkg/report"
	"github.com/spf13/cobra"
)

type pushOptions struct {
	ServerURL       string
	APIKey          string
	Project         string
	Ref             string
	Commit          string
	Environment     string
	CalvigilVersion string
	IdempotencyKey  string
	Timeout         time.Duration
	FailOnPolicy    bool
	EvaluateOnly    bool
}

type pushSummary struct {
	Project  string `json:"project"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Unknown  int    `json:"unknown"`
	KEV      int    `json:"kev"`
	Packages int    `json:"packages"`
}

type pushIngestResponse struct {
	ScanID  string      `json:"scan_id"`
	URL     string      `json:"url"`
	Replay  bool        `json:"replay"`
	Summary pushSummary `json:"summary"`
}

type pushPolicyResult struct {
	Pass          bool                  `json:"pass"`
	PolicyEnabled bool                  `json:"policy_enabled"`
	Truncated     bool                  `json:"truncated"`
	Summary       pushSummary           `json:"summary"`
	Violations    []pushPolicyViolation `json:"violations"`
}

type pushPolicyViolation struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Type        string `json:"type"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	VulnID      string `json:"vuln_id"`
	PackageName string `json:"package_name"`
	License     string `json:"license"`
	LicenseRisk string `json:"license_risk"`
	Environment string `json:"environment"`
}

type remoteProblem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

var pushOpts = pushOptions{Timeout: 30 * time.Second}

var pushCmd = &cobra.Command{
	Use:   "push <report.json>",
	Short: "Push a JSON scan report to Calvigil Enterprise",
	Long: `Push uploads an existing Calvigil JSON report to Calvigil Enterprise.

Create the report with any scanner command that supports JSON output, then push
that file with an Enterprise API key:

  calvigil scan . --skip-ai --format json --output calvigil.json
  calvigil push calvigil.json --project payments-service --ref main

The Enterprise URL and API key can be supplied by flags, config, or environment
variables. CI should prefer CALVIGIL_ENTERPRISE_URL and CALVIGIL_API_KEY.`,
	Example: `  calvigil push calvigil.json
  calvigil push calvigil.json --server-url https://calvigil.example.com --api-key "$CALVIGIL_API_KEY"
  calvigil push calvigil.json --project payments-service --ref "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --idempotency-key "$GITHUB_RUN_ID-$GITHUB_SHA"
  calvigil push calvigil.json --environment prod --fail-on-policy`,
	Args: cobra.ExactArgs(1),
	RunE: runPush,
}

func init() {
	rootCmd.AddCommand(pushCmd)

	pushCmd.Flags().StringVar(&pushOpts.ServerURL, "server-url", "", "Calvigil Enterprise URL (env: CALVIGIL_ENTERPRISE_URL)")
	pushCmd.Flags().StringVar(&pushOpts.APIKey, "api-key", "", "Calvigil Enterprise API key (env: CALVIGIL_API_KEY)")
	pushCmd.Flags().StringVar(&pushOpts.Project, "project", "", "project name override sent as X-Calvigil-Project")
	pushCmd.Flags().StringVar(&pushOpts.Ref, "ref", "", "git ref sent as X-Calvigil-Ref")
	pushCmd.Flags().StringVar(&pushOpts.Commit, "commit", "", "git commit sent as X-Calvigil-Commit")
	pushCmd.Flags().StringVar(&pushOpts.Environment, "environment", "", "policy environment, for example dev, staging, or prod")
	pushCmd.Flags().StringVar(&pushOpts.CalvigilVersion, "calvigil-version", "", "Calvigil CLI version header override")
	pushCmd.Flags().StringVar(&pushOpts.IdempotencyKey, "idempotency-key", "", "idempotency key for safe CI retries (env: CALVIGIL_IDEMPOTENCY_KEY)")
	pushCmd.Flags().DurationVar(&pushOpts.Timeout, "timeout", 30*time.Second, "HTTP timeout for Enterprise API calls")
	pushCmd.Flags().BoolVar(&pushOpts.FailOnPolicy, "fail-on-policy", false, "evaluate tenant policy first and exit non-zero without storing if it fails")
	pushCmd.Flags().BoolVar(&pushOpts.EvaluateOnly, "evaluate-only", false, "evaluate tenant policy without storing the scan")
}

func runPush(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	opts := resolvePushOptions(pushOpts, cfg)
	if opts.ServerURL == "" {
		return errors.New("missing Enterprise URL; set --server-url, CALVIGIL_ENTERPRISE_URL, or config key enterprise-url")
	}
	if opts.APIKey == "" {
		return errors.New("missing Enterprise API key; set --api-key, CALVIGIL_API_KEY, or config key enterprise-key")
	}
	if opts.Timeout <= 0 {
		return errors.New("--timeout must be greater than zero")
	}

	raw, err := readPushReport(args[0])
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), opts.Timeout)
	defer cancel()
	return pushReport(ctx, http.DefaultClient, opts, raw, cmd.OutOrStdout(), cmd.ErrOrStderr())
}

func resolvePushOptions(opts pushOptions, cfg *config.Config) pushOptions {
	if opts.ServerURL == "" {
		opts.ServerURL = cfg.EnterpriseURL
	}
	if opts.APIKey == "" {
		opts.APIKey = cfg.EnterpriseKey
	}
	if opts.Project == "" {
		opts.Project = os.Getenv("CALVIGIL_PROJECT")
	}
	if opts.Ref == "" {
		opts.Ref = os.Getenv("CALVIGIL_REF")
	}
	if opts.Commit == "" {
		opts.Commit = os.Getenv("CALVIGIL_COMMIT")
	}
	if opts.Environment == "" {
		opts.Environment = os.Getenv("CALVIGIL_ENVIRONMENT")
	}
	if opts.IdempotencyKey == "" {
		opts.IdempotencyKey = os.Getenv("CALVIGIL_IDEMPOTENCY_KEY")
	}
	if opts.CalvigilVersion == "" {
		opts.CalvigilVersion = version
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return opts
}

func readPushReport(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read report %q: %w", path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("report %q is empty", path)
	}
	if _, err := report.DecodeScanResult(raw); err != nil {
		return nil, fmt.Errorf("report %q is not valid Calvigil JSON: %w", path, err)
	}
	return raw, nil
}

func pushReport(ctx context.Context, client *http.Client, opts pushOptions, raw []byte, stdout, stderr io.Writer) error {
	if opts.FailOnPolicy || opts.EvaluateOnly {
		var policyRes pushPolicyResult
		if err := postEnterpriseJSON(ctx, client, opts, "/scans:evaluate", raw, &policyRes); err != nil {
			return err
		}
		printPolicyResult(stdout, policyRes)
		if !policyRes.Pass && opts.FailOnPolicy {
			printPolicyViolations(stderr, policyRes)
			return fmt.Errorf("policy gate failed: %d violation(s)", len(policyRes.Violations))
		}
		if opts.EvaluateOnly {
			return nil
		}
	}

	var ingestRes pushIngestResponse
	if err := postEnterpriseJSON(ctx, client, opts, "/scans", raw, &ingestRes); err != nil {
		return err
	}
	printIngestResult(stdout, ingestRes)
	return nil
}

func postEnterpriseJSON(ctx context.Context, client *http.Client, opts pushOptions, route string, raw []byte, out any) error {
	endpoint, err := enterpriseEndpoint(opts.ServerURL, route)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "calvigil/"+nonEmpty(opts.CalvigilVersion, "dev"))
	setOptionalHeader(req.Header, "X-Calvigil-Project", opts.Project)
	setOptionalHeader(req.Header, "X-Calvigil-Ref", opts.Ref)
	setOptionalHeader(req.Header, "X-Calvigil-Commit", opts.Commit)
	setOptionalHeader(req.Header, "X-Calvigil-Version", opts.CalvigilVersion)
	setOptionalHeader(req.Header, "X-Calvigil-Environment", opts.Environment)
	setOptionalHeader(req.Header, "Idempotency-Key", opts.IdempotencyKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("cannot read Enterprise response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return enterpriseHTTPError(resp.StatusCode, body)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("Enterprise returned an empty response")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("cannot decode Enterprise response: %w", err)
	}
	return nil
}

func enterpriseEndpoint(rawBase, route string) (string, error) {
	rawBase = strings.TrimSpace(rawBase)
	if rawBase == "" {
		return "", errors.New("missing Enterprise URL")
	}
	u, err := url.Parse(rawBase)
	if err != nil {
		return "", fmt.Errorf("invalid Enterprise URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Enterprise URL %q: expected absolute http(s) URL", rawBase)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid Enterprise URL %q: scheme must be http or https", rawBase)
	}
	basePath := strings.TrimRight(u.Path, "/")
	if basePath == "" {
		basePath = "/api/v1"
	} else if !strings.HasSuffix(basePath, "/api/v1") {
		basePath += "/api/v1"
	}
	u.Path = basePath + route
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func enterpriseHTTPError(status int, body []byte) error {
	var problem remoteProblem
	if err := json.Unmarshal(body, &problem); err == nil {
		msg := strings.TrimSpace(problem.Detail)
		if msg == "" {
			msg = strings.TrimSpace(problem.Title)
		}
		if msg == "" {
			msg = http.StatusText(status)
		}
		if problem.Code != "" {
			return fmt.Errorf("Enterprise returned %d %s: %s (%s)", status, http.StatusText(status), msg, problem.Code)
		}
		return fmt.Errorf("Enterprise returned %d %s: %s", status, http.StatusText(status), msg)
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		text = http.StatusText(status)
	}
	return fmt.Errorf("Enterprise returned %d %s: %s", status, http.StatusText(status), text)
}

func printPolicyResult(w io.Writer, res pushPolicyResult) {
	status := "pass"
	if !res.Pass {
		status = "fail"
	}
	if res.PolicyEnabled {
		fmt.Fprintf(w, "Policy: %s", status)
	} else {
		fmt.Fprintf(w, "Policy: %s (policy disabled)", status)
	}
	if len(res.Violations) > 0 {
		fmt.Fprintf(w, " - %d violation(s)", len(res.Violations))
	}
	fmt.Fprintln(w)
}

func printPolicyViolations(w io.Writer, res pushPolicyResult) {
	limit := len(res.Violations)
	if limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		v := res.Violations[i]
		label := nonEmpty(v.RuleID, v.Type)
		msg := nonEmpty(v.Message, "policy violation")
		fmt.Fprintf(w, "- %s: %s\n", label, msg)
	}
	if len(res.Violations) > limit {
		fmt.Fprintf(w, "- ... %d more violation(s)\n", len(res.Violations)-limit)
	}
}

func printIngestResult(w io.Writer, res pushIngestResponse) {
	action := "pushed"
	if res.Replay {
		action = "already pushed"
	}
	fmt.Fprintf(w, "Scan %s: %s\n", action, res.ScanID)
	if res.Summary.Project != "" {
		fmt.Fprintf(w, "Project: %s\n", res.Summary.Project)
	}
	fmt.Fprintf(w, "Findings: critical=%d high=%d medium=%d low=%d unknown=%d kev=%d packages=%d\n",
		res.Summary.Critical, res.Summary.High, res.Summary.Medium, res.Summary.Low,
		res.Summary.Unknown, res.Summary.KEV, res.Summary.Packages)
	if res.URL != "" {
		fmt.Fprintf(w, "URL: %s\n", res.URL)
	}
}

func setOptionalHeader(h http.Header, key, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		h.Set(key, value)
	}
}

func nonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
