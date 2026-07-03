package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/supplychain"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var supplyChainDiffOpts struct {
	BaselineReport string
	TargetReport   string
	Format         string
	OutputFile     string
}

var supplyChainCmd = &cobra.Command{
	Use:   "supply-chain",
	Short: "Analyze supply-chain trust drift and package behavior",
	Long: `Analyze dependency trust drift, package metadata suspicion signals,
and install-time behavior that can indicate software supply-chain attacks.`,
}

var supplyChainDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two Calvigil JSON reports for supply-chain trust drift",
	Example: `  calvigil scan ./baseline --format json --output baseline.json --skip-ai --skip-semgrep
  calvigil scan ./target --format json --output target.json --skip-ai --skip-semgrep --supply-chain-guard
  calvigil supply-chain diff --baseline-report baseline.json --target-report target.json
  calvigil supply-chain diff --baseline-report baseline.json --target-report target.json --format json`,
	RunE: runSupplyChainDiff,
}

func init() {
	rootCmd.AddCommand(supplyChainCmd)
	supplyChainCmd.AddCommand(supplyChainDiffCmd)

	supplyChainDiffCmd.Flags().StringVar(&supplyChainDiffOpts.BaselineReport, "baseline-report", "", "baseline Calvigil JSON report")
	supplyChainDiffCmd.Flags().StringVar(&supplyChainDiffOpts.TargetReport, "target-report", "", "target Calvigil JSON report")
	supplyChainDiffCmd.Flags().StringVarP(&supplyChainDiffOpts.Format, "format", "f", "table", "output format: table, json")
	supplyChainDiffCmd.Flags().StringVarP(&supplyChainDiffOpts.OutputFile, "output", "o", "", "write output to file (default: stdout)")
	_ = supplyChainDiffCmd.MarkFlagRequired("baseline-report")
	_ = supplyChainDiffCmd.MarkFlagRequired("target-report")
}

func runSupplyChainDiff(cmd *cobra.Command, _ []string) error {
	baseline, err := supplychain.LoadReport(supplyChainDiffOpts.BaselineReport)
	if err != nil {
		return err
	}
	target, err := supplychain.LoadReport(supplyChainDiffOpts.TargetReport)
	if err != nil {
		return err
	}
	risk := supplychain.DiffReports(contextFromCommand(cmd), baseline, target)

	var w io.Writer = os.Stdout
	if supplyChainDiffOpts.OutputFile != "" {
		file, err := os.OpenFile(supplyChainDiffOpts.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer file.Close()
		w = file
	}

	switch strings.ToLower(supplyChainDiffOpts.Format) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(risk)
	case "table", "":
		printSupplyChainDiffTable(w, risk)
		return nil
	default:
		return fmt.Errorf("unsupported supply-chain diff format %q", supplyChainDiffOpts.Format)
	}
}

func contextFromCommand(cmd *cobra.Command) context.Context {
	if cmd != nil {
		return cmd.Context()
	}
	return context.Background()
}

func printSupplyChainDiffTable(w io.Writer, risk *models.SupplyChainRisk) {
	if risk == nil {
		fmt.Fprintln(w, "No supply-chain risk data generated.")
		return
	}
	fmt.Fprintf(w, "\n🧭 Supply Chain Guard: %s score=%d decision=%s findings=%d\n\n",
		risk.Level, risk.Score, risk.Decision, risk.FindingCount)
	if len(risk.Guidance) > 0 {
		for _, g := range risk.Guidance {
			fmt.Fprintf(w, "   - %s\n", g)
		}
		fmt.Fprintln(w)
	}
	if len(risk.Findings) == 0 {
		fmt.Fprintln(w, "✅ No supply-chain drift findings detected.")
		return
	}
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"Severity", "Signal", "Package", "Evidence", "Recommendation"})
	for _, f := range risk.Findings {
		pkg := f.Package.Name
		if f.Package.Version != "" {
			pkg += "@" + f.Package.Version
		}
		t.AppendRow(table.Row{
			f.Severity,
			f.ID + " " + f.Title,
			orDashLocal(pkg),
			truncateLocal(f.Evidence, 80),
			truncateLocal(f.Recommendation, 80),
		})
	}
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, WidthMax: 42},
		{Number: 4, WidthMax: 80},
		{Number: 5, WidthMax: 80},
	})
	t.Render()
}

func orDashLocal(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func truncateLocal(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
