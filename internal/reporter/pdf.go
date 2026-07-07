package reporter

import (
	"context"
	"embed"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

//go:embed assets/fonts/Inter-Regular.ttf assets/fonts/JetBrainsMono-Regular.ttf
var pdfFontFS embed.FS

// PDFReporter generates a printable, bookmarked PDF report from a dedicated
// report view model. The HTML used here is intentionally separate from the
// interactive HTML reporter so print layout and pagination stay predictable.
type PDFReporter struct{}

func init() {
	Register("pdf", func() Reporter { return &PDFReporter{} })
}

// chromePath returns the path to a usable Chrome or Chromium binary,
// or an empty string if none is found.
func chromePath() string {
	if p := os.Getenv("CHROME_PATH"); p != "" {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}

	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

// ChromeAvailable reports whether a usable Chrome/Chromium binary exists.
func ChromeAvailable() bool {
	return chromePath() != ""
}

func (r *PDFReporter) Report(result *models.ScanResult, w io.Writer) error {
	chrome := chromePath()
	if chrome == "" {
		return fmt.Errorf(
			"Google Chrome or Chromium is required for PDF output but was not found\n\n" +
				"Install one of the following:\n" +
				"  brew install --cask google-chrome   # macOS\n" +
				"  brew install --cask chromium         # macOS (Chromium)\n" +
				"  apt-get install chromium-browser     # Debian/Ubuntu\n" +
				"  yum install chromium                 # RHEL/CentOS\n\n" +
				"Or set CHROME_PATH to the binary location:\n" +
				"  export CHROME_PATH=/usr/bin/chromium\n\n" +
				"Alternatively, use --format html and convert the HTML file manually")
	}

	data := buildPDFReportData(result)
	htmlSource, err := renderPDFSourceHTML(data)
	if err != nil {
		return fmt.Errorf("render PDF source HTML: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "calvigil-pdf-*")
	if err != nil {
		return fmt.Errorf("create PDF workspace: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := writeEmbeddedPDFFonts(tmpDir); err != nil {
		return err
	}

	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := os.WriteFile(htmlPath, []byte(htmlSource), 0o600); err != nil {
		return fmt.Errorf("write PDF source HTML: %w", err)
	}

	rawPDF := filepath.Join(tmpDir, "report.raw.pdf")
	finalPDF := filepath.Join(tmpDir, "report.pdf")
	if err := renderPDFWithChrome(chrome, htmlPath, rawPDF, data); err != nil {
		return err
	}
	if err := postProcessPDF(rawPDF, finalPDF, data); err != nil {
		return err
	}

	pdfData, err := os.ReadFile(finalPDF)
	if err != nil {
		return fmt.Errorf("read generated PDF: %w", err)
	}
	if _, err := w.Write(pdfData); err != nil {
		return fmt.Errorf("write PDF output: %w", err)
	}
	return nil
}

func writeEmbeddedPDFFonts(root string) error {
	fontDir := filepath.Join(root, "fonts")
	if err := os.MkdirAll(fontDir, 0o700); err != nil {
		return fmt.Errorf("create PDF font directory: %w", err)
	}
	for _, name := range []string{"Inter-Regular.ttf", "JetBrainsMono-Regular.ttf"} {
		src := filepath.Join("assets", "fonts", name)
		data, err := pdfFontFS.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read embedded PDF font %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(fontDir, name), data, 0o600); err != nil {
			return fmt.Errorf("write PDF font %s: %w", name, err)
		}
	}
	return nil
}

func renderPDFWithChrome(chrome, htmlPath, outPath string, data pdfReportData) error {
	fileURL := url.URL{Scheme: "file", Path: htmlPath}
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chrome),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-software-rasterizer", true),
		chromedp.Flag("run-all-compositor-stages-before-draw", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var pdfData []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(fileURL.String()),
		chromedp.Sleep(800*time.Millisecond),
		chromedp.ActionFunc(func(ctx context.Context) error {
			out, stream, err := page.PrintToPDF().
				WithPrintBackground(true).
				WithDisplayHeaderFooter(true).
				WithHeaderTemplate(pdfHeaderTemplate(data)).
				WithFooterTemplate(pdfFooterTemplate()).
				WithPreferCSSPageSize(true).
				WithGenerateTaggedPDF(true).
				WithGenerateDocumentOutline(true).
				Do(ctx)
			if stream != "" {
				return fmt.Errorf("unexpected streamed PDF output")
			}
			pdfData = out
			return err
		}),
	); err != nil {
		return fmt.Errorf("Chrome PDF rendering failed: %w\nUsed binary: %s", err, chrome)
	}

	if len(pdfData) == 0 {
		return fmt.Errorf("Chrome PDF rendering produced an empty PDF")
	}
	if err := os.WriteFile(outPath, pdfData, 0o600); err != nil {
		return fmt.Errorf("write raw PDF: %w", err)
	}
	return nil
}

func postProcessPDF(inPath, outPath string, data pdfReportData) error {
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed

	bookmarkPath := inPath + ".bookmarked.pdf"
	bookmarks := []pdfcpu.Bookmark{
		{Title: "Cover", PageFrom: 1, Bold: true},
		{Title: "Table of contents", PageFrom: 2},
		{Title: "Executive overview", PageFrom: 3, Bold: true},
		{Title: "Supply chain guard", PageFrom: 4},
		{Title: "AI code smells", PageFrom: 5},
		{Title: "Dependency vulnerabilities", PageFrom: 6},
		{Title: "Code analysis findings and scanner warnings", PageFrom: 7},
	}
	if err := api.AddBookmarksFile(inPath, bookmarkPath, bookmarks, true, conf); err != nil {
		return fmt.Errorf("add PDF bookmarks: %w", err)
	}

	properties := map[string]string{
		"Title":    data.Title + " - " + data.ProjectName,
		"Author":   "Calvigil",
		"Subject":  "Software supply-chain security scan report",
		"Keywords": "calvigil,security,sbom,supply-chain,vulnerability,license,ai-code-smells",
		"Creator":  "Calvigil OSS PDF reporter",
	}
	if err := api.AddPropertiesFile(bookmarkPath, outPath, properties, conf); err != nil {
		return fmt.Errorf("add PDF metadata: %w", err)
	}
	if err := api.ValidateFile(outPath, conf); err != nil {
		return fmt.Errorf("validate generated PDF: %w", err)
	}
	return nil
}

func pdfHeaderTemplate(data pdfReportData) string {
	project := html.EscapeString(data.ProjectPath)
	if project == "" {
		project = html.EscapeString(data.ProjectName)
	}
	return `<div style="width:100%;font-family:Inter,Arial,sans-serif;font-size:7px;line-height:1;color:#6b7787;padding:0 16mm 1.6mm;display:flex;align-items:center;justify-content:space-between;border-bottom:0.5px solid #dde3ec;">` +
		`<span>` + project + `</span>` +
		`<span>Scanned ` + html.EscapeString(data.ScannedAt) + `</span>` +
		`</div>`
}

func pdfFooterTemplate() string {
	return `<div style="width:100%;font-family:Inter,Arial,sans-serif;font-size:7px;line-height:1;color:#6b7787;padding:1.6mm 16mm 0;display:flex;align-items:center;justify-content:space-between;border-top:0.5px solid #dde3ec;">` +
		`<span>Calvigil security evidence</span>` +
		`<span>Page <span class="pageNumber"></span> / <span class="totalPages"></span></span>` +
		`</div>`
}
