package reporter

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/chavakula/calvigil/internal/models"
)

// PDFReporter generates a PDF report by rendering the HTML report and
// converting it to PDF using headless Chrome/Chromium (--print-to-pdf).
type PDFReporter struct{}

// chromePath returns the path to a usable Chrome or Chromium binary,
// or an empty string if none is found.
func chromePath() string {
	// Prefer an explicit env override.
	if p := os.Getenv("CHROME_PATH"); p != "" {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}

	// Well-known binary names / paths (macOS, Linux, Windows).
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

	// Step 1: Render the HTML report into a buffer.
	var htmlBuf bytes.Buffer
	htmlReporter := &HTMLReporter{}
	if err := htmlReporter.Report(result, &htmlBuf); err != nil {
		return fmt.Errorf("HTML rendering failed: %w", err)
	}

	// Step 2: Write HTML to a temp file (Chrome reads from a file).
	tmpHTML, err := os.CreateTemp("", "calvigil-*.html")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	defer os.Remove(tmpHTML.Name())

	if _, err := tmpHTML.Write(htmlBuf.Bytes()); err != nil {
		tmpHTML.Close()
		return fmt.Errorf("cannot write temp HTML: %w", err)
	}
	tmpHTML.Close()

	// Step 3: Create a temp file for the PDF output.
	tmpPDF, err := os.CreateTemp("", "calvigil-*.pdf")
	if err != nil {
		return fmt.Errorf("cannot create temp PDF file: %w", err)
	}
	defer os.Remove(tmpPDF.Name())
	tmpPDF.Close()

	// Step 4: Convert HTML → PDF via headless Chrome.
	cmd := exec.Command(chrome,
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-software-rasterizer",
		"--run-all-compositor-stages-before-draw",
		"--print-to-pdf="+tmpPDF.Name(),
		"--print-to-pdf-no-header",
		"--no-pdf-header-footer",
		tmpHTML.Name(),
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Chrome PDF conversion failed: %w\nUsed binary: %s", err, chrome)
	}

	// Step 5: Read the generated PDF and write to the output writer.
	pdfData, err := os.ReadFile(tmpPDF.Name())
	if err != nil {
		return fmt.Errorf("cannot read generated PDF: %w", err)
	}

	if _, err := w.Write(pdfData); err != nil {
		return fmt.Errorf("cannot write PDF output: %w", err)
	}

	return nil
}
