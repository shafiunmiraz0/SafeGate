package scanner

import (
	"regexp"
	"strings"
)

// MacroScanner detects embedded macros and scripts in Office documents and PDFs.
type MacroScanner struct{}

func NewMacroScanner() *MacroScanner { return &MacroScanner{} }

func (s *MacroScanner) Name() string { return "macro_script_scanner" }

func (s *MacroScanner) Scan(file *FileInfo) ([]Finding, error) {
	ext := strings.ToLower(file.Extension)
	mime := strings.ToLower(file.MIMEType)

	var findings []Finding

	if ext == ".pdf" || strings.Contains(mime, "pdf") {
		findings = append(findings, s.scanPDF(file.Content)...)
	}

	if isLegacyOffice(ext) || isLegacyOfficeMIME(mime) {
		findings = append(findings, s.scanLegacyOffice(file.Content)...)
	}

	if isModernOffice(ext) || isModernOfficeMIME(mime) {
		findings = append(findings, s.scanModernOffice(file.Content)...)
	}

	return findings, nil
}

func (s *MacroScanner) scanPDF(data []byte) []Finding {
	var findings []Finding
	content := string(data)

	checks := []struct {
		pattern *regexp.Regexp
		sev     Severity
		desc    string
		details string
	}{
		{pdfJSPattern, SeverityCritical, "PDF contains JavaScript",
			"Embedded JavaScript in PDF can execute malicious code when opened"},
		{pdfAutoActionPattern, SeverityHigh, "PDF contains auto-execute actions",
			"OpenAction/AA entries can trigger actions automatically when the PDF is opened"},
		{pdfLaunchPattern, SeverityCritical, "PDF contains launch actions",
			"Launch actions can execute arbitrary system commands"},
		{pdfEmbeddedFilePattern, SeverityMedium, "PDF contains embedded files",
			"Embedded file streams can carry hidden payloads"},
		{pdfURIPattern, SeverityLow, "PDF contains URI actions",
			"URI actions can redirect users to malicious websites"},
		{pdfEncryptPattern, SeverityMedium, "PDF contains encrypted or encoded streams",
			"Encrypted streams may hide malicious content from analysis"},
	}

	for _, c := range checks {
		if c.pattern.MatchString(content) {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: c.sev, Description: c.desc, Details: c.details,
			})
		}
	}
	return findings
}

func (s *MacroScanner) scanLegacyOffice(data []byte) []Finding {
	var findings []Finding

	// OLE2 Compound File magic: D0 CF 11 E0
	if len(data) < 8 || data[0] != 0xD0 || data[1] != 0xCF || data[2] != 0x11 || data[3] != 0xE0 {
		return nil
	}

	content := string(data)

	if strings.Contains(content, "VBA") || strings.Contains(content, "_VBA_PROJECT") {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityCritical,
			Description: "Office document contains VBA macros",
			Details:     "VBA macros can execute arbitrary code and are a common malware vector",
		})
	}

	autoExecNames := []string{
		"AutoOpen", "AutoClose", "AutoExec", "AutoNew",
		"Document_Open", "Document_Close",
		"Workbook_Open", "Workbook_Close",
	}
	for _, name := range autoExecNames {
		if strings.Contains(content, name) {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: SeverityCritical,
				Description: "Office document contains auto-execute macros",
				Details:     "Found auto-execute macro: " + name,
			})
			break
		}
	}

	if shellPattern.MatchString(content) {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityCritical,
			Description: "Office document contains shell execution commands",
			Details:     "Document references shell/command execution APIs",
		})
	}

	return findings
}

func (s *MacroScanner) scanModernOffice(data []byte) []Finding {
	var findings []Finding
	content := string(data)

	if strings.Contains(content, "vbaProject.bin") {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityCritical,
			Description: "Office document contains VBA macro project",
			Details:     "vbaProject.bin found — macros are present",
		})
	}

	if externalRelPattern.MatchString(content) {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityHigh,
			Description: "Office document references external content",
			Details:     "External relationships can load remote templates (template injection attack)",
		})
	}

	return findings
}

func isLegacyOffice(ext string) bool {
	switch ext {
	case ".doc", ".xls", ".ppt":
		return true
	}
	return false
}

func isLegacyOfficeMIME(mime string) bool {
	return strings.Contains(mime, "msword") ||
		strings.Contains(mime, "ms-excel") ||
		strings.Contains(mime, "ms-powerpoint")
}

func isModernOffice(ext string) bool {
	switch ext {
	case ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm":
		return true
	}
	return false
}

func isModernOfficeMIME(mime string) bool {
	return strings.Contains(mime, "openxmlformats")
}

var (
	pdfJSPattern           = regexp.MustCompile(`(?i)/JavaScript|/JS\s`)
	pdfAutoActionPattern   = regexp.MustCompile(`(?i)/OpenAction|/AA\s`)
	pdfLaunchPattern       = regexp.MustCompile(`(?i)/Launch`)
	pdfEmbeddedFilePattern = regexp.MustCompile(`(?i)/EmbeddedFile`)
	pdfURIPattern          = regexp.MustCompile(`(?i)/URI\s`)
	pdfEncryptPattern      = regexp.MustCompile(`(?i)/Encrypt|/Crypt`)
	shellPattern           = regexp.MustCompile(`(?i)(WScript|Shell|PowerShell|cmd\.exe|CreateObject)`)
	externalRelPattern     = regexp.MustCompile(`(?i)Target\s*=\s*"https?://`)
)
