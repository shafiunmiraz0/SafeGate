package scanner

import "fmt"

// MetadataScanner checks file size, empty files, null bytes, and suspicious filenames.
type MetadataScanner struct {
	maxFileSize int64
}

func NewMetadataScanner(maxFileSize int64) *MetadataScanner {
	return &MetadataScanner{maxFileSize: maxFileSize}
}

func (s *MetadataScanner) Name() string { return "metadata_scanner" }

func (s *MetadataScanner) Scan(file *FileInfo) ([]Finding, error) {
	var findings []Finding

	if file.Size > s.maxFileSize {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityHigh,
			Description: "File exceeds maximum allowed size",
			Details:     fmt.Sprintf("Size %d bytes exceeds %d byte limit", file.Size, s.maxFileSize),
		})
	}

	if file.Size == 0 {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityLow,
			Description: "Empty file uploaded", Details: "File has zero bytes",
		})
	}

	// Null bytes in text files may indicate binary injection
	if isTextFile(file) {
		nullCount := 0
		for _, b := range file.Content {
			if b == 0x00 {
				nullCount++
			}
		}
		if nullCount > 0 {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: SeverityMedium,
				Description: "Text file contains null bytes",
				Details:     fmt.Sprintf("Found %d null bytes — may indicate binary injection", nullCount),
			})
		}
	}

	findings = append(findings, checkFilename(file.Filename)...)
	return findings, nil
}

func isTextFile(file *FileInfo) bool {
	switch file.Extension {
	case ".txt", ".csv", ".json", ".xml", ".svg", ".html", ".htm":
		return true
	}
	return false
}

func checkFilename(name string) []Finding {
	var findings []Finding

	if len(name) > 255 {
		findings = append(findings, Finding{
			Scanner: "metadata_scanner", Severity: SeverityMedium,
			Description: "Filename exceeds maximum length",
			Details:     fmt.Sprintf("Filename is %d characters (max 255)", len(name)),
		})
	}

	// Double extensions: e.g. "report.pdf.exe"
	dots := 0
	for _, c := range name {
		if c == '.' {
			dots++
		}
	}
	if dots > 1 {
		findings = append(findings, Finding{
			Scanner: "metadata_scanner", Severity: SeverityHigh,
			Description: "File has multiple extensions",
			Details:     fmt.Sprintf("Filename %q has %d dots — possible extension spoofing", name, dots),
		})
	}

	return findings
}
