package scanner

import (
	"fmt"
	"time"
)

// Severity levels for scan findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents a single security issue found during scanning.
type Finding struct {
	Scanner     string   `json:"scanner"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Details     string   `json:"details,omitempty"`
}

// ScanResult is the aggregated result of all scanners.
type ScanResult struct {
	Safe       bool      `json:"safe"`
	Filename   string    `json:"filename"`
	FileSize   int64     `json:"file_size"`
	MIMEType   string    `json:"mime_type"`
	SHA256     string    `json:"sha256"`
	ScannedAt  time.Time `json:"scanned_at"`
	DurationMs int64     `json:"duration_ms"`
	Findings   []Finding `json:"findings"`
	Scanners   []string  `json:"scanners_run"`
}

// FileInfo holds metadata about the uploaded file.
type FileInfo struct {
	Filename  string
	Extension string
	MIMEType  string
	Size      int64
	SHA256    string
	Content   []byte
	TempPath  string
}

// Scanner is the interface all individual scanners must implement.
type Scanner interface {
	Name() string
	Scan(file *FileInfo) ([]Finding, error)
}

// Orchestrator runs all registered scanners against a file.
type Orchestrator struct {
	scanners []Scanner
}

// NewOrchestrator creates an orchestrator with the given scanners.
func NewOrchestrator(scanners ...Scanner) *Orchestrator {
	return &Orchestrator{scanners: scanners}
}

// Scan runs all registered scanners and returns aggregated results.
func (o *Orchestrator) Scan(file *FileInfo) *ScanResult {
	start := time.Now()

	result := &ScanResult{
		Safe:      true,
		Filename:  file.Filename,
		FileSize:  file.Size,
		MIMEType:  file.MIMEType,
		SHA256:    file.SHA256,
		ScannedAt: start.UTC(),
		Findings:  make([]Finding, 0),
		Scanners:  make([]string, 0, len(o.scanners)),
	}

	for _, s := range o.scanners {
		result.Scanners = append(result.Scanners, s.Name())

		findings, err := s.Scan(file)
		if err != nil {
			result.Findings = append(result.Findings, Finding{
				Scanner:     s.Name(),
				Severity:    SeverityMedium,
				Description: "Scanner error",
				Details:     fmt.Sprintf("Scanner %q encountered an error: %v", s.Name(), err),
			})
			continue
		}

		result.Findings = append(result.Findings, findings...)
	}

	for _, f := range result.Findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium {
			result.Safe = false
			break
		}
	}

	result.DurationMs = time.Since(start).Milliseconds()
	return result
}
