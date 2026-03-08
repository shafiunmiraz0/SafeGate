package scanner

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
)

// ArchiveScanner detects zip bombs, path traversal, and malicious archives.
type ArchiveScanner struct {
	maxDepth        int
	maxDecompressed int64
}

func NewArchiveScanner(maxDepth int, maxDecompressed int64) *ArchiveScanner {
	return &ArchiveScanner{maxDepth: maxDepth, maxDecompressed: maxDecompressed}
}

func (s *ArchiveScanner) Name() string { return "archive_bomb_scanner" }

func (s *ArchiveScanner) Scan(file *FileInfo) ([]Finding, error) {
	if !isArchive(file) {
		return nil, nil
	}

	var findings []Finding

	if isZipArchive(file) {
		f, err := s.analyzeZip(file.Content, 0)
		if err != nil {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: SeverityMedium,
				Description: "Failed to analyze archive", Details: err.Error(),
			})
		}
		findings = append(findings, f...)
	}

	return findings, nil
}

func (s *ArchiveScanner) analyzeZip(data []byte, depth int) ([]Finding, error) {
	var findings []Finding

	if depth > s.maxDepth {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityHigh,
			Description: "Archive exceeds maximum nesting depth",
			Details:     fmt.Sprintf("Depth %d exceeds limit %d — possible zip bomb", depth, s.maxDepth),
		})
		return findings, nil
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to read zip: %w", err)
	}

	var totalUncompressed uint64
	var fileCount int

	for _, f := range reader.File {
		fileCount++
		totalUncompressed += f.UncompressedSize64

		// Compression ratio bomb detection
		if f.CompressedSize64 > 0 {
			ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64)
			if ratio > 100 {
				findings = append(findings, Finding{
					Scanner: s.Name(), Severity: SeverityCritical,
					Description: "Possible zip bomb detected",
					Details:     fmt.Sprintf("File %q has %.0f:1 compression ratio", f.Name, ratio),
				})
			}
		}

		if int64(totalUncompressed) > s.maxDecompressed {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: SeverityCritical,
				Description: "Archive decompressed size exceeds limit",
				Details:     fmt.Sprintf("Total %d bytes exceeds %d byte limit", totalUncompressed, s.maxDecompressed),
			})
			return findings, nil
		}

		// Path traversal
		if strings.Contains(f.Name, "..") {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: SeverityCritical,
				Description: "Archive contains path traversal",
				Details:     fmt.Sprintf("Entry %q contains '..' — directory traversal attack", f.Name),
			})
		}

		// Executables inside archive
		if isExecutableExtension(strings.ToLower(f.Name)) {
			findings = append(findings, Finding{
				Scanner: s.Name(), Severity: SeverityHigh,
				Description: "Archive contains executable file",
				Details:     fmt.Sprintf("Found executable: %q", f.Name),
			})
		}
	}

	if fileCount > 10000 {
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityHigh,
			Description: "Archive contains excessive files",
			Details:     fmt.Sprintf("%d files — possible resource exhaustion", fileCount),
		})
	}

	return findings, nil
}

func isArchive(file *FileInfo) bool {
	ext := strings.ToLower(file.Extension)
	switch ext {
	case ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
		".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".jar":
		return true
	}
	mime := strings.ToLower(file.MIMEType)
	return strings.Contains(mime, "zip") || strings.Contains(mime, "rar") ||
		strings.Contains(mime, "7z") || strings.Contains(mime, "compressed")
}

func isZipArchive(file *FileInfo) bool {
	if len(file.Content) >= 4 &&
		file.Content[0] == 0x50 && file.Content[1] == 0x4B &&
		file.Content[2] == 0x03 && file.Content[3] == 0x04 {
		return true
	}
	ext := strings.ToLower(file.Extension)
	switch ext {
	case ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".jar":
		return true
	}
	return false
}

func isExecutableExtension(name string) bool {
	exts := []string{".exe", ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
		".sh", ".bash", ".ps1", ".vbs", ".vbe", ".js", ".wsh", ".wsf"}
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
