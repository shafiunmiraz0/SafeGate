package scanner

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ClamAVScanner integrates with ClamAV daemon via TCP for antivirus scanning.
type ClamAVScanner struct {
	address string
	timeout time.Duration
}

func NewClamAVScanner(address string) *ClamAVScanner {
	return &ClamAVScanner{address: address, timeout: 30 * time.Second}
}

func (s *ClamAVScanner) Name() string { return "clamav_antivirus" }

func (s *ClamAVScanner) Scan(file *FileInfo) ([]Finding, error) {
	result, err := s.scanStream(file.Content)
	if err != nil {
		return nil, fmt.Errorf("ClamAV scan failed: %w", err)
	}

	var findings []Finding
	if strings.Contains(result, "FOUND") {
		virusName := extractVirusName(result)
		findings = append(findings, Finding{
			Scanner: s.Name(), Severity: SeverityCritical,
			Description: "Malware detected",
			Details:     fmt.Sprintf("ClamAV detected: %s", virusName),
		})
	}
	return findings, nil
}

// scanStream uses ClamAV's INSTREAM protocol over TCP.
func (s *ClamAVScanner) scanStream(data []byte) (string, error) {
	conn, err := net.DialTimeout("tcp", s.address, s.timeout)
	if err != nil {
		return "", fmt.Errorf("connect to ClamAV at %s: %w", s.address, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return "", err
	}

	// INSTREAM command
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", fmt.Errorf("send INSTREAM: %w", err)
	}

	// Send data in chunks with 4-byte big-endian length prefix
	const chunkSize = 2048
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		size := uint32(len(chunk))
		header := []byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)}
		if _, err := conn.Write(header); err != nil {
			return "", err
		}
		if _, err := conn.Write(chunk); err != nil {
			return "", err
		}
	}

	// Zero-length terminator
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	return strings.TrimSpace(string(response)), nil
}

func extractVirusName(result string) string {
	result = strings.TrimSpace(result)
	result = strings.TrimSuffix(result, "FOUND")
	result = strings.TrimPrefix(result, "stream:")
	result = strings.Trim(result, " \x00")
	if result == "" {
		return "Unknown threat"
	}
	return result
}
