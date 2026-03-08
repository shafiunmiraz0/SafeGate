package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/YourName/safegate/internal/scanner"
)

// ScanHandler handles file upload scanning requests.
type ScanHandler struct {
	orchestrator *scanner.Orchestrator
	maxFileSize  int64
}

func NewScanHandler(orch *scanner.Orchestrator, maxFileSize int64) *ScanHandler {
	return &ScanHandler{orchestrator: orch, maxFileSize: maxFileSize}
}

// ScanResponse is the JSON response for a scan request.
type ScanResponse struct {
	Success bool                `json:"success"`
	Message string              `json:"message"`
	Data    *scanner.ScanResult `json:"data,omitempty"`
}

// HandleScan processes POST /api/v1/scan multipart file uploads.
func (h *ScanHandler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ScanResponse{
			Success: false, Message: "Method not allowed. Use POST.",
		})
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, h.maxFileSize+1024) // +1KB for form overhead

	if err := r.ParseMultipartForm(h.maxFileSize); err != nil {
		writeJSON(w, http.StatusBadRequest, ScanResponse{
			Success: false, Message: "Failed to parse multipart form: " + err.Error(),
		})
		return
	}
	defer r.MultipartForm.RemoveAll()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ScanResponse{
			Success: false, Message: "Missing 'file' field in multipart form",
		})
		return
	}
	defer file.Close()

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ScanResponse{
			Success: false, Message: "Failed to read uploaded file",
		})
		return
	}

	// Build FileInfo
	ext := strings.ToLower(filepath.Ext(header.Filename))
	hash := sha256.Sum256(content)

	fileInfo := &scanner.FileInfo{
		Filename:  header.Filename,
		Extension: ext,
		MIMEType:  header.Header.Get("Content-Type"),
		Size:      int64(len(content)),
		SHA256:    fmt.Sprintf("%x", hash),
		Content:   content,
	}

	log.Printf("Scanning file: %s (%d bytes, type: %s)", fileInfo.Filename, fileInfo.Size, fileInfo.MIMEType)

	// Run all scanners
	result := h.orchestrator.Scan(fileInfo)

	status := http.StatusOK
	msg := "File scan complete — file is safe"
	if !result.Safe {
		status = http.StatusUnprocessableEntity
		msg = "File scan complete — threats detected"
	}

	writeJSON(w, status, ScanResponse{
		Success: result.Safe,
		Message: msg,
		Data:    result,
	})
}

// HandleHealth responds to GET /health for load balancer checks.
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"service": "safegate",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
