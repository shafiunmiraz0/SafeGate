package scanner

import (
	"regexp"
	"strings"
)

// SVGScanner detects XSS attacks and malicious content embedded in SVG files.
type SVGScanner struct{}

func NewSVGScanner() *SVGScanner { return &SVGScanner{} }

func (s *SVGScanner) Name() string { return "svg_xss_scanner" }

func (s *SVGScanner) Scan(file *FileInfo) ([]Finding, error) {
	if !isSVG(file) {
		return nil, nil
	}

	var findings []Finding
	content := strings.ToLower(string(file.Content))

	checks := []struct {
		pattern  *regexp.Regexp
		severity Severity
		desc     string
		details  string
	}{
		{scriptTagPattern, SeverityCritical, "SVG contains <script> tags",
			"Inline JavaScript in SVG files can execute XSS attacks when rendered in a browser"},
		{eventHandlerPattern, SeverityCritical, "SVG contains event handler attributes",
			"Event handlers like onload/onclick can execute arbitrary JavaScript"},
		{jsURIPattern, SeverityCritical, "SVG contains javascript: URI",
			"javascript: URIs in SVG attributes can execute arbitrary code"},
		{dataURIPattern, SeverityHigh, "SVG contains data: URI",
			"data: URIs in SVG can embed executable content or exfiltrate data"},
		{foreignObjectPattern, SeverityHigh, "SVG contains <foreignObject> element",
			"foreignObject can embed arbitrary HTML/XHTML inside SVG, enabling XSS"},
		{xlinkPattern, SeverityMedium, "SVG contains external resource references",
			"External xlink:href references can load malicious content or leak data"},
		{base64EmbedPattern, SeverityMedium, "SVG contains embedded base64 data",
			"Base64-encoded content in SVG may hide malicious payloads"},
	}

	for _, c := range checks {
		if c.pattern.MatchString(content) {
			findings = append(findings, Finding{
				Scanner:     s.Name(),
				Severity:    c.severity,
				Description: c.desc,
				Details:     c.details,
			})
		}
	}

	return findings, nil
}

func isSVG(file *FileInfo) bool {
	if strings.EqualFold(file.Extension, ".svg") {
		return true
	}
	mime := strings.ToLower(file.MIMEType)
	return strings.Contains(mime, "svg")
}

var (
	scriptTagPattern     = regexp.MustCompile(`<\s*script[\s>]`)
	eventHandlerPattern  = regexp.MustCompile(`\bon\w+\s*=`)
	jsURIPattern         = regexp.MustCompile(`javascript\s*:`)
	dataURIPattern       = regexp.MustCompile(`data\s*:\s*[^,]*;`)
	foreignObjectPattern = regexp.MustCompile(`<\s*foreignobject[\s>]`)
	xlinkPattern         = regexp.MustCompile(`xlink:href\s*=\s*["']https?://`)
	base64EmbedPattern   = regexp.MustCompile(`base64\s*,\s*[A-Za-z0-9+/]{100,}`)
)
