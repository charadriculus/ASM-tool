// Package resource defines offline downloadable-resource evidence shared by HTTP and browser callers.
package resource

import (
	"asmtool/internal/core"
	"net/url"
	"sort"
	"strings"
)

var downloadableExtensions = map[string]string{
	".pdf": "PDF document",
	".doc": "Word document", ".docx": "Word document", ".odt": "text document",
	".xls": "Excel spreadsheet", ".xlsx": "Excel spreadsheet", ".ods": "spreadsheet",
	".ppt": "presentation", ".pptx": "presentation", ".odp": "presentation",
	".zip": "archive", ".rar": "archive", ".7z": "archive", ".tar": "archive",
	".gz": "archive", ".bz2": "archive", ".xz": "archive",
	".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
	".webp": "image", ".svg": "image",
	".mp3": "audio file", ".wav": "audio file", ".ogg": "media file",
	".mp4": "video file", ".webm": "video file", ".avi": "video file", ".mov": "video file",
	".exe": "executable", ".msi": "installer package", ".apk": "application package",
	".iso": "disk image", ".dmg": "disk image",
}

// This fixed table normalizes supported suffixes across hosts; Python's system
// MIME databases can vary by OS.
var downloadMIMETypes = map[string]string{
	".pdf": "application/pdf", ".doc": "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".odt":  "application/vnd.oasis.opendocument.text", ".xls": "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ods":  "application/vnd.oasis.opendocument.spreadsheet", ".ppt": "application/vnd.ms-powerpoint",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".odp":  "application/vnd.oasis.opendocument.presentation", ".zip": "application/zip",
	".rar": "application/vnd.rar", ".7z": "application/x-7z-compressed", ".tar": "application/x-tar",
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif",
	".webp": "image/webp", ".svg": "image/svg+xml", ".mp3": "audio/mpeg",
	".wav": "audio/x-wav", ".ogg": "audio/ogg", ".mp4": "video/mp4", ".webm": "video/webm",
	".avi": "video/x-msvideo", ".mov": "video/quicktime", ".exe": "application/x-msdos-program",
	".msi": "application/x-msi", ".apk": "application/vnd.android.package-archive",
	".iso": "application/x-iso9660-image", ".dmg": "application/x-apple-diskimage",
}

// DownloadInfo classifies a URL or a response that represents a downloadable resource.
type DownloadInfo struct {
	ResourceType       string `json:"resource_type"`
	Extension          string `json:"extension"`
	ContentType        string `json:"content_type"`
	ContentDisposition string `json:"content_disposition"`
}

// DownloadableResourceInfo mirrors capture.downloadable_resource_info.
func DownloadableResourceInfo(rawURL, contentType, contentDisposition string) (DownloadInfo, bool) {
	u, err := url.Parse(rawURL)
	urlPath := rawURL
	if err == nil {
		urlPath = u.EscapedPath()
	}
	urlPath = strings.ToLower(urlPath)
	ext, label := "", ""
	for suffix, candidate := range downloadableExtensions {
		if strings.HasSuffix(urlPath, suffix) && len(suffix) > len(ext) {
			ext, label = suffix, candidate
		}
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	disposition := strings.ToLower(contentDisposition)
	attachment := strings.Contains(disposition, "attachment")
	nonHTML := mediaType != "" && mediaType != "text/html" && mediaType != "application/xhtml+xml" &&
		mediaType != "text/plain" && mediaType != "application/json" && mediaType != "application/xml" &&
		mediaType != "text/xml"
	if ext == "" && !attachment && !nonHTML {
		return DownloadInfo{}, false
	}
	if label == "" {
		switch {
		case mediaType == "application/pdf":
			label = "PDF document"
		case strings.HasPrefix(mediaType, "image/"):
			label = "image"
		case strings.HasPrefix(mediaType, "audio/"):
			label = "audio file"
		case strings.HasPrefix(mediaType, "video/"):
			label = "video file"
		case strings.Contains(mediaType, "zip") || strings.Contains(mediaType, "compressed") || strings.Contains(mediaType, "archive"):
			label = "archive"
		default:
			label = "downloadable resource"
		}
	}
	if mediaType == "" && ext != "" {
		mimePath := urlPath
		for _, suffix := range []string{".gz", ".bz2", ".xz"} {
			if strings.HasSuffix(mimePath, suffix) {
				mimePath = strings.TrimSuffix(mimePath, suffix)
				break
			}
		}
		bestSuffix := ""
		for suffix, candidate := range downloadMIMETypes {
			if strings.HasSuffix(mimePath, suffix) && len(suffix) > len(bestSuffix) {
				bestSuffix, mediaType = suffix, candidate
			}
		}
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
	}
	if mediaType == "" {
		mediaType = "unknown"
	}
	return DownloadInfo{label, ext, mediaType, contentDisposition}, true
}

// DownloadEventInput holds the source fields used to create a crawler_result
// event for a detected but not downloaded resource.
type DownloadEventInput struct {
	Module, SourceTool, URL string
	TargetDomains           []string
	Phase                   string
	Depth                   int
	StatusCode              *int
	ContentType             string
	ContentDisposition      string
	NetworkContacted        bool
	DetectionReason         string
}

// NewDownloadEvent creates the crawler_result metadata consumed by crawler/web callers.
func NewDownloadEvent(in DownloadEventInput) (core.Event, error) {
	info, ok := DownloadableResourceInfo(in.URL, in.ContentType, in.ContentDisposition)
	if !ok {
		info = DownloadInfo{"downloadable resource", "", valueOr(in.ContentType, "unknown"), in.ContentDisposition}
	}
	reason := valueOr(in.DetectionReason, "url_extension")
	domains := append([]string{}, in.TargetDomains...)
	sort.Strings(domains)
	domains = uniqueStrings(domains)
	var statusCode any
	if in.StatusCode != nil {
		statusCode = *in.StatusCode
	}
	e, err := core.NewEvent(core.CrawlerResult, in.Module, in.SourceTool, in.URL, in.URL, core.InScope)
	if err != nil {
		return core.Event{}, err
	}
	e.Confidence = 0.8
	if reason == "response_headers" {
		e.Confidence = 0.9
	}
	e.Metadata = map[string]any{
		"resource_type": info.ResourceType, "extension": info.Extension,
		"content_type": info.ContentType, "content_disposition": info.ContentDisposition,
		"category": "downloadable_resource_detected", "phase": in.Phase, "depth": in.Depth,
		"origin": origin(in.URL), "target_domains": domains, "status_code": statusCode,
		"page_loaded": false, "screenshot_expected": false, "screenshot_saved": false,
		"downloaded": false, "network_contacted": in.NetworkContacted, "detection_reason": reason,
	}
	return e, nil
}

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "://"
	}
	// Python urlsplit().netloc includes userinfo, so preserve it here as well.
	authority := strings.ToLower(u.Host)
	if u.User != nil {
		authority = strings.ToLower(u.User.String()) + "@" + authority
	}
	return strings.ToLower(u.Scheme) + "://" + authority
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
