package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

// Epoch control never uses scheduler placement or legacy sandbox proxy authority.
// Until verified enrollment routing is installed, reserve these paths before both
// generic authentication classification and proxy routing, including proxy aliases.
func refuseDormantProcessEpoch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reservedProcessEpochPath(r.URL.EscapedPath()) {
			http.Error(w, "managed process epochs unavailable", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func reservedProcessEpochPath(path string) bool {
	for i := 0; i < 8; i++ {
		decoded, err := url.PathUnescape(path)
		if err != nil || decoded == path {
			break
		}
		path = decoded
	}
	parts := strings.Split(strings.TrimLeft(path, "/"), "/")
	for len(parts) > 0 && parts[0] == "proxy" {
		parts = parts[1:]
	}
	// Guest paths also arrive via host/header routing or without a sandbox prefix.
	if len(parts) > 0 && (parts[0] == "process-epochs" || parts[0] == "process-epoch-operations") {
		return true
	}
	if len(parts) < 3 || parts[0] != "sandboxes" {
		return false
	}
	return parts[2] == "process-epochs" || parts[2] == "process-epoch-operations"
}
