// Tests the prototype's request boundary before a scanner can start.
package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectScanRequest(t *testing.T) {
	const host = "127.0.0.1:9002"
	const origin = "http://" + host
	for _, tc := range []struct {
		name, host, origin, media, body string
		want                            int
	}{
		{"foreign origin", host, "https://example.org", "application/json", `{"target":"localhost"}`, 403},
		{"foreign host", "example.org:9002", origin, "application/json", `{"target":"localhost"}`, 403},
		{"form body", host, origin, "text/plain", `{"target":"localhost"}`, 415},
		{"outside range", host, origin, "application/json", `{"target":"192.0.2.1","force":true}`, 400},
		{"overlapping range", host, origin, "application/json", `{"target":"127.0.0.1/7","force":true}`, 400},
		{"blank target", host, origin, "application/json", `{"target":" "}`, 400},
		{"bad timeout", host, origin, "application/json", `{"target":"localhost","timeout":"later"}`, 400},
		{"client executable", host, origin, "application/json", `{"target":"localhost","nmap_path":"other"}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://"+tc.host+"/api/scan", strings.NewReader(tc.body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", tc.media)
			w := httptest.NewRecorder()
			handleScan(w, r, host, "")
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}
