package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLogin(t *testing.T) {
	cases := []struct {
		pass, msg string
		code      int
	}{
		{"wrong", "login_failed", http.StatusUnauthorized},
		{"secret", "login_success", http.StatusOK},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		h := newHandler("alice", "secret", slog.New(slog.NewJSONHandler(&buf, nil)))

		form := url.Values{"username": {"alice"}, "password": {c.pass}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "203.0.113.7")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != c.code {
			t.Errorf("pass=%q: code %d, want %d", c.pass, rec.Code, c.code)
		}
		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("pass=%q: log is not one JSON line: %v: %q", c.pass, err, buf.String())
		}
		if line["msg"] != c.msg || line["user"] != "alice" || line["srcip"] != "203.0.113.7" {
			t.Errorf("pass=%q: unexpected log line %v", c.pass, line)
		}
	}
}
