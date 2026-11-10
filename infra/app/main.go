// Login service for the lab: POST /login returns 401 on bad credentials and
// 200 on good ones, and writes each attempt as a JSON line to auth.json.
package main

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"os"
)

const authLog = "/var/log/kmam/app/auth.json"

func newHandler(user, pass string, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		u, p := r.FormValue("username"), r.FormValue("password")
		// X-Real-IP is set by Nginx; the app is reachable only from the
		// internal Docker network, so clients cannot set it themselves.
		ip := r.Header.Get("X-Real-IP")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		ok := subtle.ConstantTimeCompare([]byte(u), []byte(user)) &
			subtle.ConstantTimeCompare([]byte(p), []byte(pass))
		if ok != 1 {
			log.Info("login_failed", "user", u, "srcip", ip)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		log.Info("login_success", "user", u, "srcip", ip)
		w.Write([]byte("ok\n"))
	})
	return mux
}

func main() {
	user, pass := os.Getenv("APP_USER"), os.Getenv("APP_PASSWORD")
	if user == "" || pass == "" {
		slog.Error("APP_USER and APP_PASSWORD must be set")
		os.Exit(1)
	}
	f, err := os.OpenFile(authLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Error("open auth log", "err", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(f, nil))
	slog.Error("server stopped", "err", http.ListenAndServe(":8080", newHandler(user, pass, log)))
	os.Exit(1)
}
