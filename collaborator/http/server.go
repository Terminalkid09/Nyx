package http

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Terminalkid09/nyx/collaborator/config"
	"github.com/Terminalkid09/nyx/collaborator/storage"
)

type Server struct {
	config *config.Config
	store  *storage.Store
	domain string
	mux    *http.ServeMux
}

func New(cfg *config.Config, store *storage.Store) *Server {
	s := &Server{
		config: cfg,
		store:  store,
		domain: strings.ToLower(strings.TrimSuffix(cfg.Domain, ".")),
		mux:    http.NewServeMux(),
	}

	s.mux.HandleFunc("/api/v1/interactions", s.handlePoll)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/", s.handleInteraction)

	return s
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.HTTPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}

	log.Printf("[http] listening on %s (domain: %s)", addr, s.domain)

	httpServer := &http.Server{
		Handler:      s,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return httpServer.Serve(ln)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleInteraction(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.Split(r.Host, ":")[0])

	var token string
	if strings.HasSuffix(host, "."+s.domain) && host != s.domain {
		token = storage.ParseToken(s.domain, host)
	}

	if token == "" {
		token = "unauthenticated"
	}

	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	remoteStr := s.splitHostPort(r.RemoteAddr)

	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	log.Printf("[http] %s %s from %s (token: %s, host: %s)", r.Method, r.URL.String(), remoteStr, token, host)

	isHTTPS := r.TLS != nil
	it := storage.InteractionHTTP
	if isHTTPS {
		it = storage.InteractionHTTPS
	}

	s.store.Record(token, it, remoteStr, map[string]string{
		"method":     r.Method,
		"url":        r.URL.String(),
		"headers":    formatHeaders(headers),
		"body":       string(body),
		"user_agent": r.UserAgent(),
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	if secret != s.config.Secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	since := time.Now().UTC().Add(-time.Duration(s.config.InteractionTTL) * time.Hour)
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	interactions := s.store.Poll(token, since)
	if interactions == nil {
		interactions = []storage.Interaction{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interactions": interactions,
		"count":        len(interactions),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) splitHostPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func formatHeaders(h map[string]string) string {
	var parts []string
	for k, v := range h {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, "\n")
}
