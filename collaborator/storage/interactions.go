package storage

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type InteractionType string

const (
	InteractionDNS   InteractionType = "dns"
	InteractionHTTP  InteractionType = "http"
	InteractionHTTPS InteractionType = "https"
)

type Interaction struct {
	ID         string            `json:"id"`
	Token      string            `json:"token"`
	Type       InteractionType   `json:"type"`
	Timestamp  time.Time         `json:"timestamp"`
	RemoteAddr string            `json:"remote_addr"`
	QueryType  string            `json:"query_type,omitempty"`
	QueryName  string            `json:"query_name,omitempty"`
	Method     string            `json:"method,omitempty"`
	URL        string            `json:"url,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
}

type Notifier interface {
	InteractionReceived(token string, interaction Interaction)
}

type Store struct {
	mu           sync.RWMutex
	interactions []Interaction
	ttl          time.Duration
	nextID       int64
	notifier     Notifier
}

func New(ttlHours int) *Store {
	return &Store{
		ttl: time.Duration(ttlHours) * time.Hour,
	}
}

func (s *Store) SetNotifier(n Notifier) {
	s.notifier = n
}

func (s *Store) Record(token string, typ InteractionType, remoteAddr string, details map[string]string) *Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.evict()

	s.nextID++

	it := Interaction{
		ID:         fmt.Sprintf("int-%s-%d", token, s.nextID),
		Token:      token,
		Type:       typ,
		Timestamp:  time.Now().UTC(),
		RemoteAddr: remoteAddr,
	}

	switch typ {
	case InteractionDNS:
		it.QueryType = details["query_type"]
		it.QueryName = details["query_name"]
	case InteractionHTTP, InteractionHTTPS:
		it.Method = details["method"]
		it.URL = details["url"]
		it.Body = details["body"]
		it.UserAgent = details["user_agent"]
		if h := details["headers"]; h != "" {
			it.Headers = map[string]string{"raw": h}
		}
	}

	s.interactions = append(s.interactions, it)

	if s.notifier != nil {
		s.notifier.InteractionReceived(token, it)
	}

	return &it
}

func (s *Store) Poll(token string, since time.Time) []Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Interaction
	for _, it := range s.interactions {
		if it.Token == token && it.Timestamp.After(since) {
			result = append(result, it)
		}
	}
	return result
}

func (s *Store) evict() {
	cutoff := time.Now().UTC().Add(-s.ttl)
	var kept []Interaction
	for _, it := range s.interactions {
		if it.Timestamp.After(cutoff) {
			kept = append(kept, it)
		}
	}
	s.interactions = kept
}

func ParseToken(domain, queryName string) string {
	r := strings.TrimSuffix(queryName, "."+domain)
	if r == domain || r == "" {
		return ""
	}
	parts := strings.SplitN(r, ".", 2)
	return parts[0]
}

func ParseRemoteAddr(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	}
	return strings.Split(addr.String(), ":")[0]
}
