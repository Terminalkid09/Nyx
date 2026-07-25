package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

type Config struct {
	Domain       string
	Secret       string
	HTTPPort     int
	DNSPort      int
	APIPort      int
	InteractionTTL int // hours
	WebhookURL   string
	RateLimit    int // max interactions per token per second
}

func Load() (*Config, error) {
	domain := getEnv("COLLAB_DOMAIN", "oast.nyx.local")
	secret := getEnv("COLLAB_SECRET", "")
	if secret == "" {
		return nil, fmt.Errorf("COLLAB_SECRET is required")
	}

	httpPort := getEnvInt("COLLAB_HTTP_PORT", 9999)
	dnsPort := getEnvInt("COLLAB_DNS_PORT", 53)
	apiPort := getEnvInt("COLLAB_API_PORT", 9090)
	ttl := getEnvInt("COLLAB_TTL_HOURS", 24)
	rateLimit := getEnvInt("COLLAB_RATE_LIMIT", 10)

	if net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("COLLAB_DOMAIN must be a domain name, not an IP")
	}

	return &Config{
		Domain:         domain,
		Secret:         secret,
		HTTPPort:       httpPort,
		DNSPort:        dnsPort,
		APIPort:        apiPort,
		InteractionTTL: ttl,
		WebhookURL:     getEnv("COLLAB_WEBHOOK_URL", ""),
		RateLimit:      rateLimit,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
