package ui

import (
	"fmt"
	"net"
	"strings"
)

// TrustedProxies holds a list of CIDR ranges whose X-Forwarded-* headers
// are considered trustworthy. An empty list means no proxy is trusted and
// those headers are always ignored.
type TrustedProxies struct {
	networks []*net.IPNet
}

// NewTrustedProxies parses a slice of CIDR strings (e.g. "127.0.0.1/32",
// "10.0.0.0/8") into a TrustedProxies instance. Empty and whitespace-only
// entries are silently skipped. Returns an error if any non-empty entry is
// not a valid CIDR.
func NewTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		networks = append(networks, network)
	}
	return &TrustedProxies{networks: networks}, nil
}

// IsTrusted returns true if the given address (host:port or bare host) falls
// within one of the configured trusted CIDR ranges. Returns false when the
// trusted list is empty, when the address cannot be parsed, or when no range
// matches.
func (tp *TrustedProxies) IsTrusted(addr string) bool {
	if len(tp.networks) == 0 {
		return false
	}
	host := strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, network := range tp.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
