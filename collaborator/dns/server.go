package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Terminalkid09/nyx/collaborator/config"
	"github.com/Terminalkid09/nyx/collaborator/storage"
)

type Server struct {
	config *config.Config
	store  *storage.Store
	domain string
}

func New(cfg *config.Config, store *storage.Store) *Server {
	return &Server{
		config: cfg,
		store:  store,
		domain: strings.ToLower(strings.TrimSuffix(cfg.Domain, ".")),
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.DNSPort)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dns listen: %w", err)
	}
	defer pc.Close()

	log.Printf("[dns] listening on %s (domain: %s)", addr, s.domain)

	buf := make([]byte, 512)
	for {
		pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[dns] read error: %v", err)
			continue
		}

		go s.handle(pc, addr, buf[:n])
	}
}

func (s *Server) handle(pc net.PacketConn, addr net.Addr, data []byte) {
	if len(data) < 12 {
		return
	}

	id := uint16(data[0])<<8 | uint16(data[1])
	qdcount := uint16(data[4])<<8 | uint16(data[5])

	if qdcount == 0 {
		return
	}

	offset := 12
	qname, _, err := parseName(data, offset)
	if err != nil {
		return
	}

	qnameStr := strings.ToLower(string(qname))
	qtype := uint16(data[offset])<<8 | uint16(data[offset+1])

	if !strings.HasSuffix(qnameStr, "."+s.domain) && qnameStr != s.domain {
		s.respondNX(pc, addr, data, id)
		return
	}

	token := storage.ParseToken(s.domain, qnameStr)
	remoteStr := storage.ParseRemoteAddr(addr)

	qtypeStr := dnsTypeToString(qtype)

	log.Printf("[dns] query: %s (%s) from %s", qnameStr, qtypeStr, remoteStr)

	s.store.Record(token, storage.InteractionDNS, remoteStr, map[string]string{
		"query_type": qtypeStr,
		"query_name": qnameStr,
	})

	s.respondNX(pc, addr, data, id)
}

func parseName(data []byte, offset int) ([]byte, int, error) {
	var labels []string

	for {
		if offset >= len(data) {
			return nil, offset, fmt.Errorf("truncated")
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 == 0xc0 {
			offset += 2
			break
		}
		offset++
		if offset+length > len(data) {
			return nil, offset, fmt.Errorf("label too long")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	name := strings.Join(labels, ".")
	return []byte(name), offset, nil
}

func (s *Server) respondNX(pc net.PacketConn, addr net.Addr, query []byte, id uint16) {
	resp := make([]byte, len(query)+4)
	copy(resp[:2], []byte{byte(id >> 8), byte(id & 0xff)})
	resp[2] = 0x81
	resp[3] = 0x83
	resp[4] = byte(len(query) >> 8)
	resp[5] = byte(len(query) & 0xff)
	resp[6] = 0
	resp[7] = 0
	resp[8] = 0
	resp[9] = 0
	resp[10] = 0
	resp[11] = 0
	copy(resp[12:], query[12:])

	pc.WriteTo(resp, addr)
}

func dnsTypeToString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}
