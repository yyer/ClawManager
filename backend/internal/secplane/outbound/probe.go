package outbound

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeResult — TLS 握手抓到的 leaf cert 摘要。
type ProbeResult struct {
	Host              string    `json:"host"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	SubjectCN         string    `json:"subject_cn"`
	Issuer            string    `json:"issuer"`
	NotAfter          time.Time `json:"not_after"`
}

// ProbeTLS 拨号 host:port，跳过证书链验证只为抓取 leaf cert
// （用于建立白名单基线指纹，验证链路是上层 ClawAegis 的事）。
func ProbeTLS(host string, port int) (*ProbeResult, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if strings.ContainsAny(host, "*?") {
		return nil, fmt.Errorf("wildcard host %q not supported for probe; use a concrete subdomain", host)
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("no leaf cert from %s", addr)
	}
	leaf := chain[0]
	sum := sha256.Sum256(leaf.Raw)
	return &ProbeResult{
		Host:              host,
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		SubjectCN:         leaf.Subject.CommonName,
		Issuer:            leaf.Issuer.CommonName,
		NotAfter:          leaf.NotAfter,
	}, nil
}
