package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var hermesDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var hermesRepositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
var hermesTagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// ResolveHermesRolloutImage freezes a tag before the job is persisted. Never
// change runtime resources when resolution fails, or weaken Runtime validation.
func ResolveHermesRolloutImage(ctx context.Context, image string) (string, error) {
	image = strings.TrimSpace(image)
	host, path, ok := strings.Cut(image, "/")
	if !ok || strings.ContainsAny(image, " \t\r\n?#") || strings.Contains(image, "://") {
		return "", fmt.Errorf("Hermes image must include a registry and tag or sha256 digest")
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.User != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid Hermes registry")
	}
	repository, reference, isDigest := strings.Cut(path, "@")
	if isDigest {
		if colon := strings.LastIndex(repository, ":"); colon >= 0 {
			if !hermesTagPattern.MatchString(repository[colon+1:]) {
				return "", fmt.Errorf("invalid Hermes image tag")
			}
			repository = repository[:colon]
		}
	} else {
		colon := strings.LastIndex(path, ":")
		if colon < 0 {
			return "", fmt.Errorf("Hermes image requires an explicit tag or digest")
		}
		repository, reference = path[:colon], path[colon+1:]
	}
	if !hermesRepositoryPattern.MatchString(repository) {
		return "", fmt.Errorf("invalid Hermes image repository")
	}
	if isDigest {
		if !hermesDigestPattern.MatchString(reference) {
			return "", fmt.Errorf("invalid Hermes sha256 digest")
		}
		return host + "/" + repository + "@" + reference, nil
	}
	if !hermesTagPattern.MatchString(reference) {
		return "", fmt.Errorf("invalid Hermes image tag")
	}
	// Existing private registries use HTTP. Restrict plaintext to literal private
	// or loopback IPs with an explicit port; never downgrade public TLS failures.
	scheme := "https"
	if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) && u.Port() != "" {
		scheme = "http"
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/v2/"+repository+"/manifests/"+reference, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json")
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve Hermes image: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Hermes registry returned HTTP %d; for restricted registries supply a verified digest", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil {
		return "", err
	}
	if len(body) > 4*1024*1024 {
		return "", fmt.Errorf("Hermes manifest exceeds size limit")
	}
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if json.Unmarshal(body, &manifest) != nil || manifest.SchemaVersion != 2 {
		return "", fmt.Errorf("invalid Hermes registry manifest")
	}
	switch manifest.MediaType {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json":
	default:
		return "", fmt.Errorf("unsupported Hermes manifest media type")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	if advertised := response.Header.Get("Docker-Content-Digest"); advertised != "" && advertised != digest {
		return "", fmt.Errorf("Hermes registry manifest digest mismatch")
	}
	return host + "/" + repository + "@" + digest, nil
}
