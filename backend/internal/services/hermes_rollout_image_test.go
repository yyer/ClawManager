package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveHermesRolloutImage(t *testing.T) {
	body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(body)))
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v2/runtime/hermes/manifests/test" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", digest)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	repository := strings.TrimPrefix(server.URL, "http://") + "/runtime/hermes"
	got, err := ResolveHermesRolloutImage(context.Background(), repository+":test")
	if err != nil || got != repository+"@"+digest {
		t.Fatalf("got %q, %v", got, err)
	}
	before := calls
	got, err = ResolveHermesRolloutImage(context.Background(), repository+"@"+digest)
	if err != nil || got != repository+"@"+digest || calls != before {
		t.Fatalf("digest pass-through: %q %v calls=%d", got, err, calls)
	}
	for _, input := range []string{repository + "@sha256:bad", repository + ":missing", "https://example.com/x:v1", repository + "/../bad:v1"} {
		if _, err := ResolveHermesRolloutImage(context.Background(), input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestResolveHermesRolloutImageRejectsMismatchAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
		fmt.Fprint(w, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	}))
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "http://") + "/hermes:test"
	if _, err := ResolveHermesRolloutImage(context.Background(), target); err == nil {
		t.Fatal("accepted mismatched manifest digest")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveHermesRolloutImage(ctx, target); err == nil {
		t.Fatal("ignored cancelled request")
	}
}
