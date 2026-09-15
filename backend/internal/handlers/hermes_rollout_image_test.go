package handlers

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHermesRolloutTagResolutionBeforeCreate(t *testing.T) {
	body := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer registry.Close()
	repository := strings.TrimPrefix(registry.URL, "http://") + "/hermes"
	for _, tag := range []string{"test", "missing"} {
		repo := &runtimePoolHandlerRolloutRepo{}
		events := &runtimePoolHandlerEvents{}
		handler := NewRuntimePoolHandler(&runtimePoolHandlerPodRepo{}, &runtimePoolHandlerBindingRepo{}, repo, nil, events)
		router := runtimePoolHandlerRouter(7, "admin", handler)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/runtime-rollouts", bytes.NewBufferString(fmt.Sprintf(`{"runtime_type":"hermes","target_image_ref":%q}`, repository+":"+tag)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if tag == "missing" {
			if rec.Code != 409 || repo.created != nil || events.lastType != "" {
				t.Fatalf("failed resolution created work: %d %s", rec.Code, rec.Body.String())
			}
		} else {
			want := fmt.Sprintf("%s@sha256:%x", repository, sha256.Sum256([]byte(body)))
			if rec.Code != 201 || repo.created == nil || repo.created.TargetImageRef != want {
				t.Fatalf("unpinned task: %d %s", rec.Code, rec.Body.String())
			}
		}
	}
}
