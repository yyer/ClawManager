package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// MetricsService talks to the in-cluster metrics-server (metrics.k8s.io API)
// to recover Pod-level resource usage. We use the bare REST client + manual
// JSON parsing instead of pulling in k8s.io/metrics so the dependency surface
// stays small.
type MetricsService struct {
	client *Client
}

func NewMetricsService() *MetricsService {
	return &MetricsService{client: globalClient}
}

// PodCPUUsage represents the parsed Pod CPU usage from metrics-server.
type PodCPUUsage struct {
	// UsageMillicores is the total CPU usage of all containers in the pod,
	// expressed in millicores (1 core = 1000 millicores).
	UsageMillicores int64
	// MemoryBytes is the total memory usage of all containers in the pod.
	MemoryBytes int64
}

// GetPodCPUUsage queries metrics.k8s.io for the pod and returns CPU usage in
// millicores. Returns nil + nil error if metrics-server is unavailable or the
// pod has no metrics yet (e.g. just started) — caller should treat that as a
// "no live data" signal rather than a hard failure.
func (s *MetricsService) GetPodCPUUsage(ctx context.Context, namespace, name string) (*PodCPUUsage, error) {
	if s.client == nil {
		return nil, fmt.Errorf("k8s client not initialized")
	}
	if strings.TrimSpace(namespace) == "" || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("namespace and name required")
	}

	path := fmt.Sprintf("/apis/metrics.k8s.io/v1beta1/namespaces/%s/pods/%s", namespace, name)
	raw, err := s.client.Clientset.RESTClient().Get().AbsPath(path).DoRaw(ctx)
	if err != nil {
		// metrics-server may be unavailable; surface as soft failure (nil, nil)
		// so the caller can simply omit the metric and the UI falls back.
		return nil, nil
	}

	// PodMetrics shape:
	//   {"containers":[{"name":"...","usage":{"cpu":"714m","memory":"2410Mi"}}, ...]}
	var pm struct {
		Containers []struct {
			Name  string `json:"name"`
			Usage struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
			} `json:"usage"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(raw, &pm); err != nil {
		return nil, fmt.Errorf("decode pod metrics: %w", err)
	}

	var totalMilli int64
	var totalMem int64
	for _, c := range pm.Containers {
		totalMilli += parseCPUToMillicores(c.Usage.CPU)
		totalMem += parseMemoryToBytes(c.Usage.Memory)
	}
	return &PodCPUUsage{UsageMillicores: totalMilli, MemoryBytes: totalMem}, nil
}

// parseCPUToMillicores accepts metrics-server style values like "714m",
// "2", "1500000n" (nanocores) and returns the value in millicores. Anything
// unparseable returns 0.
func parseCPUToMillicores(v string) int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	switch {
	case strings.HasSuffix(v, "n"):
		// nanocores → millicores
		num, err := strconv.ParseInt(strings.TrimSuffix(v, "n"), 10, 64)
		if err != nil {
			return 0
		}
		return num / 1_000_000
	case strings.HasSuffix(v, "u"):
		// microcores → millicores
		num, err := strconv.ParseInt(strings.TrimSuffix(v, "u"), 10, 64)
		if err != nil {
			return 0
		}
		return num / 1_000
	case strings.HasSuffix(v, "m"):
		num, err := strconv.ParseInt(strings.TrimSuffix(v, "m"), 10, 64)
		if err != nil {
			return 0
		}
		return num
	default:
		// bare number means cores
		num, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0
		}
		return int64(num * 1000)
	}
}

func parseMemoryToBytes(v string) int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	// Suffix table for Kubernetes quantity (binary + SI). Order matters: try
	// the longer suffix first.
	multipliers := []struct {
		suf string
		mul int64
	}{
		{"Ei", 1 << 60}, {"Pi", 1 << 50}, {"Ti", 1 << 40}, {"Gi", 1 << 30}, {"Mi", 1 << 20}, {"Ki", 1 << 10},
		{"E", 1e18}, {"P", 1e15}, {"T", 1e12}, {"G", 1e9}, {"M", 1e6}, {"k", 1e3},
	}
	for _, m := range multipliers {
		if strings.HasSuffix(v, m.suf) {
			num, err := strconv.ParseFloat(strings.TrimSuffix(v, m.suf), 64)
			if err != nil {
				return 0
			}
			return int64(num * float64(m.mul))
		}
	}
	num, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return num
}
