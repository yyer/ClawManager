package k8s

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hermes trust comes only from deployment/operator configuration and verified
// Kubernetes endpoints, never from a browser Origin or a workspace file.
func (s *runtimeDeploymentService) HermesGatewayEnvironment(ctx context.Context, namespace, name string) (map[string]string, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CLAWMANAGER_HERMES_DESKTOP_WEB_ENABLED")), "true") {
		return nil, nil
	}
	d, err := s.client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if d.Labels["clawmanager.io/runtime-type"] != "hermes" {
		return nil, fmt.Errorf("Hermes deployment identity mismatch")
	}
	values := map[string]string{}
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.Name == "runtime" {
			for _, e := range c.Env {
				if e.Name == "CLAWMANAGER_CONTROL_UI_ORIGIN" || e.Name == "CLAWMANAGER_TRUSTED_PROXY_CIDRS" || e.Name == "CLAWMANAGER_HERMES_PROXY_SOURCE" {
					if e.ValueFrom != nil {
						return nil, fmt.Errorf("Hermes trust setting %s has unresolved valueFrom", e.Name)
					}
					values[e.Name] = strings.ReplaceAll(strings.TrimSpace(e.Value), "$(HERMES_DEPLOYMENT_NAMESPACE)", namespace)
				}
			}
		}
	}
	origin := strings.TrimSpace(os.Getenv("CLAWMANAGER_CONTROL_UI_ORIGIN"))
	if values["CLAWMANAGER_CONTROL_UI_ORIGIN"] != "" && values["CLAWMANAGER_CONTROL_UI_ORIGIN"] != origin {
		return nil, fmt.Errorf("Hermes App and Runtime origins differ")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid Hermes control origin")
	}
	suffix := "." + namespace + ".svc.cluster.local"
	if !strings.HasSuffix(u.Hostname(), suffix) {
		return nil, fmt.Errorf("Hermes origin must be an internal Service in the runtime namespace")
	}
	serviceName := strings.TrimSuffix(u.Hostname(), suffix)
	if serviceName == "" || strings.Contains(serviceName, ".") {
		return nil, fmt.Errorf("invalid Hermes Service name")
	}
	proxies := values["CLAWMANAGER_TRUSTED_PROXY_CIDRS"]
	source := "explicit"
	if proxies == "" || values["CLAWMANAGER_HERMES_PROXY_SOURCE"] == "service-endpoints" {
		endpoints, err := s.client.CoreV1().Endpoints(namespace).Get(ctx, serviceName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("resolve Hermes trusted endpoints: %w", err)
		}
		addresses := map[string]bool{}
		for _, subset := range endpoints.Subsets {
			for _, a := range subset.Addresses {
				if a.TargetRef == nil || a.TargetRef.Kind != "Pod" || (a.TargetRef.Namespace != "" && a.TargetRef.Namespace != namespace) {
					continue
				}
				if ip := net.ParseIP(a.IP); ip != nil {
					addresses[ip.String()] = true
				}
			}
		}
		list := make([]string, 0, len(addresses))
		for a := range addresses {
			list = append(list, a)
		}
		sort.Strings(list)
		proxies = strings.Join(list, ",")
		source = "service-endpoints"
	}
	if proxies == "" {
		return nil, fmt.Errorf("no ready Hermes control-plane endpoints")
	}
	for _, p := range strings.Split(proxies, ",") {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) != nil {
			continue
		}
		_, network, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("invalid Hermes trusted proxy")
		}
		ones, _ := network.Mask.Size()
		if ones == 0 {
			return nil, fmt.Errorf("unbounded Hermes trusted proxy forbidden")
		}
	}
	return map[string]string{"CLAWMANAGER_HERMES_DESKTOP_WEB_ENABLED": "true", "CLAWMANAGER_CONTROL_UI_ORIGIN": origin, "CLAWMANAGER_TRUSTED_PROXY_CIDRS": proxies, "CLAWMANAGER_HERMES_PROXY_SOURCE": source}, nil
}
