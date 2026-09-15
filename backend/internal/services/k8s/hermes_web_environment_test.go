package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestHermesTrustHonorsExplicitOriginAndRejectsUnboundedProxy(t *testing.T) {
	t.Setenv("CLAWMANAGER_HERMES_DESKTOP_WEB_ENABLED", "true")
	t.Setenv("CLAWMANAGER_CONTROL_UI_ORIGIN", "http://clawmanager-gateway.tenant.svc.cluster.local:9001")
	for _, proxy := range []string{"10.42.0.3/32", "0.0.0.0/0"} {
		d := BuildRuntimeDeployment(RuntimeDeploymentSpec{Name: "hermes-runtime", Namespace: "tenant", RuntimeType: "hermes", Image: "new", Replicas: 1})
		d.Spec.Template.Spec.Containers[0].Env = append(d.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: "CLAWMANAGER_TRUSTED_PROXY_CIDRS", Value: proxy})
		s := &runtimeDeploymentService{client: fake.NewSimpleClientset(d)}
		values, err := s.HermesGatewayEnvironment(context.Background(), "tenant", "hermes-runtime")
		if proxy == "0.0.0.0/0" {
			if err == nil {
				t.Fatal("unbounded proxy accepted")
			}
		} else if err != nil || values["CLAWMANAGER_TRUSTED_PROXY_CIDRS"] != proxy {
			t.Fatalf("values=%v error=%v", values, err)
		}
	}
}
