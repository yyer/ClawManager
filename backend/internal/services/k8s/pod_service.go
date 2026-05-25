package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PodService handles Pod operations
type PodService struct {
	client *Client
}

const (
	podDeletionPollInterval = 500 * time.Millisecond
	podDeletionTimeout      = 60 * time.Second
)

// NewPodService creates a new Pod service
func NewPodService() *PodService {
	return &PodService{
		client: globalClient,
	}
}

// GetClient returns the k8s client
func (s *PodService) GetClient() *Client {
	return s.client
}

// podPostStartScript is the postStart hook body. /var/run is tmpfs, so all
// in-pod patches re-run on every pod startup — this hook is the source of
// truth, not the image. Does three things, each best-effort:
//
//  1. Xvfb max-clients patch: default 256 saturates after a few chromium /
//     plugin restart cycles; bumping to 2048 + dropping -noreset (so dead
//     clients release resources eagerly) keeps xclip / xdotool / chromium
//     reliable across long sessions.
//  2. Chromium autostart fix: the seeded openclaw-browser.desktop calls
//     xdg-open, which in this container falls through to a text-browser
//     fallback (links/lynx/elinks — none installed) because XDG_CURRENT_DESKTOP
//     is unset; chromium never launches. We rewrite the Exec line to invoke
//     chromium directly with --no-sandbox --kiosk so the WebChat tab appears
//     automatically.
//  3. workspace/skills → extensions sync watcher: install_skill drops the
//     plugin bundle in /config/.openclaw/workspace/skills/<name>/, but
//     OpenClaw only loads from /config/.openclaw/extensions/. Without this
//     watcher, install_skill silently succeeds but the plugin never runs.
//     Background polling daemon mirrors new/updated workspace skills into
//     extensions/, then kills openclaw-gateway so s6 / openclaw-agent reload
//     and pick up the plugin.
const podPostStartScript = `
set +e

# --- (1) Xvfb max-clients ---
SVCDIR=/var/run/s6-rc/servicedirs/svc-xorg
F=$SVCDIR/run
for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$F" ] && break; sleep 1; done
if [ -f "$F" ]; then
  if ! grep -q "maxclients 2048" "$F"; then
    sed -i 's|-screen 0|-maxclients 2048 \\\n    -screen 0|' "$F"
  fi
  sed -i '/-noreset/d' "$F"
  s6-svc -r "$SVCDIR" 2>/dev/null
fi

# --- (2) Chromium autostart ---
# Wait briefly for /config to be writable (PVC mount) and the seeded
# autostart file to appear. If it never appears (fresh PVC, no seed) skip.
AUTOSTART_DIR=/config/.config/autostart
for i in 1 2 3 4 5 6 7 8 9 10; do [ -d "$AUTOSTART_DIR" ] && break; sleep 1; done
if [ -d "$AUTOSTART_DIR" ]; then
  cat > "$AUTOSTART_DIR/openclaw-browser.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Version=1.0
Name=OpenClaw Web UI
Comment=Launch chromium kiosk against the local openclaw gateway
Exec=/usr/bin/bash -lc "sleep 8 && rm -rf /tmp/chromium-profile && exec /usr/bin/chromium --no-sandbox --kiosk --start-fullscreen --disable-features=UseOzonePlatform --user-data-dir=/tmp/chromium-profile http://localhost:18789"
Terminal=false
StartupNotify=false
EOF
  chmod 644 "$AUTOSTART_DIR/openclaw-browser.desktop" 2>/dev/null
fi

# --- (3) workspace/skills -> extensions sync watcher ---
# Background daemon: polls every 5s, copies any workspace skill that's newer
# than its extensions/ counterpart, then bounces openclaw-gateway so the
# agent reloads. The seeded chromium autostart's "sleep 8" gives this loop
# at least one cycle before chromium needs to connect to the gateway.
#
# Write the loop body to disk so the daemon can be exec'd cleanly. Spawning
# via 'setsid -f' double-forks the daemon into its own session so kubelet's
# postStart exec termination doesn't take it with it.
mkdir -p /config/.openclaw/extensions 2>/dev/null
cat > /usr/local/bin/openclaw-skill-sync.sh <<'SYNC_EOF'
#!/bin/sh
exec >> /var/log/skill-sync.log 2>&1
echo "[$(date)] skill-sync daemon starting"
while true; do
  changed=0
  for src in /config/.openclaw/workspace/skills/*/; do
    [ -d "$src" ] || continue
    name=$(basename "$src")
    dst=/config/.openclaw/extensions/$name
    if [ ! -d "$dst" ] || [ "$src" -nt "$dst" ]; then
      echo "[$(date)] sync $name: workspace -> extensions"
      rm -rf "$dst" 2>/dev/null
      cp -r "$src" /config/.openclaw/extensions/ 2>/dev/null && changed=1
    fi
  done
  if [ "$changed" = "1" ]; then
    # Kill openclaw-agent (s6-supervise will respawn it). A fresh agent
    # restart re-spawns openclaw → openclaw-gateway → plugin load. Killing
    # only openclaw-gateway leaves the parent openclaw dead without auto-
    # restart, because the agent only starts openclaw at its own boot.
    echo "[$(date)] killing openclaw-agent to trigger full reload"
    pkill -KILL -f openclaw-agent 2>/dev/null
    pkill -KILL -f openclaw-gateway 2>/dev/null
    pkill -KILL -f "^openclaw$" 2>/dev/null
  fi
  sleep 5
done
SYNC_EOF
chmod +x /usr/local/bin/openclaw-skill-sync.sh
setsid -f /usr/local/bin/openclaw-skill-sync.sh </dev/null >/dev/null 2>&1

# --- (4) selkies browser cursor ---
# Pod env SELKIES_USE_BROWSER_CURSORS=true is in container_environment but
# selkies first start does NOT honor it (timing / impl bug). Patching the
# run script with an explicit export + restart fixes it. Idempotent.
#
# WARNING: killing selkies during postStart's window crashes the s6 init and
# the whole pod exits (Completed/exit 0). Defer the kill 90s via a detached
# background, by which time pod is fully Running and s6 happily restarts.
SELKIES_RUN=/etc/s6-overlay/s6-rc.d/svc-selkies/run
if [ -f "$SELKIES_RUN" ] && ! grep -q "^export SELKIES_USE_BROWSER_CURSORS" "$SELKIES_RUN"; then
  sed -i '/^export XCURSOR_THEME/a export SELKIES_USE_BROWSER_CURSORS=true' "$SELKIES_RUN"
fi
setsid -f sh -c 'sleep 90; pkill -9 -f /lsiopy/bin/selkies 2>/dev/null' </dev/null >/dev/null 2>&1

exit 0
`

// PodConfig holds configuration for creating a pod
type PodConfig struct {
	InstanceID         int
	InstanceName       string
	UserID             int
	Type               string
	CPUCores           float64
	MemoryGB           int
	GPUEnabled         bool
	GPUCount           int
	Image              string
	MountPath          string
	ContainerPort      int32
	ExtraEnv           map[string]string
	EnvFromSecretNames []string
}

// CreatePod creates a new pod for an instance
func (s *PodService) CreatePod(ctx context.Context, config PodConfig) (*corev1.Pod, error) {
	if s.client == nil {
		return nil, fmt.Errorf("k8s client not initialized")
	}

	podName := s.client.GetPodName(config.InstanceID, config.InstanceName)
	namespace := s.client.GetNamespace(config.UserID)
	pvcName := s.client.GetPVCName(config.InstanceID)

	// Build resource requirements
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%g", config.CPUCores)),
			corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dGi", config.MemoryGB)),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%g", config.CPUCores)),
			corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dGi", config.MemoryGB)),
		},
	}

	// Add GPU resources if enabled
	if config.GPUEnabled && config.GPUCount > 0 {
		resources.Limits["nvidia.com/gpu"] = resource.MustParse(fmt.Sprintf("%d", config.GPUCount))
		resources.Requests["nvidia.com/gpu"] = resource.MustParse(fmt.Sprintf("%d", config.GPUCount))
	}

	// Default container port
	if config.ContainerPort == 0 {
		config.ContainerPort = 3001
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				"app":           "clawreef",
				"instance-id":   fmt.Sprintf("%d", config.InstanceID),
				"instance-name": config.InstanceName,
				"user-id":       fmt.Sprintf("%d", config.UserID),
				"instance-type": config.Type,
				"managed-by":    "clawreef",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "desktop",
					Image: config.Image,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: config.ContainerPort,
							Name:          "http",
						},
					},
					StartupProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstrFromInt32(config.ContainerPort),
							},
						},
						FailureThreshold: 30,
						PeriodSeconds:    5,
						TimeoutSeconds:   2,
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstrFromInt32(config.ContainerPort),
							},
						},
						InitialDelaySeconds: 3,
						PeriodSeconds:       5,
						TimeoutSeconds:      2,
						FailureThreshold:    6,
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstrFromInt32(config.ContainerPort),
							},
						},
						InitialDelaySeconds: 15,
						PeriodSeconds:       10,
						TimeoutSeconds:      2,
						FailureThreshold:    3,
					},
					Resources: resources,
					// Post-start hook patches three image-level shortcomings
					// (see podPostStartScript for full rationale):
					//   1. Xvfb max-clients pool too small
					//   2. Chromium autostart broken (xdg-open fallback)
					//   3. install_skill drops plugins in workspace/, but
					//      OpenClaw only loads from extensions/
					// All three are idempotent + best-effort (exit 0 on any
					// failure to avoid blocking pod readiness).
					Lifecycle: &corev1.Lifecycle{
						PostStart: &corev1.LifecycleHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"sh", "-c", podPostStartScript},
							},
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "data",
							MountPath: config.MountPath,
						},
					},
					Env: []corev1.EnvVar{
						{
							Name:  "INSTANCE_ID",
							Value: fmt.Sprintf("%d", config.InstanceID),
						},
						{
							Name:  "USER_ID",
							Value: fmt.Sprintf("%d", config.UserID),
						},
						{
							Name:  "SELKIES_USE_BROWSER_CURSORS",
							Value: "true",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: pvcName,
						},
					},
				},
			},
		},
	}

	for key, value := range config.ExtraEnv {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  key,
			Value: value,
		})
	}

	for _, secretName := range config.EnvFromSecretNames {
		if secretName == "" {
			continue
		}
		pod.Spec.Containers[0].EnvFrom = append(pod.Spec.Containers[0].EnvFrom, corev1.EnvFromSource{
			SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
			},
		})
	}

	createdPod, err := s.client.Clientset.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		// Check if pod already exists
		if errors.IsAlreadyExists(err) {
			// Try to get the existing pod with the same name. It may still be terminating.
			existingPod, getErr := s.client.Clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
			if getErr == nil && existingPod != nil {
				if existingPod.DeletionTimestamp == nil {
					deleteErr := s.client.Clientset.CoreV1().Pods(namespace).Delete(ctx, existingPod.Name, metav1.DeleteOptions{})
					if deleteErr != nil && !errors.IsNotFound(deleteErr) {
						return nil, fmt.Errorf("failed to delete existing pod %s: %w", existingPod.Name, deleteErr)
					}
				}

				if waitErr := s.waitForPodDeletion(ctx, namespace, existingPod.Name); waitErr != nil {
					return nil, fmt.Errorf("failed waiting for pod deletion %s: %w", existingPod.Name, waitErr)
				}

				// Retry creation
				createdPod, err = s.client.Clientset.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
				if err != nil {
					return nil, fmt.Errorf("failed to create pod after deletion %s: %w", podName, err)
				}
				return createdPod, nil
			}
		}
		return nil, fmt.Errorf("failed to create pod %s: %w", podName, err)
	}

	return createdPod, nil
}

func intstrFromInt32(port int32) intstr.IntOrString {
	return intstr.FromInt32(port)
}

// GetPod gets a pod by instance ID
func (s *PodService) GetPod(ctx context.Context, userID, instanceID int) (*corev1.Pod, error) {
	if s.client == nil {
		return nil, fmt.Errorf("k8s client not initialized")
	}

	// List pods with instance-id label
	namespace := s.client.GetNamespace(userID)
	selector := fmt.Sprintf("instance-id=%d", instanceID)

	pods, err := s.client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("pod not found for instance %d", instanceID)
	}

	return &pods.Items[0], nil
}

// DeletePod deletes a pod
func (s *PodService) DeletePod(ctx context.Context, userID, instanceID int) error {
	if s.client == nil {
		return fmt.Errorf("k8s client not initialized")
	}

	pod, err := s.GetPod(ctx, userID, instanceID)
	if err != nil {
		// Pod doesn't exist, nothing to delete
		if isNotFoundError(err) {
			return nil
		}
		return err
	}

	err = s.client.Clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete pod %s: %w", pod.Name, err)
	}

	if err := s.waitForPodDeletion(ctx, pod.Namespace, pod.Name); err != nil {
		return fmt.Errorf("failed waiting for pod %s to be deleted: %w", pod.Name, err)
	}

	return nil
}

// GetPodStatus gets the status of a pod
func (s *PodService) GetPodStatus(ctx context.Context, userID, instanceID int) (*corev1.PodStatus, error) {
	pod, err := s.GetPod(ctx, userID, instanceID)
	if err != nil {
		return nil, err
	}
	return &pod.Status, nil
}

// GetPodIP gets the pod IP
func (s *PodService) GetPodIP(ctx context.Context, userID, instanceID int) (string, error) {
	pod, err := s.GetPod(ctx, userID, instanceID)
	if err != nil {
		return "", err
	}
	return pod.Status.PodIP, nil
}

// PodExists checks if a pod exists
func (s *PodService) PodExists(ctx context.Context, userID, instanceID int) (bool, error) {
	_, err := s.GetPod(ctx, userID, instanceID)
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsSubstring(errStr, "not found") ||
		containsSubstring(errStr, "NotFound")
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (s *PodService) waitForPodDeletion(ctx context.Context, namespace, podName string) error {
	waitCtx, cancel := context.WithTimeout(ctx, podDeletionTimeout)
	defer cancel()

	ticker := time.NewTicker(podDeletionPollInterval)
	defer ticker.Stop()

	for {
		_, err := s.client.Clientset.CoreV1().Pods(namespace).Get(waitCtx, podName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to check pod %s: %w", podName, err)
		}

		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("timed out waiting for pod %s deletion", podName)
		case <-ticker.C:
		}
	}
}
