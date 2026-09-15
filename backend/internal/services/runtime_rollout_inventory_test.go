package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/services/k8s"
)

// Filtering must not rewrite the database inventory used by later rollout steps.
func TestCurrentRuntimePodsDoesNotMutateInventory(t *testing.T) {
	now := time.Now().UTC()
	stale := now.Add(-time.Hour)
	pods := []models.RuntimePod{{ID: 1, LastSeenAt: &stale}, {ID: 2, LastSeenAt: &now}}
	scheduler := &RuntimeScheduler{heartbeatTimeout: time.Minute}
	current := scheduler.currentRuntimePods(pods, now)
	if len(current) != 1 || current[0].ID != 2 {
		t.Fatalf("unexpected current inventory: %#v", current)
	}
	if pods[0].ID != 1 || pods[1].ID != 2 {
		t.Fatalf("filter mutated original inventory: %#v", pods)
	}
}

type liveRolloutInventoryFake struct {
	fakeRuntimeDeploymentService
	targets []k8s.RuntimeRolloutTarget
	err     error
}

func (f *liveRolloutInventoryFake) RolloutTargets(context.Context, string, string) ([]k8s.RuntimeRolloutTarget, error) {
	return f.targets, f.err
}

func TestRolloutLiveInventoryOverridesHistoricalRows(t *testing.T) {
	f := &liveRolloutInventoryFake{targets: []k8s.RuntimeRolloutTarget{{Namespace: "tenant", Name: "live"}}}
	s := &RuntimeScheduler{deployments: f, runtimeNamespace: "tenant"}
	r := &models.RuntimeRollout{RuntimeType: RuntimeTypeOpenClaw, TargetImageRef: "stable"}
	err := s.rolloutRuntimeDeployments(context.Background(), r, []models.RuntimePod{{RuntimeType: RuntimeTypeOpenClaw, Namespace: "tenant", DeploymentName: "deleted-lab"}}, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.rolloutImageCalls) != 1 || f.rolloutImageCalls[0].name != "live" {
		t.Fatalf("unexpected mutations: %#v", f.rolloutImageCalls)
	}
}

func TestRolloutInventoryFailureDoesNotFallBackOrMutate(t *testing.T) {
	for _, failure := range []error{nil, errors.New("inventory forbidden")} {
		f := &liveRolloutInventoryFake{err: failure}
		s := &RuntimeScheduler{deployments: f, runtimeNamespace: "tenant"}
		err := s.rolloutRuntimeDeployments(context.Background(), &models.RuntimeRollout{RuntimeType: RuntimeTypeOpenClaw, TargetImageRef: "stable"}, nil, 1, 1)
		if err == nil || len(f.rolloutImageCalls) != 0 {
			t.Fatalf("must fail closed: err=%v calls=%#v", err, f.rolloutImageCalls)
		}
	}
}
