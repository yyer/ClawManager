package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/services/k8s"
)

func checkpointRollout(repo *fakeRuntimeRolloutRepo, r *models.RuntimeRollout) {
	last := repo.statuses[len(repo.statuses)-1]
	r.Status = last.status
	r.StartedAt = last.startedAt
	r.ErrorMessage = last.message
}

func TestSequentialRolloutWaitsForHealthAndSurvivesWorkerRecreation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	endpoint := "http://runtime"
	r := &models.RuntimeRollout{ID: 1, RuntimeType: RuntimeTypeHermes, TargetImageRef: "new", Status: "pending"}
	repo := &fakeRuntimeRolloutRepo{rollouts: map[int64]*models.RuntimeRollout{1: r}}
	f := &liveRolloutInventoryFake{targets: []k8s.RuntimeRolloutTarget{{Namespace: "tenant", Name: "a", UID: "a1", Image: "old"}, {Namespace: "tenant", Name: "b", UID: "b1", Image: "old"}}}
	pods := &fakeRuntimePodRepo{pods: map[int64]*models.RuntimePod{1: {ID: 1, Namespace: "tenant", DeploymentName: "a", RuntimeType: RuntimeTypeHermes, ImageRef: "new", State: "ready", LastSeenAt: &now, AgentEndpoint: &endpoint}}}
	s := &RuntimeScheduler{deployments: f, runtimeNamespace: "tenant", rolloutRepo: repo, podRepo: pods, agentClient: &fakeRuntimeAgentClient{}, heartbeatTimeout: time.Minute}
	if err := s.StartRollout(ctx, 1); err != nil {
		t.Fatal(err)
	}
	checkpointRollout(repo, r)
	if len(f.rolloutImageCalls) != 0 {
		t.Fatal("preflight mutated a pool")
	}
	for i := 0; i < 2; i++ {
		if err := s.finishRolloutIfReady(ctx, *r); err != nil {
			t.Fatal(err)
		}
		checkpointRollout(repo, r)
	}
	if len(f.rolloutImageCalls) != 1 || f.rolloutImageCalls[0].name != "a" {
		t.Fatalf("calls=%#v", f.rolloutImageCalls)
	}
	f.targets[0].Image = "new"
	for i := 0; i < 3; i++ {
		if err := s.finishRolloutIfReady(ctx, *r); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.rolloutImageCalls) != 1 {
		t.Fatal("touched next pool before readiness")
	}
	// Nothing except persisted DB state is required by a replacement worker.
	s = &RuntimeScheduler{deployments: f, runtimeNamespace: "tenant", rolloutRepo: repo, podRepo: pods, agentClient: &fakeRuntimeAgentClient{}, heartbeatTimeout: time.Minute}
	f.targets[0].Ready = true
	for i := 0; i < 3; i++ {
		if err := s.finishRolloutIfReady(ctx, *r); err != nil {
			t.Fatal(err)
		}
		checkpointRollout(repo, r)
	}
	if len(f.rolloutImageCalls) != 2 || f.rolloutImageCalls[1].name != "b" {
		t.Fatalf("calls=%#v", f.rolloutImageCalls)
	}
}

func TestSequentialRolloutStopsIfDeploymentIdentityChanges(t *testing.T) {
	r := &models.RuntimeRollout{ID: 1, RuntimeType: RuntimeTypeHermes, TargetImageRef: "new", Status: "pending"}
	repo := &fakeRuntimeRolloutRepo{rollouts: map[int64]*models.RuntimeRollout{1: r}}
	f := &liveRolloutInventoryFake{targets: []k8s.RuntimeRolloutTarget{{Namespace: "tenant", Name: "a", UID: "a1", Image: "old"}}}
	s := &RuntimeScheduler{deployments: f, runtimeNamespace: "tenant", rolloutRepo: repo, podRepo: &fakeRuntimePodRepo{}}
	if err := s.StartRollout(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	checkpointRollout(repo, r)
	f.targets[0].UID = "a2"
	if err := s.finishRolloutIfReady(context.Background(), *r); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("expected identity failure: %v", err)
	}
	checkpointRollout(repo, r)
	if r.Status != "error" || len(f.rolloutImageCalls) != 0 {
		t.Fatal("unsafe replacement update")
	}
}
