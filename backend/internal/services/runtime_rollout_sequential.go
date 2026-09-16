package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/services/k8s"
)

const rolloutPlanPrefix = "runtime-rollout-plan-v1:"

// The existing rollout record is the durable checkpoint; no extra database
// privileges or schema changes are needed. Sources and UIDs are frozen before
// the first mutation. A crash after set-image is recovered by inspecting it.
type sequentialRolloutPlan struct {
	Targets           []k8s.RuntimeRolloutTarget `json:"targets"`
	Index             int                        `json:"index"`
	Applying          bool                       `json:"applying"`
	Submitted         bool                       `json:"submitted"`
	StepStarted       time.Time                  `json:"step_started"`
	EmptyPoolRequired bool                       `json:"empty_pool_required"`
	Failure           string                     `json:"failure,omitempty"`
}

func (s *RuntimeScheduler) saveRolloutPlan(ctx context.Context, r *models.RuntimeRollout, p *sequentialRolloutPlan, status string) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(b) > 60000 {
		return fmt.Errorf("rollout inventory exceeds safe checkpoint size")
	}
	message := rolloutPlanPrefix + string(b)
	var finished *time.Time
	if status == "finished" || status == "error" {
		now := time.Now().UTC()
		finished = &now
	}
	return s.rolloutRepo.UpdateStatus(ctx, r.ID, status, r.StartedAt, finished, &message)
}

func (s *RuntimeScheduler) startSequentialRollout(ctx context.Context, r *models.RuntimeRollout, inventory k8s.RuntimeRolloutInventory) error {
	active, err := s.rolloutRepo.ListActive(ctx, r.RuntimeType)
	if err != nil {
		return err
	}
	for _, other := range active {
		if other.ID != r.ID && (other.Status == "running" || other.ID < r.ID) {
			return fmt.Errorf("another %s runtime rollout is active; wait for it to finish", r.RuntimeType)
		}
	}
	targets, err := inventory.RolloutTargets(ctx, s.runtimeNamespace, r.RuntimeType)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no eligible live runtime deployment for %s", r.RuntimeType)
	}
	p := &sequentialRolloutPlan{Targets: targets}
	for _, t := range targets {
		if r.RuntimeType == RuntimeTypeOpenClaw && t.Upgrade {
			p.EmptyPoolRequired = true
		}
	}
	if p.EmptyPoolRequired {
		guard, ok := s.podRepo.(interface {
			ValidateEmptyOpenClawPool(context.Context, int64) error
		})
		if !ok {
			return fmt.Errorf("empty OpenClaw pool validation is unavailable")
		}
		if err := guard.ValidateEmptyOpenClawPool(ctx, r.ID); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	r.StartedAt = &now
	return s.saveRolloutPlan(ctx, r, p, "running")
}

// Public progress intentionally omits checkpoint internals; administrators get
// the exact pool and source image without any credentials or workspace data.
func RuntimeRolloutProgress(r models.RuntimeRollout) map[string]any {
	result := map[string]any{"id": r.ID, "runtime_type": r.RuntimeType, "status": r.Status, "target_image": r.TargetImageRef}
	if r.ErrorMessage != nil {
		if strings.HasPrefix(*r.ErrorMessage, rolloutPlanPrefix) {
			var p sequentialRolloutPlan
			if json.Unmarshal([]byte(strings.TrimPrefix(*r.ErrorMessage, rolloutPlanPrefix)), &p) == nil {
				result["completed"] = p.Index
				result["total"] = len(p.Targets)
				result["error"] = p.Failure
				if p.Index >= 0 && p.Index < len(p.Targets) {
					result["current_pool"] = p.Targets[p.Index].Name
				}
				result["sources"] = p.Targets
			}
		} else {
			result["error"] = *r.ErrorMessage
		}
	}
	return result
}

func (s *RuntimeScheduler) advanceSequentialRollout(ctx context.Context, r models.RuntimeRollout) error {
	p := &sequentialRolloutPlan{}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(*r.ErrorMessage, rolloutPlanPrefix)), p); err != nil {
		return fmt.Errorf("invalid rollout checkpoint: %w", err)
	}
	fail := func(err error) error {
		p.Failure = err.Error()
		if saveErr := s.saveRolloutPlan(ctx, &r, p, "error"); saveErr != nil {
			return saveErr
		}
		return err
	}
	if p.Index < 0 || p.Index > len(p.Targets) || len(p.Targets) == 0 {
		return fail(fmt.Errorf("invalid rollout target index"))
	}
	if p.Index == len(p.Targets) {
		return s.saveRolloutPlan(ctx, &r, p, "finished")
	}
	inventory, ok := s.deployments.(k8s.RuntimeRolloutInventory)
	if !ok {
		return fail(fmt.Errorf("live rollout inventory unavailable"))
	}
	live, err := inventory.RolloutTargets(ctx, s.runtimeNamespace, r.RuntimeType)
	if err != nil {
		return fail(err)
	}
	source := p.Targets[p.Index]
	var target *k8s.RuntimeRolloutTarget
	for i := range live {
		if live[i].Namespace == source.Namespace && live[i].Name == source.Name {
			target = &live[i]
			break
		}
	}
	if target == nil || target.UID != source.UID {
		return fail(fmt.Errorf("rollout target %s/%s disappeared or was replaced; stopped after %d completed pools", source.Namespace, source.Name, p.Index))
	}
	if p.EmptyPoolRequired {
		guard, ok := s.podRepo.(interface {
			ValidateEmptyOpenClawPool(context.Context, int64) error
		})
		if !ok {
			return fail(fmt.Errorf("empty pool guard unavailable"))
		}
		if err := guard.ValidateEmptyOpenClawPool(ctx, r.ID); err != nil {
			return fail(err)
		}
	}
	if !p.Applying {
		if target.Image != source.Image && target.Image != r.TargetImageRef {
			return fail(fmt.Errorf("target image changed outside rollout: %s", source.Name))
		}
		p.Applying = true
		p.StepStarted = time.Now().UTC()
		return s.saveRolloutPlan(ctx, &r, p, "running")
	}
	if time.Since(p.StepStarted) > 10*time.Minute {
		return fail(fmt.Errorf("pool %s readiness timed out; %d completed, remaining pools not changed", source.Name, p.Index))
	}
	if !p.Submitted {
		if target.Image != source.Image && target.Image != r.TargetImageRef {
			return fail(fmt.Errorf("unexpected image on %s; stopping", source.Name))
		}
		var updateErr error
		if p.EmptyPoolRequired {
			compatible, ok := s.deployments.(interface {
				RolloutEmptyPoolImage(context.Context, string, string, string) error
			})
			if !ok {
				return fail(fmt.Errorf("empty pool deployment compatibility unavailable"))
			}
			updateErr = compatible.RolloutEmptyPoolImage(ctx, source.Namespace, source.Name, r.TargetImageRef)
		} else {
			updateErr = s.deployments.RolloutImage(ctx, source.Namespace, source.Name, r.TargetImageRef, 0, 1)
		}
		if updateErr != nil {
			return fail(updateErr)
		}
		p.Submitted = true
		return s.saveRolloutPlan(ctx, &r, p, "running")
	}
	if target.Image != r.TargetImageRef {
		return fail(fmt.Errorf("pool image changed after submission: %s", source.Name))
	}
	if !target.Ready {
		return nil
	}
	pods, err := s.podRepo.List(ctx, r.RuntimeType)
	if err != nil {
		return fail(err)
	}
	healthy := false
	for _, pod := range pods {
		if pod.Namespace != source.Namespace || pod.DeploymentName != source.Name || pod.ImageRef != r.TargetImageRef || pod.State != "ready" || pod.Draining || pod.AgentEndpoint == nil || pod.LastSeenAt == nil || time.Since(*pod.LastSeenAt) > s.heartbeatTimeout {
			continue
		}
		if s.agentClient != nil && s.agentClient.Health(ctx, *pod.AgentEndpoint) == nil {
			healthy = true
			break
		}
	}
	if !healthy {
		return nil
	}
	p.Index++
	p.Applying = false
	p.Submitted = false
	status := "running"
	if p.Index == len(p.Targets) {
		status = "finished"
	}
	return s.saveRolloutPlan(ctx, &r, p, status)
}
