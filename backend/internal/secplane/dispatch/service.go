// Package dispatch enqueues compiled secplane configuration onto the existing
// ClawManager control plane (skill upload + InstanceCommand pull queue) so
// on-host openclaw-agent can consume it without any new protocol.
//
// The pipeline:
//   policyService.List(rules)
//     -> compiler/aegis.Compile(rules) -> UserConfig
//     -> compiler/aegis.PackageSkill(UserConfig) -> claw-aegis-vX.zip
//        (embedded ClawAegis source + injected user_config.json)
//     -> skillService.ImportArchiveBytes -> SkillPayload (versioned)
//     -> for each target instance: cmdService.Create(install_skill, ...)
//        with a sha-derived idempotency key so each policy revision is a
//        distinct command (avoids dedup against earlier installs).
//
// The patched ClawAegis (see ClawAegis/src/config.ts:resolveClawAegisPluginConfig)
// reads `user_config.json` from its plugin rootDir on startup and merges it on
// top of api.pluginConfig. So a fresh install effectively ships new policy.
package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"clawreef/internal/repository"
	"clawreef/internal/secplane/compiler/aegis"
	"clawreef/internal/secplane/policy"
	"clawreef/internal/services"
)

// adminUserID is the user the secplane skill is uploaded under. Skills are
// per-user in ClawManager but secplane operates at admin scope; using uid=1
// (the seeded admin) keeps the dependency simple and matches dev defaults.
const adminUserID = 1

// Service exposes high-level dispatch operations for security configurations.
type Service interface {
	DispatchAegis(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error)
	// GetEffectiveAegisConfig returns the most recent claw-aegis user_config
	// that was successfully dispatched to the given instance, by scanning
	// instance_commands for the last install_skill of target_name="claw-aegis".
	// Returns (nil, nil) when no dispatch has happened for this instance yet.
	GetEffectiveAegisConfig(instanceID int) (*EffectiveAegisConfig, error)
}

// EffectiveAegisConfig is what we last pushed to an instance — useful for the
// admin UI to answer "what's actually live on pod N right now?".
type EffectiveAegisConfig struct {
	InstanceID   int                    `json:"instance_id"`
	CommandID    int                    `json:"command_id"`
	Revision     string                 `json:"revision,omitempty"`
	Sha256       string                 `json:"sha256,omitempty"`
	UserConfig   map[string]interface{} `json:"user_config"`
	Status       string                 `json:"status"`
	IssuedAt     time.Time              `json:"issued_at"`
	DispatchedAt *time.Time             `json:"dispatched_at,omitempty"`
	FinishedAt   *time.Time             `json:"finished_at,omitempty"`
}

// DispatchResult is what callers receive after a dispatch attempt.
type DispatchResult struct {
	Revision   string           `json:"revision"`
	Sha256     string           `json:"sha256"`
	UserConfig aegis.UserConfig `json:"user_config"`
	SkillID    int              `json:"skill_id"`
	SkillKey   string           `json:"skill_key"`
	VersionNo  int              `json:"version_no"`
	Targets    []DispatchTarget `json:"targets"`
}

// DispatchTarget records what happened for a single instance target.
type DispatchTarget struct {
	InstanceID  int    `json:"instance_id"`
	CommandID   int    `json:"command_id,omitempty"`
	CommandType string `json:"command_type"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

type service struct {
	policyService policy.Service
	cmdService    services.InstanceCommandService
	instances     repository.InstanceRepository
	skills        services.SkillService
}

// NewService constructs the dispatch service.
func NewService(
	policyService policy.Service,
	cmdService services.InstanceCommandService,
	instances repository.InstanceRepository,
	skills services.SkillService,
) Service {
	return &service{
		policyService: policyService,
		cmdService:    cmdService,
		instances:     instances,
		skills:        skills,
	}
}

func (s *service) DispatchAegis(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error) {
	rules, err := s.policyService.List("")
	if err != nil {
		return DispatchResult{}, fmt.Errorf("load secplane rules: %w", err)
	}
	revision := time.Now().UTC().Format("20060102T150405.000000000Z")
	bundle, err := aegis.Compile(rules, revision)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("compile aegis bundle: %w", err)
	}

	zipBytes, _, err := aegis.PackageSkill(bundle.UserConfig)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("package skill zip: %w", err)
	}

	// The skill content_hash is computed by skill_service over the directory
	// contents, but we still need a stable per-revision identifier for the
	// install_skill idempotency key. Hash the user_config alone (sha already
	// in bundle).
	userCfgJSON, _ := json.Marshal(bundle.UserConfig)
	cfgSum := sha256.Sum256(userCfgJSON)
	cfgSha := hex.EncodeToString(cfgSum[:])

	// Upload as a new version of the claw-aegis skill (skill_service dedups
	// by content_hash, so when the user_config differs the directory hash
	// differs and we get a fresh version).
	fname := fmt.Sprintf("claw-aegis-secplane-%s.zip", revision)
	payloads, err := s.skills.ImportArchiveBytes(ctx, adminUserID, fname, zipBytes)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("import claw-aegis skill: %w", err)
	}
	if len(payloads) == 0 {
		return DispatchResult{}, fmt.Errorf("import claw-aegis skill: empty result")
	}
	skill := payloads[0]

	targets, err := s.resolveTargets(instanceIDs)
	if err != nil {
		return DispatchResult{}, err
	}

	versionNo := 0
	if skill.CurrentVersionNo != nil {
		versionNo = *skill.CurrentVersionNo
	}
	out := DispatchResult{
		Revision:   bundle.Revision,
		Sha256:     bundle.Sha256,
		UserConfig: bundle.UserConfig,
		SkillID:    skill.ID,
		SkillKey:   skill.SkillKey,
		VersionNo:  versionNo,
		Targets:    make([]DispatchTarget, 0, len(targets)),
	}

	// Idempotency key combines skill version + user_config sha. Same dispatch
	// twice (same source + same config) safely dedups; new ClawAegis source
	// (-> new version_no) OR new policy (-> new sha) produces a distinct key
	// so the agent actually re-installs.
	//
	// IMPORTANT: revision is part of the key. Without it, two dispatches whose
	// bundle bytes happen to be byte-identical to a historical command would
	// collapse via idempotency dedup and never reach the pod — operators see
	// "dispatch succeeded" but the on-pod user_config.json stays stale because
	// no new install_skill row hits the agent's poll queue. Revision is a
	// fresh per-dispatch timestamp (RFC3339-like), so the key is always
	// unique across distinct dispatch attempts, while still merging "double
	// click within the same dispatch service call" because the same revision
	// reaches Create() twice in that pathological case.
	idemKey := fmt.Sprintf("secplane.aegis.%s.v%d.%s.r%s",
		strings.TrimPrefix(skill.SkillKey, ""), versionNo, cfgSha[:16], revision)

	contentMD5 := ""
	if skill.ContentMD5 != nil {
		contentMD5 = *skill.ContentMD5
	}
	versionExtID := ""
	if skill.CurrentVersionID != nil {
		versionExtID = fmt.Sprintf("ver_%d", *skill.CurrentVersionID)
	}

	for _, instanceID := range targets {
		target := DispatchTarget{
			InstanceID:  instanceID,
			CommandType: services.InstanceCommandTypeInstallSkill,
		}
		req := services.CreateInstanceCommandRequest{
			CommandType: services.InstanceCommandTypeInstallSkill,
			Payload: map[string]interface{}{
				"skill_id":      skill.ExternalSkillID,
				"skill_version": versionExtID,
				"target_name":   skill.SkillKey,
				"content_md5":   contentMD5,
				// Carry the compiled bundle alongside so a later
				// `effective-config` query can show what was actually pushed,
				// without having to crack open the skill zip again.
				"aegis_revision":     bundle.Revision,
				"aegis_sha256":       bundle.Sha256,
				"aegis_user_config":  bundle.UserConfig,
			},
			IdempotencyKey: idemKey,
			TimeoutSeconds: 300,
		}
		cmd, cerr := s.cmdService.Create(instanceID, issuedBy, req)
		if cerr != nil {
			target.Status = "failed"
			target.Error = cerr.Error()
		} else {
			target.CommandID = cmd.ID
			target.Status = cmd.Status
		}
		out.Targets = append(out.Targets, target)
	}

	return out, nil
}

func (s *service) resolveTargets(in []int) ([]int, error) {
	if len(in) == 0 {
		all, err := s.instances.GetAll(0, 1000)
		if err != nil {
			return nil, fmt.Errorf("list instances: %w", err)
		}
		ids := make([]int, 0, len(all))
		for _, inst := range all {
			ids = append(ids, inst.ID)
		}
		return ids, nil
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, id := range in {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		inst, err := s.instances.GetByID(id)
		if err != nil {
			return nil, err
		}
		if inst == nil {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 && len(in) > 0 {
		return nil, fmt.Errorf("no valid target instances")
	}
	return out, nil
}

// GetEffectiveAegisConfig walks instance_commands backwards for the given
// instance, looking for the most recent install_skill whose payload claims
// target_name="claw-aegis" and which actually carries the aegis_user_config
// snapshot. We persist that snapshot in the payload (see DispatchAegis above)
// precisely so this read can stay local — no need to crack the skill zip or
// round-trip to the agent.
func (s *service) GetEffectiveAegisConfig(instanceID int) (*EffectiveAegisConfig, error) {
	const scanLimit = 50
	cmds, err := s.cmdService.ListByInstanceID(instanceID, scanLimit)
	if err != nil {
		return nil, fmt.Errorf("list instance commands: %w", err)
	}
	for _, cmd := range cmds {
		if cmd.CommandType != services.InstanceCommandTypeInstallSkill {
			continue
		}
		if cmd.Payload == nil {
			continue
		}
		if name, _ := cmd.Payload["target_name"].(string); name != "claw-aegis" {
			continue
		}
		ucRaw, ok := cmd.Payload["aegis_user_config"]
		if !ok || ucRaw == nil {
			// Older command rows (before we started persisting the bundle).
			continue
		}
		userCfg, ok := ucRaw.(map[string]interface{})
		if !ok {
			continue
		}
		revision, _ := cmd.Payload["aegis_revision"].(string)
		sha, _ := cmd.Payload["aegis_sha256"].(string)
		return &EffectiveAegisConfig{
			InstanceID:   instanceID,
			CommandID:    cmd.ID,
			Revision:     revision,
			Sha256:       sha,
			UserConfig:   userCfg,
			Status:       cmd.Status,
			IssuedAt:     cmd.IssuedAt,
			DispatchedAt: cmd.DispatchedAt,
			FinishedAt:   cmd.FinishedAt,
		}, nil
	}
	return nil, nil
}
