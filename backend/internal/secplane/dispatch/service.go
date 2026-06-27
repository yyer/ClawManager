// Package dispatch enqueues compiled secplane configuration onto the existing
// ClawManager control plane (skill upload + InstanceCommand pull queue) so
// on-host openclaw-agent can consume it without any new protocol.
//
// The pipeline:
//   policyService.List(rules)
//     -> compiler/aegis.Compile(rules) -> UserConfig
//     -> compiler/aegis.PackageSkill(UserConfig) -> clawaegisex-vX.zip
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
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/repository"
	"clawreef/internal/secplane/compiler/aegis"
	"clawreef/internal/secplane/compiler/secureclaw"
	"clawreef/internal/secplane/outbound"
	"clawreef/internal/secplane/policy"
	"clawreef/internal/services"
	"clawreef/internal/services/k8s"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// adminUserID is the user the secplane skill is uploaded under. Skills are
// per-user in ClawManager but secplane operates at admin scope; using uid=1
// (the seeded admin) keeps the dependency simple and matches dev defaults.
const adminUserID = 1

// Service exposes high-level dispatch operations for security configurations.
type Service interface {
	SetKillSwitchProvider(p KillSwitchProvider)
	DispatchAegis(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error)
	// DispatchAegisApply ships compiled UserConfig inline via
	// secplane.apply_aegis_config — no skill zip, no blob upload. The plugin's
	// mtime watcher hot-reloads from the rewritten user_config.json within ~1s.
	// Use for routine policy edits; use DispatchAegis only when the plugin
	// source itself needs to be (re)deployed.
	DispatchAegisApply(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error)
	DispatchSecureClaw(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error)
	// GetEffectiveAegisConfig returns the most recent clawaegisex user_config
	// that was successfully dispatched to the given instance, by scanning
	// instance_commands for either the last install_skill of target_name="clawaegisex"
	// or the last secplane.apply_aegis_config — whichever is most recent.
	// Returns (nil, nil) when no dispatch has happened for this instance yet.
	GetEffectiveAegisConfig(instanceID int) (*EffectiveAegisConfig, error)
	// GetLiveAegisConfig returns the user_config.json from the LATEST skill_blob
	// the agent has uploaded for this instance's clawaegisex skill. Closer to
	// "ground truth on pod" than GetEffectiveAegisConfig (which only knows what
	// was last DISPATCHED, not what's actually on disk). Reads from skill_blobs
	// via SkillService.DownloadSkill, unzips, and extracts the user_config.json
	// file (typically at top level clawaegisex/user_config.json).
	//
	// Returns (nil, error) when:
	//   - instance has no clawaegisex skill registered (agent never reported it)
	//   - latest blob is missing or not a valid zip
	//   - user_config.json is not present in the zip
	GetLiveAegisConfig(userID, instanceID int) (*LiveAegisConfig, error)
}

// LiveAegisConfig is the user_config.json read from the most-recent skill_blob
// the agent uploaded for the instance's clawaegisex skill. Use to compare
// against EffectiveAegisConfig (what was dispatched) to detect drift between
// "what we sent" and "what the agent is actually carrying on disk".
type LiveAegisConfig struct {
	InstanceID      int                    `json:"instance_id"`
	SkillID         int                    `json:"skill_id"`
	SkillName       string                 `json:"skill_name"`
	BlobContentHash string                 `json:"blob_content_hash"`
	SourceFile      string                 `json:"source_file"`
	UserConfig      map[string]interface{} `json:"user_config"`
	FetchedAt       time.Time              `json:"fetched_at"`
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

// DispatchResult is what callers receive after a dispatch attempt. UserConfig
// is plugin-shaped (aegis.UserConfig or secureclaw.UserConfig); we keep it
// typed as `any` here so a single DispatchResult type can flow back from
// either dispatcher. JSON marshaling preserves the original plugin shape.
type DispatchResult struct {
	Revision   string           `json:"revision"`
	Sha256     string           `json:"sha256"`
	UserConfig any              `json:"user_config"`
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
	// PostInstallError is kept for API backwards-compat. The new exec-based
	// install path folds post-install failures into Error directly, so this
	// field is no longer populated by DispatchAegis/DispatchAegisApply.
	PostInstallError string `json:"post_install_error,omitempty"`
}

type service struct {
	policyService     policy.Service
	cmdService        services.InstanceCommandService
	instances         repository.InstanceRepository
	skills            services.SkillService
	outboundService   outbound.Service
	killSwitchService KillSwitchProvider
	podService        *k8s.PodService
	cmdRepo           repository.InstanceCommandRepository
}

// KillSwitchProvider — 我们只需要读状态，不引入对 killswitch 包的循环依赖。
type KillSwitchProvider interface {
	IsEnabled() (bool, string)
}

// NewService constructs the dispatch service.
//
// podService is used by installClawaegisexViaExec/writeUserConfigDirect to
// k8s-exec into the desktop container. cmdRepo is used by markCommandTerminal
// to flip secplane.apply_aegis_config command rows to succeeded/failed after
// the exec. Either may be nil in test contexts — DispatchAegis/Apply skip the
// exec and mark the command succeeded.
func NewService(
	policyService policy.Service,
	cmdService services.InstanceCommandService,
	instances repository.InstanceRepository,
	skills services.SkillService,
	outboundSvc outbound.Service,
	podService *k8s.PodService,
	cmdRepo repository.InstanceCommandRepository,
) Service {
	return &service{
		outboundService: outboundSvc,
		policyService:   policyService,
		cmdService:      cmdService,
		instances:       instances,
		skills:          skills,
		podService:      podService,
		cmdRepo:          cmdRepo,
	}
}

// SetKillSwitchProvider — 由 router 在所有服务实例化后注入，避开循环依赖。
func (s *service) SetKillSwitchProvider(p KillSwitchProvider) { s.killSwitchService = p }

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
	s.injectOutboundEntries(&bundle.UserConfig)
	s.injectKillSwitch(&bundle.UserConfig)

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

	// Upload as a new version of the clawaegisex skill (skill_service dedups
	// by content_hash, so when the user_config differs the directory hash
	// differs and we get a fresh version).
	fname := fmt.Sprintf("clawaegisex-secplane-%s.zip", revision)
	payloads, err := s.skills.ImportArchiveBytes(ctx, adminUserID, fname, zipBytes)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("import clawaegisex skill: %w", err)
	}
	if len(payloads) == 0 {
		return DispatchResult{}, fmt.Errorf("import clawaegisex skill: empty result")
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

	for _, instanceID := range targets {
		target := DispatchTarget{
			InstanceID:  instanceID,
			CommandType: services.InstanceCommandTypeSecplaneApplyAegisConfig,
		}
		inst, err := s.instances.GetByID(instanceID)
		if err != nil || inst == nil {
			target.Status = "failed"
			target.Error = fmt.Sprintf("load instance: %v", err)
			out.Targets = append(out.Targets, target)
			continue
		}

		// Record a secplane.apply_aegis_config command row so GetEffectiveAegisConfig
		// can read back the dispatched user_config. The command is created in
		// "pending" status; we flip it to succeeded/failed after the k8s exec.
		req := services.CreateInstanceCommandRequest{
			CommandType: services.InstanceCommandTypeSecplaneApplyAegisConfig,
			Payload: map[string]interface{}{
				"user_config":    bundle.UserConfig,
				"revision":       bundle.Revision,
				"sha256":         bundle.Sha256,
				"install_method": "exec_zip",
			},
			IdempotencyKey: idemKey,
			TimeoutSeconds: 60,
		}
		cmd, cerr := s.cmdService.Create(instanceID, issuedBy, req)
		if cerr != nil {
			target.Status = "failed"
			target.Error = cerr.Error()
			out.Targets = append(out.Targets, target)
			continue
		}
		target.CommandID = cmd.ID

		// Test mode: skip the k8s exec, mark command succeeded.
		if s.podService == nil {
			target.Status = "succeeded"
			_ = s.markCommandTerminal(cmd.ID, "succeeded", "")
			out.Targets = append(out.Targets, target)
			continue
		}

		if err := s.installClawaegisexViaExec(ctx, inst, zipBytes); err != nil {
			target.Status = "failed"
			target.Error = err.Error()
			_ = s.markCommandTerminal(cmd.ID, "failed", err.Error())
		} else {
			target.Status = "succeeded"
			_ = s.markCommandTerminal(cmd.ID, "succeeded", "")
		}
		out.Targets = append(out.Targets, target)
	}

	return out, nil
}

// DispatchAegisApply is the config-only fast path. It writes the compiled
// user_config.json directly to extensions/clawaegisex/ via k8s exec (no skill
// zip rebuild, no install_skill command). clawaegisex has its own mtime-based
// hot-reload (handlers.js getLiveConfig() fs.statSync's user_config.json on
// every hook event), so writing the file is enough — no gateway restart.
//
// If extensions/clawaegisex/ doesn't exist on the pod (first-time install),
// falls back to installClawaegisexViaExec which pipes the full zip via stdin
// and restarts the gateway. Subsequent calls take the config-only path.
//
// Flow per target:
//  1. Compile rules → UserConfig (in-process)
//  2. PackageSkill (only needed for the fallback full-install path; cheap)
//  3. Create secplane.apply_aegis_config command row (for GetEffectiveAegisConfig)
//  4. extensionsMissing? → installClawaegisexViaExec (full zip + pkill)
//    else → writeUserConfigDirect (base64 user_config.json, no pkill)
//  5. Mark command succeeded/failed
func (s *service) DispatchAegisApply(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error) {
	rules, err := s.policyService.List("")
	if err != nil {
		return DispatchResult{}, fmt.Errorf("load secplane rules: %w", err)
	}
	revision := time.Now().UTC().Format("20060102T150405.000000000Z")
	bundle, err := aegis.Compile(rules, revision)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("compile aegis bundle: %w", err)
	}
	s.injectOutboundEntries(&bundle.UserConfig)
	s.injectKillSwitch(&bundle.UserConfig)

	userCfgJSON, err := json.Marshal(bundle.UserConfig)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("marshal user_config: %w", err)
	}
	cfgSum := sha256.Sum256(userCfgJSON)
	cfgSha := hex.EncodeToString(cfgSum[:])

	// PackageSkill is needed for the fallback full-install path (when
	// extensions/clawaegisex/ doesn't exist yet). It's cheap (in-memory zip
	// assembly) so we always compute it rather than branch per-target.
	zipBytes, _, err := aegis.PackageSkill(bundle.UserConfig)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("package skill zip: %w", err)
	}

	targets, err := s.resolveTargets(instanceIDs)
	if err != nil {
		return DispatchResult{}, err
	}

	out := DispatchResult{
		Revision:   bundle.Revision,
		Sha256:     bundle.Sha256,
		UserConfig: bundle.UserConfig,
		Targets:    make([]DispatchTarget, 0, len(targets)),
	}

	for _, instanceID := range targets {
		target := DispatchTarget{
			InstanceID:  instanceID,
			CommandType: services.InstanceCommandTypeSecplaneApplyAegisConfig,
			Status:      "succeeded",
		}
		inst, err := s.instances.GetByID(instanceID)
		if err != nil || inst == nil {
			target.Status = "failed"
			target.Error = fmt.Sprintf("load instance: %v", err)
			out.Targets = append(out.Targets, target)
			continue
		}

		// Record a command row so GetEffectiveAegisConfig can read back the
		// dispatched user_config. Without this, Apply-only dispatches leave
		// no history trace.
		idemKey := fmt.Sprintf("secplane.aegis-apply.%s.r%s", cfgSha[:16], revision)
		req := services.CreateInstanceCommandRequest{
			CommandType: services.InstanceCommandTypeSecplaneApplyAegisConfig,
			Payload: map[string]interface{}{
				"user_config": bundle.UserConfig,
				"revision":    bundle.Revision,
				"sha256":      bundle.Sha256,
			},
			IdempotencyKey: idemKey,
			TimeoutSeconds: 60,
		}
		cmd, _ := s.cmdService.Create(instanceID, issuedBy, req)
		if cmd != nil {
			target.CommandID = cmd.ID
		}

		// Test mode: skip exec, mark command succeeded.
		if s.podService == nil {
			if cmd != nil {
				_ = s.markCommandTerminal(cmd.ID, "succeeded", "")
			}
			out.Targets = append(out.Targets, target)
			continue
		}

		needFullInstall, err := s.extensionsMissing(ctx, inst)
		if err != nil {
			target.Status = "failed"
			target.Error = err.Error()
			if cmd != nil {
				_ = s.markCommandTerminal(cmd.ID, "failed", err.Error())
			}
			out.Targets = append(out.Targets, target)
			continue
		}
		if needFullInstall {
			// First-time install: write the full zip (includes user_config.json).
			// No separate writeUserConfigDirect needed — PackageSkill already
			// injected the correct user_config.json into the zip.
			if err := s.installClawaegisexViaExec(ctx, inst, zipBytes); err != nil {
				target.Status = "failed"
				target.Error = err.Error()
				if cmd != nil {
					_ = s.markCommandTerminal(cmd.ID, "failed", err.Error())
				}
			} else if cmd != nil {
				_ = s.markCommandTerminal(cmd.ID, "succeeded", "")
			}
		} else {
			// Config-only update: just overwrite user_config.json (mtime hot-reload, no pkill).
			if err := s.writeUserConfigDirect(ctx, inst, userCfgJSON); err != nil {
				target.Status = "failed"
				target.Error = err.Error()
				if cmd != nil {
					_ = s.markCommandTerminal(cmd.ID, "failed", err.Error())
				}
			} else if cmd != nil {
				_ = s.markCommandTerminal(cmd.ID, "succeeded", "")
			}
		}
		out.Targets = append(out.Targets, target)
	}

	return out, nil
}

// DispatchSecureClaw compiles the SecureClaw knob rules into a SecureClawConfig
// JSON, packages it into a fresh secureclaw skill zip, uploads as a new
// skill version, and enqueues install_skill on each target. Symmetric to
// DispatchAegis — see that function's comment for the full pipeline.
func (s *service) DispatchSecureClaw(ctx context.Context, issuedBy *int, instanceIDs []int) (DispatchResult, error) {
	rules, err := s.policyService.List("")
	if err != nil {
		return DispatchResult{}, fmt.Errorf("load secplane rules: %w", err)
	}
	revision := time.Now().UTC().Format("20060102T150405.000000000Z")
	bundle, err := secureclaw.Compile(rules, revision)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("compile secureclaw bundle: %w", err)
	}

	zipBytes, _, err := secureclaw.PackageSkill(bundle.UserConfig, bundle.SkillConfigs)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("package secureclaw skill: %w", err)
	}

	userCfgJSON, _ := json.Marshal(bundle.UserConfig)
	cfgSum := sha256.Sum256(userCfgJSON)
	cfgSha := hex.EncodeToString(cfgSum[:])

	fname := fmt.Sprintf("secureclaw-secplane-%s.zip", revision)
	payloads, err := s.skills.ImportArchiveBytes(ctx, adminUserID, fname, zipBytes)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("import secureclaw skill: %w", err)
	}
	if len(payloads) == 0 {
		return DispatchResult{}, fmt.Errorf("import secureclaw skill: empty result")
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

	// Same revision-in-key trick as DispatchAegis. See that function's note
	// for why the timestamp suffix is load-bearing.
	idemKey := fmt.Sprintf("secplane.secureclaw.%s.v%d.%s.r%s",
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
				// Mirror aegis_* payload keys but namespaced by plugin so
				// effective-config reads can disambiguate when both plugins
				// are deployed to the same instance.
				"secureclaw_revision":    bundle.Revision,
				"secureclaw_sha256":      bundle.Sha256,
				"secureclaw_user_config": bundle.UserConfig,
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

// writeUserConfigDirect is the config-only fast path used by DispatchAegisApply.
// It writes user_config.json directly to extensions/clawaegisex/ via k8s exec
// (base64-decoded from stdin). Does NOT restart the gateway — clawaegisex has
// its own mtime-based hot-reload (handlers.js getLiveConfig() fs.statSync's
// user_config.json on every hook event and re-parses when mtime moves), so
// writing the file is enough to apply the new config on the next hook.
// Requires that extensions/clawaegisex/ already exists (i.e. DispatchAegis has
// been run at least once). If the directory doesn't exist, returns an error
// directing the caller to run DispatchAegis first.
func (s *service) writeUserConfigDirect(ctx context.Context, inst *models.Instance, userCfgJSON []byte) error {
	const script = `set -e
OPENCLAW_DIR="${CLAWMANAGER_AGENT_PERSISTENT_DIR:-/config}/.openclaw"
DST="$OPENCLAW_DIR/extensions/clawaegisex"
if [ ! -d "$DST" ]; then
  echo "ERR: $DST does not exist; run DispatchAegis (full install) first" >&2
  exit 1
fi
mkdir -p "$DST"
base64 -d > "$DST/user_config.json"
chmod 0644 "$DST/user_config.json"
echo "OK: user_config.json updated (hot-reload will pick up on next hook)"
`
	stdin := bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(userCfgJSON)))
	stdout, stderr, err := s.execInDesktop(ctx, inst.UserID, inst.ID,
		[]string{"sh", "-lc", script}, stdin)
	if err != nil {
		return fmt.Errorf("exec: %w; stderr: %s; stdout: %s", err, stderr, stdout)
	}
	return nil
}

// installClawaegisexViaExec installs the full clawaegisex plugin zip directly
// to extensions/clawaegisex/ via a single k8s exec call. Replaces the legacy
// install_skill + ensureClawaegisexLoaded pipeline: no agent poll, no
// workspace/skills/ extraction, no 90s wait. The zip bytes (from
// aegis.PackageSkill) are base64-encoded and piped via stdin to python3's
// zipfile module (desktop container has no unzip binary). pkill openclaw
// restarts the gateway so it auto-discovers the new plugin code.
//
// Used by:
//   - DispatchAegis (full install path, every call)
//   - DispatchAegisApply fallback when extensions/clawaegisex/ is missing
//     (first-time install on a fresh pod)
func (s *service) installClawaegisexViaExec(ctx context.Context, inst *models.Instance, zipBytes []byte) error {
	const script = `set -e
OPENCLAW_DIR="${CLAWMANAGER_AGENT_PERSISTENT_DIR:-/config}/.openclaw"
mkdir -p "$OPENCLAW_DIR/extensions"
# zip top-level dir is clawaegisex/ — extract creates/overwrites $OPENCLAW_DIR/extensions/clawaegisex/
# desktop container has no unzip binary, use python3 zipfile (always available on openclaw images).
base64 -d | python3 -c "import zipfile,io,sys; zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())).extractall(sys.argv[1])" "$OPENCLAW_DIR/extensions/"
DST="$OPENCLAW_DIR/extensions/clawaegisex"
date -u +%Y-%m-%dT%H:%M:%SZ > "$DST/.clawmanager-dispatched-at"
# pkill openclaw matches both comm=openclaw (gateway) and comm=openclaw-agent.
# s6-supervise restarts the agent within ~1s, agent re-execs gateway which
# auto-discovers extensions/clawaegisex/ and loads the new code.
pkill openclaw || true
echo "OK: clawaegisex installed via exec, agent restarting"
`
	stdin := bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(zipBytes)))
	stdout, stderr, err := s.execInDesktop(ctx, inst.UserID, inst.ID,
		[]string{"sh", "-lc", script}, stdin)
	if err != nil {
		return fmt.Errorf("exec: %w; stderr: %s; stdout: %s", err, stderr, stdout)
	}
	return nil
}

// extensionsMissing returns true if extensions/clawaegisex/ does not exist
// on the pod (first-time install scenario). Used by DispatchAegisApply to
// decide between the config-only writeUserConfigDirect path and the full
// installClawaegisexViaExec fallback.
func (s *service) extensionsMissing(ctx context.Context, inst *models.Instance) (bool, error) {
	const script = `test -d "${CLAWMANAGER_AGENT_PERSISTENT_DIR:-/config}/.openclaw/extensions/clawaegisex"`
	_, _, err := s.execInDesktop(ctx, inst.UserID, inst.ID,
		[]string{"sh", "-lc", script}, nil)
	if err != nil {
		// non-zero exit = directory missing
		return true, nil
	}
	return false, nil
}

// markCommandTerminal flips an instance_commands row to a terminal status
// (succeeded/failed) and sets FinishedAt + ErrorMessage. Used by
// DispatchAegis/DispatchAegisApply after the k8s exec succeeds or fails —
// secplane.apply_aegis_config commands are created in "pending" status by
// cmdService.Create and need to be marked terminal since there's no agent
// poll loop (unlike install_skill which the agent reports back).
func (s *service) markCommandTerminal(cmdID int, status, errMsg string) error {
	if s.cmdRepo == nil || cmdID == 0 {
		return nil
	}
	cmd, err := s.cmdRepo.GetByID(cmdID)
	if err != nil {
		return fmt.Errorf("load command %d: %w", cmdID, err)
	}
	if cmd == nil {
		return nil
	}
	cmd.Status = status
	now := time.Now().UTC()
	cmd.FinishedAt = &now
	if errMsg != "" {
		cmd.ErrorMessage = &errMsg
	}
	return s.cmdRepo.Update(cmd)
}

// execInDesktop runs a command in the desktop container of the instance's pod
// via k8s exec (SPDY). Modeled on openclaw_transfer_service.exec but targets
// the desktop container (not the runtime container) since clawaegisex lives in
// /config/.openclaw/ which is the desktop container's PVC.
func (s *service) execInDesktop(ctx context.Context, userID, instanceID int, command []string, stdin io.Reader) (string, string, error) {
	if s.podService == nil || s.podService.GetClient() == nil || s.podService.GetClient().Clientset == nil {
		return "", "", fmt.Errorf("k8s client not initialized")
	}
	pod, err := s.podService.GetPod(ctx, userID, instanceID)
	if err != nil {
		return "", "", fmt.Errorf("get pod: %w", err)
	}
	var stdout, stderr bytes.Buffer
	req := s.podService.GetClient().Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod.Name).Namespace(pod.Namespace).SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Container: "desktop",
		Command:   command,
		Stdin:     stdin != nil,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(s.podService.GetClient().Config, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("init exec: %w", err)
	}
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	return stdout.String(), stderr.String(), err
}

// GetEffectiveAegisConfig walks instance_commands backwards for the given
// instance and returns whichever happened most recently:
//   - an install_skill with target_name="clawaegisex" carrying aegis_user_config
//     (bundle path — produced by DispatchAegis), OR
//   - a secplane.apply_aegis_config carrying user_config (config-only fast
//     path — produced by DispatchAegisApply).
//
// ListByInstanceID returns commands newest-first, so the first match wins.
// We persist the snapshot in the payload precisely so this read stays local
// — no need to crack the skill zip or round-trip to the agent.
func (s *service) GetEffectiveAegisConfig(instanceID int) (*EffectiveAegisConfig, error) {
	const scanLimit = 50
	cmds, err := s.cmdService.ListByInstanceID(instanceID, scanLimit)
	if err != nil {
		return nil, fmt.Errorf("list instance commands: %w", err)
	}
	for _, cmd := range cmds {
		if cmd.Payload == nil {
			continue
		}
		var userCfg map[string]interface{}
		var revision, sha string

		switch cmd.CommandType {
		case services.InstanceCommandTypeInstallSkill:
			if name, _ := cmd.Payload["target_name"].(string); name != "clawaegisex" {
				continue
			}
			ucRaw, ok := cmd.Payload["aegis_user_config"]
			if !ok || ucRaw == nil {
				// Older command rows (before we started persisting the bundle).
				continue
			}
			userCfg, ok = ucRaw.(map[string]interface{})
			if !ok {
				continue
			}
			revision, _ = cmd.Payload["aegis_revision"].(string)
			sha, _ = cmd.Payload["aegis_sha256"].(string)
		case services.InstanceCommandTypeSecplaneApplyAegisConfig:
			ucRaw, ok := cmd.Payload["user_config"]
			if !ok || ucRaw == nil {
				continue
			}
			userCfg, ok = ucRaw.(map[string]interface{})
			if !ok {
				continue
			}
			revision, _ = cmd.Payload["revision"].(string)
			sha, _ = cmd.Payload["sha256"].(string)
		default:
			continue
		}

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

// GetLiveAegisConfig — see Service interface doc.
func (s *service) GetLiveAegisConfig(userID, instanceID int) (*LiveAegisConfig, error) {
	// 1. Find this instance's clawaegisex skill row.
	items, err := s.skills.ListInstanceSkills(instanceID)
	if err != nil {
		return nil, fmt.Errorf("list instance skills: %w", err)
	}
	var aegisSkillID int
	var aegisSkillName string
	for _, it := range items {
		if it.Skill == nil {
			continue
		}
		// 名字匹配 "clawaegisex" 或类似 (大小写不敏感, 容忍连字符变体)
		nameLower := strings.ToLower(it.Skill.Name)
		keyLower := strings.ToLower(it.Skill.SkillKey)
		if strings.Contains(nameLower, "clawaegisex") ||
			strings.Contains(nameLower, "clawaegis") ||
			strings.Contains(nameLower, "ksecforclaw") ||
			strings.Contains(keyLower, "clawaegisex") ||
			strings.Contains(keyLower, "clawaegis") ||
			strings.Contains(keyLower, "ksecforclaw") {
			aegisSkillID = it.SkillID
			aegisSkillName = it.Skill.Name
			break
		}
	}
	if aegisSkillID == 0 {
		return nil, fmt.Errorf("clawaegisex skill not registered on instance %d (agent may not have reported yet)", instanceID)
	}

	// 2. Pull the latest version's blob bytes via SkillService.DownloadSkill.
	zipBytes, _, err := s.skills.DownloadSkill(userID, aegisSkillID)
	if err != nil {
		return nil, fmt.Errorf("download skill blob (skill_id=%d): %w", aegisSkillID, err)
	}

	// 3. Open as zip and extract user_config.json (look at common locations).
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("open skill zip: %w", err)
	}
	candidateSuffixes := []string{
		"user_config.json",
		"/user_config.json",
	}
	var (
		raw        []byte
		sourceFile string
	)
	for _, f := range zr.File {
		matched := false
		for _, suf := range candidateSuffixes {
			if strings.HasSuffix(f.Name, suf) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			return nil, fmt.Errorf("open %s in zip: %w", f.Name, openErr)
		}
		raw, err = io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s in zip: %w", f.Name, err)
		}
		sourceFile = f.Name
		break
	}
	if raw == nil {
		return nil, fmt.Errorf("user_config.json not found in skill zip (skill_id=%d)", aegisSkillID)
	}

	var userCfg map[string]interface{}
	if err := json.Unmarshal(raw, &userCfg); err != nil {
		return nil, fmt.Errorf("parse user_config.json: %w", err)
	}

	// content_hash 取 sha256 (跟 skill_blobs.content_hash 字段对齐展示用)
	sum := sha256.Sum256(zipBytes)
	return &LiveAegisConfig{
		InstanceID:      instanceID,
		SkillID:         aegisSkillID,
		SkillName:       aegisSkillName,
		BlobContentHash: hex.EncodeToString(sum[:]),
		SourceFile:      sourceFile,
		UserConfig:      userCfg,
		FetchedAt:       time.Now().UTC(),
	}, nil
}

// injectOutboundEntries 把 secplane_outbound_trusted 表里 active 的条目灌进
// UserConfig.OutboundTrustedEndpoints。失败不阻断整体 dispatch (只是没白名单)。
func (s *service) injectOutboundEntries(cfg *aegis.UserConfig) {
	if s.outboundService == nil {
		return
	}
	entries, err := s.outboundService.ListActive()
	if err != nil {
		return
	}
	out := make([]aegis.OutboundTrustedEntry, 0, len(entries))
	for _, e := range entries {
		entry := aegis.OutboundTrustedEntry{
			Domain: e.DomainPattern,
		}
		if e.FingerprintSHA256 != nil {
			entry.Fingerprint = *e.FingerprintSHA256
		}
		if e.Label != nil {
			entry.Label = *e.Label
		}
		out = append(out, entry)
	}
	cfg.OutboundTrustedEndpoints = out
}

// injectKillSwitch — 把应急熔断状态写到 UserConfig，ClawAegis 据此无条件阻断
// 所有工具调用。provider 未注入或读取失败时按"未启用"处理（fail-open）。
func (s *service) injectKillSwitch(cfg *aegis.UserConfig) {
	if s.killSwitchService == nil {
		return
	}
	enabled, reason := s.killSwitchService.IsEnabled()
	cfg.KillSwitchEnabled = enabled
	cfg.KillSwitchReason = reason
}
