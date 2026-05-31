// Package ingest receives security events from on-host OpenClaw agents and
// stores them as secplane_alert rows. It accepts the JSONL emitted by
// clawaegisex (defense-events.jsonl) and any compatible agent-side emitter.
//
// Authentication uses the same bootstrap→session token flow as the rest of
// the /api/v1/agent/* endpoints; the secplane package provides a thin
// adapter middleware so we don't have to add a method to the existing
// AgentHandler.
package ingest

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/repository"
	"clawreef/internal/secplane/policy"
	"clawreef/internal/services"
	"clawreef/internal/utils"

	"github.com/gin-gonic/gin"
)

// Handler holds dependencies for the ingest endpoint.
type Handler struct {
	agents    services.InstanceAgentService
	instances repository.InstanceRepository
	policySvc policy.Service
}

// NewHandler builds the ingest handler.
func NewHandler(
	agents services.InstanceAgentService,
	instances repository.InstanceRepository,
	policySvc policy.Service,
) *Handler {
	return &Handler{agents: agents, instances: instances, policySvc: policySvc}
}

// AuthMiddleware accepts either:
//   - an InstanceAgent session token (agt_sess_*) — used by Python reference
//     agent and any future custom agent that runs the bootstrap→session flow,
//   - or an Instance access token (igt_*) — what the OpenClaw image's
//     `CLAWMANAGER_INSTANCE_TOKEN` env carries. ClawAegis ships defense
//     events directly using this token (it can't see the agent session
//     token because that's negotiated by the openclaw-agent process).
//
// Either way we record the resolved instance_id on the gin context for the
// downstream handler to attribute alerts.
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c.GetHeader("Authorization"))
		if token == "" {
			utils.Error(c, http.StatusUnauthorized, "ingest token is required")
			c.Abort()
			return
		}
		// Try agent-session first (existing path).
		if session, err := h.agents.AuthenticateSession(token); err == nil && session != nil && session.Instance != nil {
			c.Set("agentSession", session)
			c.Set("ingestInstance", session.Instance)
			if session.Agent != nil {
				c.Set("ingestAgentID", session.Agent.AgentID)
			}
			c.Next()
			return
		}
		// Fallback: instance access token (igt_*).
		if h.instances != nil {
			if inst, err := h.instances.GetByAccessToken(token); err == nil && inst != nil {
				c.Set("ingestInstance", inst)
				c.Set("ingestAgentID", fmt.Sprintf("instance-%d-aegis", inst.ID))
				c.Next()
				return
			}
		}
		utils.Error(c, http.StatusUnauthorized, "invalid ingest token")
		c.Abort()
	}
}

// EventsBatchRequest is the wire shape posted by the on-host agent. Each
// `events` item is a normalized clawaegisex defense event; the agent is
// responsible for parsing JSONL lines and packaging them here.
type EventsBatchRequest struct {
	Source string         `json:"source"` // "aegis" / "secureclaw" / ...
	Events []IngestEvent  `json:"events" binding:"required"`
}

// IngestEvent is a single security event. Fields mirror the JSONL emitted by
// clawaegisex (event_id, hook, defense, result, severity, message, trace_id...).
// We accept the union of common keys; unknown extras are silently dropped.
type IngestEvent struct {
	EventID     string                 `json:"event_id"`
	Ts          string                 `json:"ts"`           // ISO-8601 string from agent
	Hook        string                 `json:"hook"`         // clawaegisex lifecycle hook
	Defense     string                 `json:"defense"`      // module name
	RuleID      string                 `json:"rule_id"`      // optional, for secplane-aware emitters
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`     // low/medium/high
	Result      string                 `json:"result"`       // blocked/observed/redacted/allowed
	Action      string                 `json:"action"`       // alias for result
	Reason      string                 `json:"reason"`
	Message     string                 `json:"message"`
	Evidence    string                 `json:"evidence"`
	TraceID     string                 `json:"trace_id"`
	AgentID     string                 `json:"agent_id"`
	Subject     string                 `json:"subject"`
	RawPayload  string                 `json:"raw_payload"`
	Extras      map[string]interface{} `json:"-"`
}

// IngestBatch — POST /api/v1/secplane/agent/sec_events/batch
func (h *Handler) IngestBatch(c *gin.Context) {
	// AuthMiddleware sets ingestInstance for both auth modes; ingestAgentID
	// is filled from agent-session.Agent.AgentID when present, otherwise
	// synthesized as instance-{id}-aegis when authenticated via igt_*.
	rawInst, instOK := c.Get("ingestInstance")
	if !instOK {
		utils.Error(c, http.StatusUnauthorized, "ingest instance unresolved")
		return
	}
	instance, _ := rawInst.(*models.Instance)
	defaultAgentID, _ := c.Get("ingestAgentID")
	defaultAgentIDStr, _ := defaultAgentID.(string)

	var req EventsBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "aegis"
	}

	accepted := 0
	rejected := 0
	for _, ev := range req.Events {
		alert, err := buildAlert(source, instance, defaultAgentIDStr, ev)
		if err != nil {
			rejected++
			continue
		}
		if err := h.policySvc.RecordExternalAlert(alert); err != nil {
			rejected++
			continue
		}
		accepted++
	}

	utils.Success(c, http.StatusOK, "secplane events ingested", gin.H{
		"accepted": accepted,
		"rejected": rejected,
	})
}

func buildAlert(source string, _ *models.Instance, defaultAgentID string, ev IngestEvent) (*policy.Alert, error) {
	severity := normSeverity(ev.Severity)
	action := strings.TrimSpace(ev.Result)
	if action == "" {
		action = strings.TrimSpace(ev.Action)
	}
	if action == "" {
		action = "observed"
	}

	ts := time.Now()
	if ev.Ts != "" {
		if t, err := time.Parse(time.RFC3339Nano, ev.Ts); err == nil {
			ts = t
		} else if t, err := time.Parse(time.RFC3339, ev.Ts); err == nil {
			ts = t
		}
	}

	subject := pickSubject(ev)
	evidence := pickEvidence(ev)

	a := &policy.Alert{
		Source:   source,
		Severity: severity,
		Action:   action,
		Ts:       ts,
	}
	a.AgentID = strPtrIf(coalesce(ev.AgentID, defaultAgentID))
	a.TraceID = strPtrIf(ev.TraceID)
	a.RuleID = strPtrIf(coalesce(ev.RuleID, ev.Defense))
	a.RuleName = strPtrIf(coalesce(ev.RuleName, ev.Hook))
	a.Subject = strPtrIf(subject)
	a.Evidence = strPtrIf(evidence)
	a.RawPayload = strPtrIf(ev.RawPayload)
	return a, nil
}

func pickSubject(ev IngestEvent) string {
	if ev.Subject != "" {
		return ev.Subject
	}
	if ev.Hook != "" {
		return "clawaegisex." + ev.Hook
	}
	return "clawaegisex"
}

func pickEvidence(ev IngestEvent) string {
	if ev.Evidence != "" {
		return ev.Evidence
	}
	if ev.Message != "" {
		return ev.Message
	}
	return ev.Reason
}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "high", "medium", "low":
		return s
	default:
		return "low"
	}
}

func coalesce(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func strPtrIf(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

func extractBearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
