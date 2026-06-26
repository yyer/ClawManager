package policy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/utils"

	"github.com/gin-gonic/gin"
)

// Handler exposes secplane policy & alert REST endpoints.
type Handler struct {
	svc Service
}

// NewHandler constructs the secplane policy handler.
func NewHandler(svc Service) *Handler { return &Handler{svc: svc} }

// upsertRequest is the wire-shape for create/update. Pattern is optional
// because the toggle-shaped kinds (defense_toggle, user_risk_flag,
// tool_result_flag) have nothing to put there.
type upsertRequest struct {
	RuleID      string  `json:"rule_id" binding:"required"`
	Kind        string  `json:"kind"`
	DisplayName string  `json:"display_name" binding:"required"`
	Description *string `json:"description,omitempty"`
	Pattern     string  `json:"pattern"`
	Target      string  `json:"target"`
	Severity    string  `json:"severity"`
	Action      string  `json:"action"`
	Mode        string  `json:"mode"`
	IsEnabled   bool    `json:"is_enabled"`
	SortOrder   int     `json:"sort_order"`
	Tags        *string `json:"tags,omitempty"`
}

func (r upsertRequest) toInput() SaveRuleInput {
	return SaveRuleInput{
		RuleID:      r.RuleID,
		Kind:        r.Kind,
		DisplayName: r.DisplayName,
		Description: r.Description,
		Pattern:     r.Pattern,
		Target:      r.Target,
		Severity:    r.Severity,
		Action:      r.Action,
		Mode:        r.Mode,
		IsEnabled:   r.IsEnabled,
		SortOrder:   r.SortOrder,
		Tags:        r.Tags,
	}
}

type bulkStatusRequest struct {
	RuleIDs   []string `json:"rule_ids" binding:"required"`
	IsEnabled bool     `json:"is_enabled"`
}

type testRequest struct {
	Text        string         `json:"text" binding:"required"`
	Target      string         `json:"target"`
	RecordAlert bool           `json:"record_alert"`
	Subject     string         `json:"subject"`
	TraceID     string         `json:"trace_id"`
	AgentID     string         `json:"agent_id"`
	Source      string         `json:"source"`
	Rule        *upsertRequest `json:"rule,omitempty"`
}

// ListRules — GET /api/v1/secplane/policy/rules?kind=prompt_filter
func (h *Handler) ListRules(c *gin.Context) {
	items, err := h.svc.List(c.Query("kind"))
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane rules retrieved", gin.H{"items": items})
}

// UpsertRule — PUT /api/v1/secplane/policy/rules
func (h *Handler) UpsertRule(c *gin.Context) {
	var req upsertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	rule, err := h.svc.Save(req.toInput())
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane rule saved", rule)
}

// DeleteRule — DELETE /api/v1/secplane/policy/rules/:rule_id (disable)
func (h *Handler) DeleteRule(c *gin.Context) {
	if err := h.svc.Disable(c.Param("rule_id")); err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane rule disabled", nil)
}

// BulkStatus — POST /api/v1/secplane/policy/rules/bulk-status
func (h *Handler) BulkStatus(c *gin.Context) {
	var req bulkStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	if err := h.svc.BulkSetEnabled(req.RuleIDs, req.IsEnabled); err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane rule status updated", nil)
}

// Test — POST /api/v1/secplane/policy/rules/test
func (h *Handler) Test(c *gin.Context) {
	var req testRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	in := TestInput{
		Text:        req.Text,
		Target:      req.Target,
		RecordAlert: req.RecordAlert,
		Subject:     req.Subject,
		TraceID:     req.TraceID,
		AgentID:     req.AgentID,
		Source:      req.Source,
	}
	if req.Rule != nil {
		draft := req.Rule.toInput()
		in.Draft = &draft
	}
	result, err := h.svc.Test(in)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane rule test completed", result)
}

// ListAlerts — GET /api/v1/secplane/alerts
func (h *Handler) ListAlerts(c *gin.Context) {
	limit := 0
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	items, err := h.svc.ListAlerts(AlertFilter{
		Source:   c.Query("source"),
		Severity: c.Query("severity"),
		RuleID:   c.Query("rule_id"),
		Limit:    limit,
	})
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane alerts retrieved", gin.H{"items": items})
}

// collabPolicyResponse is the wire shape for GET/PUT /api/v1/secplane/collab/policy.
// Mirrors the frontend CollaborationPolicy interface. The full object is
// round-tripped through the rule's Pattern field as JSON.
type collabPolicyResponse struct {
	TeamId            string `json:"teamId"`
	CommunicationMode string `json:"communicationMode"`
	RedisAclMode      string `json:"redisAclMode"`
	RelayRequired     bool   `json:"relayRequired"`
	IdentityMode      string `json:"identityMode"`
	SchemaMode        string `json:"schemaMode"`
	QuotaMode         string `json:"quotaMode"`
	ApprovalMode      string `json:"approvalMode"`
	MuteOnAnomaly     bool   `json:"muteOnAnomaly"`
	AuditReplay       bool   `json:"auditReplay"`
	XaddRps           int    `json:"xaddRps"`
	XaddWindowSeconds int    `json:"xaddWindowSeconds"`
	StreamMaxLen      int    `json:"streamMaxLen"`
	ApprovalThreshold int    `json:"approvalThreshold"`
	RedisAclPreview   string `json:"redisAclPreview"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
}

// defaultCollabPolicy returns the safe initial policy used when no row exists
// yet. Matches the frontend DEFAULT_POLICY so the UI shows the same draft on
// first load.
func defaultCollabPolicy() collabPolicyResponse {
	return collabPolicyResponse{
		TeamId:            "12",
		CommunicationMode: "leader_mediated",
		RedisAclMode:      "per_member",
		RelayRequired:     true,
		IdentityMode:      "enforce",
		SchemaMode:        "observe",
		QuotaMode:         "enforce",
		ApprovalMode:      "observe",
		MuteOnAnomaly:     true,
		AuditReplay:       true,
		XaddRps:           20,
		XaddWindowSeconds: 1,
		StreamMaxLen:      5000,
		ApprovalThreshold: 85,
		RedisAclPreview:   "",
	}
}

// GetCollabPolicy — GET /api/v1/secplane/collab/policy
//
// Returns the singleton collaboration governance policy. If no row exists
// yet (fresh install), returns the default policy with 200 so the frontend
// can render the draft without a 404.
func (h *Handler) GetCollabPolicy(c *gin.Context) {
	rule, err := h.svc.GetByRuleID(CollabPolicyRuleID)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	if rule == nil {
		utils.Success(c, http.StatusOK, "collab policy default", defaultCollabPolicy())
		return
	}
	resp := defaultCollabPolicy()
	if strings.TrimSpace(rule.Pattern) != "" {
		_ = json.Unmarshal([]byte(rule.Pattern), &resp)
	}
	resp.UpdatedAt = rule.UpdatedAt.Format(time.RFC3339)
	utils.Success(c, http.StatusOK, "collab policy retrieved", resp)
}

// UpsertCollabPolicy — PUT /api/v1/secplane/collab/policy
//
// Body: collabPolicyResponse JSON. Stored as a single KindCollabPolicy row
// with RuleID="collab.policy". The whole policy is serialized into Pattern
// as JSON; compile.applyCollabPolicy parses it back during dispatch.
func (h *Handler) UpsertCollabPolicy(c *gin.Context) {
	var req collabPolicyResponse
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	payloadBytes, err := json.Marshal(req)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	mode := strings.TrimSpace(req.IdentityMode)
	if mode == "" {
		mode = "observe"
	}
	rule, err := h.svc.Save(SaveRuleInput{
		RuleID:      CollabPolicyRuleID,
		Kind:        KindCollabPolicy,
		DisplayName: "协同治理策略",
		Description: strPtr("Collaboration governance policy for ClawAegis collab_guard defense"),
		Pattern:     string(payloadBytes),
		Target:      TargetUserInput,
		Severity:    SeverityMedium,
		Action:      ActionObserve,
		Mode:        mode,
		IsEnabled:   true,
		SortOrder:   900,
	})
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	resp := defaultCollabPolicy()
	_ = json.Unmarshal(payloadBytes, &resp)
	resp.UpdatedAt = rule.UpdatedAt.Format(time.RFC3339)
	utils.Success(c, http.StatusOK, "collab policy saved", resp)
}
