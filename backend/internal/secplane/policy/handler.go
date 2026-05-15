package policy

import (
	"net/http"
	"strconv"

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
