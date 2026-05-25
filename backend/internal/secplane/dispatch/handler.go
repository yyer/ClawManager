package dispatch

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"clawreef/internal/utils"

	"github.com/gin-gonic/gin"
)

// Handler exposes the dispatch HTTP endpoints.
type Handler struct {
	svc Service
}

// NewHandler builds a dispatch handler.
func NewHandler(svc Service) *Handler { return &Handler{svc: svc} }

type dispatchAegisRequest struct {
	InstanceIDs []int `json:"instance_ids"`
}

// DispatchAegis — POST /api/v1/secplane/dispatch/aegis
//
// Body: {"instance_ids":[1,2]}; if omitted/empty, dispatches to ALL instances.
// Always returns 200 with a per-target status array; partial failures don't
// fail the whole request because each instance is independently enqueued.
func (h *Handler) DispatchAegis(c *gin.Context) {
	var req dispatchAegisRequest
	// Body is optional; bind only when content present so an empty POST works.
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			utils.ValidationError(c, err)
			return
		}
	}

	var issuedBy *int
	if raw, ok := c.Get("userID"); ok {
		if uid, ok := raw.(int); ok {
			v := uid
			issuedBy = &v
		}
	}

	result, err := h.svc.DispatchAegis(c.Request.Context(), issuedBy, req.InstanceIDs)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane aegis dispatch enqueued", result)
}

// DispatchAegisApply — POST /api/v1/secplane/dispatch/aegis-apply
//
// Config-only fast path. Compiles the secplane rules into a ClawAegis
// UserConfig and ships it inline on each target via secplane.apply_aegis_config.
// No skill zip is built or uploaded; the plugin hot-reloads from the rewritten
// user_config.json (≤1s). Use this for routine policy edits.
// Same request body as DispatchAegis: {"instance_ids":[...]}; empty = all.
func (h *Handler) DispatchAegisApply(c *gin.Context) {
	var req dispatchAegisRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			utils.ValidationError(c, err)
			return
		}
	}

	var issuedBy *int
	if raw, ok := c.Get("userID"); ok {
		if uid, ok := raw.(int); ok {
			v := uid
			issuedBy = &v
		}
	}

	result, err := h.svc.DispatchAegisApply(c.Request.Context(), issuedBy, req.InstanceIDs)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane aegis apply enqueued", result)
}

// DispatchSecureClaw — POST /api/v1/secplane/dispatch/secureclaw
//
// Same shape as DispatchAegis. Body: {"instance_ids":[...]}; empty = all.
// Compiles secureclaw_config rules into a SecureClawConfig user_config.json,
// packages it into a secureclaw skill zip, and enqueues install_skill on
// each target instance.
func (h *Handler) DispatchSecureClaw(c *gin.Context) {
	var req dispatchAegisRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			utils.ValidationError(c, err)
			return
		}
	}

	var issuedBy *int
	if raw, ok := c.Get("userID"); ok {
		if uid, ok := raw.(int); ok {
			v := uid
			issuedBy = &v
		}
	}

	result, err := h.svc.DispatchSecureClaw(c.Request.Context(), issuedBy, req.InstanceIDs)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "secplane secureclaw dispatch enqueued", result)
}

// GetInstanceEffectiveConfig — GET /api/v1/secplane/instances/:id/effective-config
//
// Returns the most recent claw-aegis user_config that was dispatched to the
// given instance (as recorded in instance_commands.payload_json). This is
// "what was last pushed" — for ground-truth "what's actually loaded by the
// plugin right now", a future enhancement will round-trip through the agent.
//
// Response shape:
//
//	{ data: EffectiveAegisConfig | null, ... }
//
// `null` data means no claw-aegis dispatch has happened for this instance yet
// (or the dispatches predate the persistence of aegis_user_config in payload).
func (h *Handler) GetInstanceEffectiveConfig(c *gin.Context) {
	id, err := strconv.Atoi(strings.TrimSpace(c.Param("id")))
	if err != nil || id <= 0 {
		utils.ValidationError(c, fmt.Errorf("invalid instance id"))
		return
	}
	cfg, err := h.svc.GetEffectiveAegisConfig(id)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "effective aegis config", cfg)
}

// GetInstanceLiveConfig — GET /api/v1/secplane/instances/:id/aegis/live-config
//
// Reads the user_config.json out of the latest skill_blob the agent has
// uploaded for this instance's claw-aegis skill. Closer to "what the pod
// actually has on disk" than GetInstanceEffectiveConfig (which only reflects
// what was last dispatched). See service.GetLiveAegisConfig for caveats.
func (h *Handler) GetInstanceLiveConfig(c *gin.Context) {
	id, err := strconv.Atoi(strings.TrimSpace(c.Param("id")))
	if err != nil || id <= 0 {
		utils.ValidationError(c, fmt.Errorf("invalid instance id"))
		return
	}
	userIDRaw, ok := c.Get("userID")
	if !ok {
		utils.Error(c, http.StatusUnauthorized, "missing user context")
		return
	}
	userID, ok := userIDRaw.(int)
	if !ok {
		utils.Error(c, http.StatusUnauthorized, "invalid user context")
		return
	}
	cfg, err := h.svc.GetLiveAegisConfig(userID, id)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "live aegis config", cfg)
}
