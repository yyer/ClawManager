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
