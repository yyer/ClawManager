// Package handlers — internal_secplane_handler.go
//
// This file exposes a small, internal-only HTTP surface used by the
// standalone secplane-server pod. The endpoints live under
// /api/v1/internal/secplane/* and require:
//
//   1. Header `X-Internal-Service: secplane-server`
//   2. Header `Authorization: Bearer $CLAWREEF_INTERNAL_TOKEN`
//
// They are NOT user-facing — they exist solely so that secplane-server
// can fetch data (instances, agent sessions, skills, users) from
// clawmanager without going through the public REST API. None of them
// perform user impersonation; they all run as a service identity.
//
// The endpoints delegate to the same in-process services that the
// public REST API uses (instanceRepo, instanceCommandService,
// instanceAgentService, skillService, userRepo), so behaviour matches
// the existing code paths exactly.
package handlers

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/repository"
	"clawreef/internal/services"

	"github.com/gin-gonic/gin"
)

// expectedInternalService identifies the calling service. Any other value
// (or absent header) results in 401. This is matched against the value
// secplane-server's HTTP client sets in clawmanager.go.
const expectedInternalService = "secplane-server"

// InternalSecplaneHandler bundles the dependencies needed to serve
// /api/v1/internal/secplane/*. Pass it the same service instances that
// cmd/server/main.go wires for the public REST API.
type InternalSecplaneHandler struct {
	InstanceRepo         repository.InstanceRepository
	InstanceCommandRepo  repository.InstanceCommandRepository
	InstanceCommandSvc   services.InstanceCommandService
	InstanceAgentSvc     services.InstanceAgentService
	SkillSvc             services.SkillService
	UserRepo             repository.UserRepository
	InternalServiceToken string // matches $CLAWREEF_INTERNAL_TOKEN
}

// NewInternalSecplaneHandler constructs the handler.
func NewInternalSecplaneHandler(
	instanceRepo repository.InstanceRepository,
	instanceCommandRepo repository.InstanceCommandRepository,
	instanceCommandSvc services.InstanceCommandService,
	instanceAgentSvc services.InstanceAgentService,
	skillSvc services.SkillService,
	userRepo repository.UserRepository,
	internalToken string,
) *InternalSecplaneHandler {
	return &InternalSecplaneHandler{
		InstanceRepo:         instanceRepo,
		InstanceCommandRepo:  instanceCommandRepo,
		InstanceCommandSvc:   instanceCommandSvc,
		InstanceAgentSvc:     instanceAgentSvc,
		SkillSvc:             skillSvc,
		UserRepo:             userRepo,
		InternalServiceToken: internalToken,
	}
}

// RegisterInternalRoutes wires the internal routes onto a router group
// (typically api.Group("/internal/secplane")). All routes are protected
// by RequireInternalService().
func (h *InternalSecplaneHandler) RegisterInternalRoutes(g *gin.RouterGroup) {
	g.Use(h.RequireInternalService())

	g.GET("/instances", h.listInstances)
	g.GET("/instances/:id", h.getInstanceByID)
	g.GET("/instances/access/:token", h.getInstanceByAccessToken)
	g.POST("/instance-commands", h.createInstanceCommand)
	g.GET("/instance-commands", h.listInstanceCommands)
	g.PATCH("/instance-commands/:id", h.updateInstanceCommand)
	g.POST("/agents/authenticate", h.authenticateAgentSession)
	g.POST("/skills/import-bytes", h.importSkillArchiveBytes)
	g.GET("/users/:id", h.getUserByID)
}

// RequireInternalService is the auth middleware. It validates the
// X-Internal-Service header and the bearer token against
// $CLAWREEF_INTERNAL_TOKEN. Both must match.
func (h *InternalSecplaneHandler) RequireInternalService() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Internal-Service") != expectedInternalService {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "internal endpoint, X-Internal-Service header required",
			})
			return
		}
		auth := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing bearer token",
			})
			return
		}
		token := strings.TrimPrefix(auth, prefix)
		if h.InternalServiceToken == "" || token != h.InternalServiceToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid internal token",
			})
			return
		}
		c.Next()
	}
}

// ---- GET /instances -----------------------------------------------------

func (h *InternalSecplaneHandler) listInstances(c *gin.Context) {
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	list, err := h.InstanceRepo.GetAll(offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

// ---- GET /instances/:id -------------------------------------------------

func (h *InternalSecplaneHandler) getInstanceByID(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id must be an integer"})
		return
	}
	inst, err := h.InstanceRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, inst)
}

// ---- GET /instances/access/:token ---------------------------------------

func (h *InternalSecplaneHandler) getInstanceByAccessToken(c *gin.Context) {
	token := c.Param("token")
	inst, err := h.InstanceRepo.GetByAccessToken(token)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	// repository.GetByAccessToken returns (nil, nil) for an unknown
	// token (it consults two tables and the "not found" path explicitly
	// yields no error). Without this guard we'd serialise `null` with
	// a 200 status, which the secplane-server auth middleware would
	// treat as a successful lookup → an unauthenticated request could
	// silently post defense events with no associated instance.
	if inst == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found for token"})
		return
	}
	c.JSON(http.StatusOK, inst)
}

// ---- POST /instance-commands --------------------------------------------

type internalCreateCommandRequest struct {
	InstanceID int                                  `json:"instance_id"`
	IssuedBy   *int                                 `json:"issued_by,omitempty"`
	Req        services.CreateInstanceCommandRequest `json:"req"`
}

func (h *InternalSecplaneHandler) createInstanceCommand(c *gin.Context) {
	var body internalCreateCommandRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// The wire shape is { "instance_id": N, "req": {...} }. InstanceID
	// lives on the top-level request, not inside the embedded
	// services.CreateInstanceCommandRequest (which only carries
	// command_type / payload / idempotency_key / timeout_seconds).
	if body.InstanceID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "instance_id required"})
		return
	}
	out, err := h.InstanceCommandSvc.Create(body.InstanceID, body.IssuedBy, body.Req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

// ---- GET /instance-commands ---------------------------------------------

func (h *InternalSecplaneHandler) listInstanceCommands(c *gin.Context) {
	instanceID, err := strconv.Atoi(c.Query("instance_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "instance_id required"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	out, err := h.InstanceCommandSvc.ListByInstanceID(instanceID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

// ---- PATCH /instance-commands/:id ---------------------------------------

// updateInstanceCommandRequest is the wire shape secplane-server uses to
// flip a command to a terminal status. status must be one of
// "succeeded" / "failed" / "running" / "cancelled"; error_message is
// optional and only meaningful when status is "failed".
type updateInstanceCommandRequest struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// updateInstanceCommand is the server-side (non-agent) terminal transition
// for commands the agent never picks up. In practice the only caller is
// secplane-server's dispatch service after the k8s exec returns —
// secplane.apply_aegis_config has no agent poll loop, so the command row
// would otherwise stay in "pending" forever (which is what happened
// pre-fix: 2026-09-06, see project_secplane_jwt_secret_2026_09_06 memory).
//
// Auth is via the X-Internal-Service middleware (no AgentSession check),
// which is the right posture: secplane-server is a trusted service.
func (h *InternalSecplaneHandler) updateInstanceCommand(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id must be an integer"})
		return
	}
	var body updateInstanceCommandRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	switch body.Status {
	case "pending", "running", "succeeded", "failed", "cancelled":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be one of pending|running|succeeded|failed|cancelled"})
		return
	}
	if h.InstanceCommandRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "instance command repo not wired"})
		return
	}
	cmd, err := h.InstanceCommandRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if cmd == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}
	cmd.Status = body.Status
	if body.Status == "succeeded" || body.Status == "failed" || body.Status == "cancelled" {
		now := time.Now().UTC()
		cmd.FinishedAt = &now
	}
	if body.ErrorMessage != "" {
		msg := body.ErrorMessage
		cmd.ErrorMessage = &msg
	} else if body.Status == "succeeded" {
		// Clear stale error message on a successful re-flip.
		cmd.ErrorMessage = nil
	}
	if err := h.InstanceCommandRepo.Update(cmd); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cmd)
}

// ---- POST /agents/authenticate -----------------------------------------

type internalAuthAgentRequest struct {
	Token string `json:"token"`
}

func (h *InternalSecplaneHandler) authenticateAgentSession(c *gin.Context) {
	var body internalAuthAgentRequest
	if err := c.ShouldBindJSON(&body); err != nil || body.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token required"})
		return
	}
	session, err := h.InstanceAgentSvc.AuthenticateSession(body.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, session)
}

// ---- POST /skills/import-bytes ------------------------------------------

type internalImportSkillRequest struct {
	UserID   int    `json:"user_id"`
	FileName string `json:"file_name"`
	DataB64  string `json:"data_b64"`
	Ext      string `json:"ext"`
}

func (h *InternalSecplaneHandler) importSkillArchiveBytes(c *gin.Context) {
	// Accept up to 64 MiB of base64-encoded zip.
	const maxBody = 64 * 1024 * 1024
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBody)
	var body internalImportSkillRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.UserID == 0 || body.FileName == "" || body.DataB64 == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id, file_name, data_b64 required"})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.DataB64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "data_b64 not valid base64: " + err.Error()})
		return
	}
	// Delegate to SkillService.ImportArchiveBytes — this is the in-process
	// path that secplane's packager already uses, which avoids having to
	// fabricate a *multipart.FileHeader. It runs the same scanner,
	// version-creation, and dedup logic as the public multipart endpoint.
	out, err := h.SkillSvc.ImportArchiveBytes(c.Request.Context(), body.UserID, body.FileName, raw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

// ---- GET /users/:id ----------------------------------------------------

// getUserByID is the smallest possible user lookup for the standalone
// secplane-server pod. secplane's RBAC middleware needs the user record
// (role + tenant_id) to gate certain admin routes, so this endpoint
// just wraps userRepo.GetByID with a 404-on-missing convention.
func (h *InternalSecplaneHandler) getUserByID(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user id must be an integer"})
		return
	}
	if h.UserRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user repo not wired"})
		return
	}
	u, err := h.UserRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, u)
}
