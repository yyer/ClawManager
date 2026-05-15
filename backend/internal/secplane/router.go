// Package secplane wires the security protection platform routes onto a Gin
// engine. Keeping all route registration here lets main.go integrate the
// module with a single function call so the rest of ClawManager is unaware of
// secplane internals.
package secplane

import (
	"clawreef/internal/middleware"
	"clawreef/internal/repository"
	"clawreef/internal/secplane/dispatch"
	"clawreef/internal/secplane/ingest"
	"clawreef/internal/secplane/policy"
	"clawreef/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/upper/db/v4"
)

// Module bundles the wired-up secplane components so handlers can be reached
// from main.go without leaking sub-package types.
type Module struct {
	PolicyService policy.Service
	policyHandler *policy.Handler

	DispatchService dispatch.Service
	dispatchHandler *dispatch.Handler

	ingestHandler *ingest.Handler
}

// NewModule constructs the secplane module with all of its repositories and
// services from a shared db.Session and the ClawManager-side InstanceAgent /
// InstanceCommand / Skill collaborators.
func NewModule(
	sess db.Session,
	cmdSvc services.InstanceCommandService,
	agentSvc services.InstanceAgentService,
	instanceRepo repository.InstanceRepository,
	skillSvc services.SkillService,
) *Module {
	ruleRepo := policy.NewRuleRepository(sess)
	alertRepo := policy.NewAlertRepository(sess)
	policySvc := policy.NewService(ruleRepo, alertRepo)

	dispatchSvc := dispatch.NewService(policySvc, cmdSvc, instanceRepo, skillSvc)

	return &Module{
		PolicyService:   policySvc,
		policyHandler:   policy.NewHandler(policySvc),
		DispatchService: dispatchSvc,
		dispatchHandler: dispatch.NewHandler(dispatchSvc),
		ingestHandler:   ingest.NewHandler(agentSvc, instanceRepo, policySvc),
	}
}

// Register attaches /api/v1/secplane/* routes. Three sub-trees:
//
//   /policy/*        admin-authenticated rule CRUD + test
//   /alerts          admin-authenticated alert read
//   /dispatch/*      admin-authenticated config push
//   /agent/*         agent-session-authenticated event ingest
func (m *Module) Register(api *gin.RouterGroup, userRepo repository.UserRepository) {
	g := api.Group("/secplane")

	// Admin-protected routes (rules, alerts, dispatch).
	admin := g.Group("")
	admin.Use(middleware.Auth())
	admin.Use(middleware.SetUserInfo(userRepo))
	admin.Use(middleware.NewAdminAuth(userRepo))
	{
		rules := admin.Group("/policy/rules")
		{
			rules.GET("", m.policyHandler.ListRules)
			rules.PUT("", m.policyHandler.UpsertRule)
			rules.DELETE("/:rule_id", m.policyHandler.DeleteRule)
			rules.POST("/bulk-status", m.policyHandler.BulkStatus)
			rules.POST("/test", m.policyHandler.Test)
		}
		admin.GET("/alerts", m.policyHandler.ListAlerts)
		admin.POST("/dispatch/aegis", m.dispatchHandler.DispatchAegis)
		admin.GET("/instances/:id/effective-config", m.dispatchHandler.GetInstanceEffectiveConfig)
	}

	// Agent-session-protected routes (security event ingest).
	agent := g.Group("/agent")
	agent.Use(m.ingestHandler.AuthMiddleware())
	{
		agent.POST("/sec_events/batch", m.ingestHandler.IngestBatch)
	}
}
