// Package secplane wires the security protection platform routes onto a Gin
// engine. Keeping all route registration here lets main.go integrate the
// module with a single function call so the rest of ClawManager is unaware of
// secplane internals.
package secplane

import (
	"context"
	"time"

	"clawreef/internal/middleware"
	"clawreef/internal/repository"
	"clawreef/internal/secplane/dispatch"
	"clawreef/internal/secplane/ingest"
	"clawreef/internal/secplane/killswitch"
	"clawreef/internal/secplane/outbound"
	"clawreef/internal/secplane/policy"
	"clawreef/internal/services"
	"clawreef/internal/services/k8s"

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

	OutboundService outbound.Service
	outboundHandler *outbound.Handler
	outboundWatcher *outbound.Watcher

	KillSwitchService killswitch.Service
	killSwitchHandler *killswitch.Handler
}

// killSwitchAdapter — 把 killswitch.Service 适配成 dispatch.KillSwitchProvider，
// 避免 dispatch 包直接 import killswitch（dispatch ← killswitch 单向）。
type killSwitchAdapter struct{ svc killswitch.Service }

func (a killSwitchAdapter) IsEnabled() (bool, string) {
	st, err := a.svc.Get()
	if err != nil || st == nil {
		return false, ""
	}
	reason := ""
	if st.Reason != nil {
		reason = *st.Reason
	}
	return st.IsEnabled(), reason
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

	outboundRepo := outbound.NewRepository(sess)
	outboundSvc := outbound.NewService(outboundRepo)

	podSvc := k8s.NewPodService()
	cmdRepo := repository.NewInstanceCommandRepository(sess)
	runtimeCfgRepo := dispatch.NewRuntimeConfigRepository(sess)
	dispatchSvc := dispatch.NewService(policySvc, cmdSvc, instanceRepo, skillSvc, outboundSvc, podSvc, cmdRepo, runtimeCfgRepo)

	killSwitchSvc := killswitch.NewService(sess)
	dispatchSvc.SetKillSwitchProvider(killSwitchAdapter{svc: killSwitchSvc})

	return &Module{
		PolicyService:     policySvc,
		policyHandler:     policy.NewHandler(policySvc),
		DispatchService:   dispatchSvc,
		dispatchHandler:   dispatch.NewHandler(dispatchSvc),
		ingestHandler:     ingest.NewHandler(agentSvc, instanceRepo, policySvc),
		OutboundService:   outboundSvc,
		outboundHandler:   outbound.NewHandler(outboundSvc),
		outboundWatcher:   outbound.NewWatcher(outboundRepo, alertRepo, time.Hour),
		KillSwitchService: killSwitchSvc,
		killSwitchHandler: killswitch.NewHandler(killSwitchSvc, dispatchSvc),
	}
}

// StartBackgroundWorkers 启动模块自己的周期任务（如出站证书指纹漂移巡检）。
// 调用方传入 ctx，关闭即停。
func (m *Module) StartBackgroundWorkers(ctx context.Context) {
	if m.outboundWatcher != nil {
		m.outboundWatcher.Start(ctx)
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
		admin.POST("/dispatch/aegis-apply", m.dispatchHandler.DispatchAegisApply)
		admin.POST("/dispatch/secureclaw", m.dispatchHandler.DispatchSecureClaw)
		admin.GET("/instances/:id/effective-config", m.dispatchHandler.GetInstanceEffectiveConfig)
		admin.GET("/instances/:id/aegis/live-config", m.dispatchHandler.GetInstanceLiveConfig)

		collab := admin.Group("/collab")
		{
			collab.GET("/policy", m.policyHandler.GetCollabPolicy)
			collab.PUT("/policy", m.policyHandler.UpsertCollabPolicy)
		}

		outboundGrp := admin.Group("/outbound/trusted")
		{
			outboundGrp.GET("", m.outboundHandler.List)
			outboundGrp.POST("", m.outboundHandler.Create)
			outboundGrp.POST("/probe", m.outboundHandler.Probe)
			outboundGrp.POST("/:id/reprobe", m.outboundHandler.Reprobe)
			outboundGrp.DELETE("/:id", m.outboundHandler.Delete)
		}

		ks := admin.Group("/kill-switch")
		{
			ks.GET("", m.killSwitchHandler.Get)
			ks.POST("/enable", m.killSwitchHandler.Enable)
			ks.POST("/disable", m.killSwitchHandler.Disable)
		}
	}

	// Agent-session-protected routes (security event ingest).
	agent := g.Group("/agent")
	agent.Use(m.ingestHandler.AuthMiddleware())
	{
		agent.POST("/sec_events/batch", m.ingestHandler.IngestBatch)
	}
}
