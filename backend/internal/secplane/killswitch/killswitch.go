// Package killswitch — 应急熔断单行状态 + 启用/关闭。
//
// 启用后，dispatch 编译 user_config 时会注入 killSwitchEnabled=true，
// ClawAegis 在 before_tool_call 中无条件 block 所有工具调用直到关闭。
// 关闭即恢复（通过同样的 dispatch 链路把 killSwitchEnabled=false 推下去）。
package killswitch

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"clawreef/internal/secplane/dispatch"
	"clawreef/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/upper/db/v4"
)

// ----- Model ---------------------------------------------------------------

type State struct {
	ID        int        `db:"id" json:"id"`
	Enabled   int        `db:"enabled" json:"enabled"` // 0/1 (mysql tinyint)
	Reason    *string    `db:"reason" json:"reason,omitempty"`
	SetBy     *string    `db:"set_by" json:"set_by,omitempty"`
	SetAt     *time.Time `db:"set_at" json:"set_at,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt time.Time  `db:"updated_at" json:"updated_at"`
}

// IsEnabled exposes the int flag as bool for callers.
func (s *State) IsEnabled() bool { return s != nil && s.Enabled == 1 }

// ----- Service -------------------------------------------------------------

type Service interface {
	Get() (*State, error)
	Enable(reason, by string) (*State, error)
	Disable() (*State, error)
}

type service struct{ sess db.Session }

func NewService(sess db.Session) Service { return &service{sess: sess} }

func (s *service) col() db.Collection { return s.sess.Collection("secplane_kill_switch") }

func (s *service) Get() (*State, error) {
	var st State
	if err := s.col().Find(db.Cond{"id": 1}).One(&st); err != nil {
		return nil, fmt.Errorf("kill-switch state read: %w", err)
	}
	return &st, nil
}

func (s *service) Enable(reason, by string) (*State, error) {
	now := time.Now()
	fields := map[string]any{
		"enabled":    1,
		"reason":     reason,
		"set_by":     by,
		"set_at":     now,
		"updated_at": now,
	}
	if err := s.col().Find(db.Cond{"id": 1}).Update(fields); err != nil {
		return nil, fmt.Errorf("kill-switch enable: %w", err)
	}
	return s.Get()
}

func (s *service) Disable() (*State, error) {
	now := time.Now()
	fields := map[string]any{
		"enabled":    0,
		"reason":     nil,
		"set_by":     nil,
		"set_at":     nil,
		"updated_at": now,
	}
	if err := s.col().Find(db.Cond{"id": 1}).Update(fields); err != nil {
		return nil, fmt.Errorf("kill-switch disable: %w", err)
	}
	return s.Get()
}

// ----- Handler -------------------------------------------------------------

// Handler 暴露 GET / Enable / Disable。Enable / Disable 后立即触发一次
// dispatchAegisApply（空 instance_ids = 全实例），让状态秒级生效。
type Handler struct {
	svc          Service
	dispatchSvc  dispatch.Service
	dispatchCtx  context.Context // background ctx for the auto-dispatch
}

func NewHandler(svc Service, dispatchSvc dispatch.Service) *Handler {
	return &Handler{svc: svc, dispatchSvc: dispatchSvc, dispatchCtx: context.Background()}
}

// GET /api/v1/secplane/kill-switch
func (h *Handler) Get(c *gin.Context) {
	st, err := h.svc.Get()
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "kill-switch state", st)
}

type EnableRequest struct {
	Reason string `json:"reason"`
}

// POST /api/v1/secplane/kill-switch/enable  body: {"reason": "..."}
func (h *Handler) Enable(c *gin.Context) {
	var req EnableRequest
	_ = c.ShouldBindJSON(&req)
	if req.Reason == "" {
		req.Reason = "(未填写原因)"
	}
	st, err := h.svc.Enable(req.Reason, currentUsername(c))
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	dispatchResult := h.autoDispatch(c)
	utils.Success(c, http.StatusOK, "kill-switch enabled", gin.H{
		"state":    st,
		"dispatch": dispatchResult,
	})
}

// POST /api/v1/secplane/kill-switch/disable
func (h *Handler) Disable(c *gin.Context) {
	st, err := h.svc.Disable()
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	dispatchResult := h.autoDispatch(c)
	utils.Success(c, http.StatusOK, "kill-switch disabled", gin.H{
		"state":    st,
		"dispatch": dispatchResult,
	})
}

// autoDispatch — best-effort，错误只写日志不挡 toggle。
// 空 instance_ids → 派发到所有 running 实例。
func (h *Handler) autoDispatch(c *gin.Context) gin.H {
	if h.dispatchSvc == nil {
		return gin.H{"skipped": true, "reason": "dispatch service not wired"}
	}
	uid := currentUserID(c)
	res, err := h.dispatchSvc.DispatchAegisApply(h.dispatchCtx, uid, nil)
	if err != nil {
		return gin.H{"error": err.Error()}
	}
	return gin.H{
		"revision":      res.Revision,
		"target_count":  len(res.Targets),
	}
}

func currentUsername(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func currentUserID(c *gin.Context) *int {
	if v, ok := c.Get("userID"); ok {
		switch x := v.(type) {
		case int:
			return &x
		case int64:
			n := int(x)
			return &n
		case uint:
			n := int(x)
			return &n
		}
	}
	return nil
}
