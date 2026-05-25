// Package outbound — 出站可信端点白名单（域名 + 可选证书指纹）。
// ClawAegis before_tool_call 钩子读取 user_config.outboundTrustedEndpoints,
// 不在表里的 https URL 直接 block。配合 defense.outboundTrust toggle 三态。
package outbound

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/upper/db/v4"
)

// ----- Model ---------------------------------------------------------------

type Endpoint struct {
	ID                int        `db:"id" json:"id"`
	DomainPattern     string     `db:"domain_pattern" json:"domain_pattern"`
	FingerprintSHA256 *string    `db:"fingerprint_sha256" json:"fingerprint_sha256,omitempty"`
	Label             *string    `db:"label" json:"label,omitempty"`
	Channel           *string    `db:"channel" json:"channel,omitempty"`
	Scope             *string    `db:"scope" json:"scope,omitempty"`
	Status            string     `db:"status" json:"status"`
	ExpiresAt         *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	CreatedAt         time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time  `db:"updated_at" json:"updated_at"`
}

// ----- Repository ----------------------------------------------------------

type Repository interface {
	List() ([]Endpoint, error)
	ListActive() ([]Endpoint, error)
	ListPinned() ([]Endpoint, error) // status=active 且 fingerprint_sha256 非空
	Get(id int) (*Endpoint, error)
	Insert(e *Endpoint) error
	UpdateFingerprint(id int, fp string) error
	Delete(id int) error
}

type repository struct{ sess db.Session }

func NewRepository(sess db.Session) Repository { return &repository{sess: sess} }

func (r *repository) col() db.Collection { return r.sess.Collection("secplane_outbound_trusted") }

func (r *repository) List() ([]Endpoint, error) {
	var out []Endpoint
	err := r.col().Find().OrderBy("id ASC").All(&out)
	return out, err
}

func (r *repository) ListActive() ([]Endpoint, error) {
	var out []Endpoint
	err := r.col().Find(db.Cond{"status": "active"}).OrderBy("id ASC").All(&out)
	return out, err
}

func (r *repository) Insert(e *Endpoint) error {
	now := time.Now()
	e.CreatedAt = now
	e.UpdatedAt = now
	if e.Status == "" {
		e.Status = "active"
	}
	_, err := r.col().Insert(e)
	return err
}

func (r *repository) Delete(id int) error {
	return r.col().Find(db.Cond{"id": id}).Delete()
}

func (r *repository) ListPinned() ([]Endpoint, error) {
	var out []Endpoint
	err := r.col().Find(db.Cond{
		"status":                 "active",
		"fingerprint_sha256 IS NOT": nil,
	}).OrderBy("id ASC").All(&out)
	return out, err
}

func (r *repository) Get(id int) (*Endpoint, error) {
	var ep Endpoint
	if err := r.col().Find(db.Cond{"id": id}).One(&ep); err != nil {
		return nil, err
	}
	return &ep, nil
}

func (r *repository) UpdateFingerprint(id int, fp string) error {
	return r.col().Find(db.Cond{"id": id}).Update(map[string]any{
		"fingerprint_sha256": fp,
		"updated_at":         time.Now(),
	})
}

// ----- Service -------------------------------------------------------------

type Service interface {
	List() ([]Endpoint, error)
	ListActive() ([]Endpoint, error)
	Create(req CreateRequest) (*Endpoint, error)
	Delete(id int) error
	Probe(host string) (*ProbeResult, error)
	Reprobe(id int) (*ReprobeResponse, error)
}

type ReprobeResponse struct {
	Endpoint          *Endpoint    `json:"endpoint"`
	Probe             *ProbeResult `json:"probe"`
	PreviousFingerprint string     `json:"previous_fingerprint"`
	Drift             bool         `json:"drift"`
}

type CreateRequest struct {
	DomainPattern     string  `json:"domain_pattern" binding:"required,min=1,max=255"`
	FingerprintSHA256 *string `json:"fingerprint_sha256,omitempty"`
	Label             *string `json:"label,omitempty"`
	Channel           *string `json:"channel,omitempty"`
	Scope             *string `json:"scope,omitempty"`
}

type service struct{ repo Repository }

func NewService(repo Repository) Service { return &service{repo: repo} }

func (s *service) List() ([]Endpoint, error)       { return s.repo.List() }
func (s *service) ListActive() ([]Endpoint, error) { return s.repo.ListActive() }

func (s *service) Create(req CreateRequest) (*Endpoint, error) {
	domain := strings.ToLower(strings.TrimSpace(req.DomainPattern))
	if domain == "" {
		return nil, fmt.Errorf("domain_pattern is required")
	}
	if req.FingerprintSHA256 != nil {
		fp := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(*req.FingerprintSHA256, ":", "")))
		if fp != "" && len(fp) != 64 {
			return nil, fmt.Errorf("fingerprint_sha256 must be 64 hex chars (got %d)", len(fp))
		}
		if fp == "" {
			req.FingerprintSHA256 = nil
		} else {
			req.FingerprintSHA256 = &fp
		}
	}
	ep := &Endpoint{
		DomainPattern:     domain,
		FingerprintSHA256: req.FingerprintSHA256,
		Label:             req.Label,
		Channel:           req.Channel,
		Scope:             req.Scope,
		Status:            "active",
	}
	if err := s.repo.Insert(ep); err != nil {
		return nil, fmt.Errorf("insert: %w", err)
	}
	return ep, nil
}

func (s *service) Delete(id int) error {
	if id <= 0 {
		return fmt.Errorf("invalid id")
	}
	return s.repo.Delete(id)
}

// Probe 抓取 host 的 leaf cert 摘要，但不写库（用于"添加前预览"）。
func (s *service) Probe(host string) (*ProbeResult, error) {
	return ProbeTLS(strings.ToLower(strings.TrimSpace(host)), 443)
}

// Reprobe 拨号现有条目所在 domain_pattern，比对并按需更新指纹 +
// 报告 drift（drift=true 表示存量指纹与最新不一致，调用方自行决定是否发告警）。
// 不支持通配条目（domain_pattern 含 *）。
func (s *service) Reprobe(id int) (*ReprobeResponse, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid id")
	}
	ep, err := s.repo.Get(id)
	if err != nil {
		return nil, fmt.Errorf("not found: %w", err)
	}
	if strings.ContainsAny(ep.DomainPattern, "*?") {
		return nil, fmt.Errorf("wildcard pattern %q cannot be probed", ep.DomainPattern)
	}
	probe, err := ProbeTLS(ep.DomainPattern, 443)
	if err != nil {
		return nil, err
	}
	prev := ""
	if ep.FingerprintSHA256 != nil {
		prev = *ep.FingerprintSHA256
	}
	drift := prev != "" && prev != probe.FingerprintSHA256
	if prev != probe.FingerprintSHA256 {
		if err := s.repo.UpdateFingerprint(ep.ID, probe.FingerprintSHA256); err != nil {
			return nil, fmt.Errorf("update fingerprint: %w", err)
		}
		ep.FingerprintSHA256 = &probe.FingerprintSHA256
	}
	return &ReprobeResponse{
		Endpoint:            ep,
		Probe:               probe,
		PreviousFingerprint: prev,
		Drift:               drift,
	}, nil
}

// ----- Handler -------------------------------------------------------------

type Handler struct{ svc Service }

func NewHandler(svc Service) *Handler { return &Handler{svc: svc} }

// GET /api/v1/secplane/outbound/trusted
func (h *Handler) List(c *gin.Context) {
	items, err := h.svc.List()
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "outbound trusted endpoints", gin.H{"items": items})
}

// POST /api/v1/secplane/outbound/trusted
func (h *Handler) Create(c *gin.Context) {
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	ep, err := h.svc.Create(req)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusCreated, "trusted endpoint created", ep)
}

// POST /api/v1/secplane/outbound/trusted/probe
// 添加前预览 — 不写库，只返回 leaf cert 摘要让 UI 自动填指纹。
func (h *Handler) Probe(c *gin.Context) {
	var req struct {
		Host string `json:"host" binding:"required,min=1,max=255"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationError(c, err)
		return
	}
	res, err := h.svc.Probe(req.Host)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "tls probe ok", res)
}

// POST /api/v1/secplane/outbound/trusted/:id/reprobe
// 拨现有条目，对比并按需更新；返回 drift 标记。
func (h *Handler) Reprobe(c *gin.Context) {
	id, err := strconv.Atoi(strings.TrimSpace(c.Param("id")))
	if err != nil || id <= 0 {
		utils.ValidationError(c, fmt.Errorf("invalid id"))
		return
	}
	res, err := h.svc.Reprobe(id)
	if err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "tls reprobe ok", res)
}

// DELETE /api/v1/secplane/outbound/trusted/:id
func (h *Handler) Delete(c *gin.Context) {
	id, err := strconv.Atoi(strings.TrimSpace(c.Param("id")))
	if err != nil || id <= 0 {
		utils.ValidationError(c, fmt.Errorf("invalid id"))
		return
	}
	if err := h.svc.Delete(id); err != nil {
		utils.HandleError(c, err)
		return
	}
	utils.Success(c, http.StatusOK, "trusted endpoint deleted", nil)
}
