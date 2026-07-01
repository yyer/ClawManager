package dispatch

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/upper/db/v4"
)

// RuntimeConfigRecord 是 secplane_instance_runtime_config 表的一行：某个
// instance 上某个 skill（clawaegisex / secureclaw）最近一次成功下发的
// user_config 快照。dispatch 路径在 target 成功时 upsert；GetLiveAegisConfig
// 优先读本表，避免依赖 agent 上报的 skill_blob。
type RuntimeConfigRecord struct {
	InstanceID   int                    `db:"instance_id"   json:"instance_id"`
	SkillName    string                 `db:"skill_name"    json:"skill_name"`
	Revision     string                 `db:"revision"      json:"revision"`
	Sha256       string                 `db:"sha256"        json:"sha256"`
	ConfigSha256 string                 `db:"config_sha256" json:"config_sha256"`
	UserConfig   string                 `db:"user_config"   json:"-"` // JSON-encoded; expose via UserConfigMap
	Source       string                 `db:"source"        json:"source"`
	CommandID    *int                   `db:"command_id"    json:"command_id,omitempty"`
	Status       string                 `db:"status"        json:"status"`
	DispatchedAt time.Time              `db:"dispatched_at" json:"dispatched_at"`
	CreatedAt    time.Time              `db:"created_at"    json:"created_at"`
	UpdatedAt    time.Time              `db:"updated_at"    json:"updated_at"`
}

// UserConfigMap 反序列化 UserConfig 字段。出错返回空 map（调用方自行处理 nil）。
func (r *RuntimeConfigRecord) UserConfigMap() map[string]interface{} {
	if r == nil || r.UserConfig == "" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(r.UserConfig), &m); err != nil {
		return nil
	}
	return m
}

// RuntimeConfigRepository 读写 secplane_instance_runtime_config 表。
type RuntimeConfigRepository interface {
	// Upsert 写入或覆盖 (instance_id, skill_name) 对应的行。dispatch 成功后调用。
	Upsert(rec *RuntimeConfigRecord) error
	// GetByInstance 取 (instance_id, skill_name) 当前行；不存在返回 (nil, nil)。
	GetByInstance(instanceID int, skillName string) (*RuntimeConfigRecord, error)
}

type runtimeConfigRepo struct{ sess db.Session }

// NewRuntimeConfigRepository 构造默认实现。
func NewRuntimeConfigRepository(sess db.Session) RuntimeConfigRepository {
	return &runtimeConfigRepo{sess: sess}
}

func (r *runtimeConfigRepo) col() db.Collection {
	return r.sess.Collection("secplane_instance_runtime_config")
}

func (r *runtimeConfigRepo) Upsert(rec *RuntimeConfigRecord) error {
	if rec == nil {
		return fmt.Errorf("runtime_config: nil record")
	}
	if rec.InstanceID == 0 || rec.SkillName == "" {
		return fmt.Errorf("runtime_config: instance_id and skill_name are required")
	}
	if rec.DispatchedAt.IsZero() {
		rec.DispatchedAt = time.Now().UTC()
	}
	if rec.Status == "" {
		rec.Status = "succeeded"
	}
	now := time.Now().UTC()
	rec.UpdatedAt = now
	// 显式 Get → Insert/Update，避免依赖 upper/db 对 duplicate-key 的错误语义。
	existing, err := r.GetByInstance(rec.InstanceID, rec.SkillName)
	if err != nil {
		return fmt.Errorf("runtime_config: lookup before upsert: %w", err)
	}
	if existing == nil {
		rec.CreatedAt = now
		if _, err := r.col().Insert(rec); err != nil {
			return fmt.Errorf("runtime_config: insert: %w", err)
		}
		return nil
	}
	// Update 用 map 显式列出字段，避免 ORM 把 created_at 一起覆盖。
	row := map[string]interface{}{
		"instance_id":   rec.InstanceID,
		"skill_name":    rec.SkillName,
		"revision":      rec.Revision,
		"sha256":        rec.Sha256,
		"config_sha256": rec.ConfigSha256,
		"user_config":   rec.UserConfig,
		"source":        rec.Source,
		"command_id":    rec.CommandID,
		"status":        rec.Status,
		"dispatched_at": rec.DispatchedAt,
		"updated_at":    now,
	}
	if err := r.col().Find(db.Cond{"instance_id": rec.InstanceID, "skill_name": rec.SkillName}).Update(row); err != nil {
		return fmt.Errorf("runtime_config: update: %w", err)
	}
	return nil
}

func (r *runtimeConfigRepo) GetByInstance(instanceID int, skillName string) (*RuntimeConfigRecord, error) {
	var rec RuntimeConfigRecord
	err := r.col().Find(db.Cond{"instance_id": instanceID, "skill_name": skillName}).One(&rec)
	if err != nil {
		if err == db.ErrNoMoreRows {
			return nil, nil
		}
		return nil, fmt.Errorf("runtime_config: lookup (instance=%d, skill=%s): %w", instanceID, skillName, err)
	}
	return &rec, nil
}
