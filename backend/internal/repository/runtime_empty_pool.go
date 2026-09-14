package repository

import (
	"context"
	"fmt"
)

// Fail closed: even stale occupancy needs inspection rather than deletion.
// Counting all OpenClaw instances also includes Team references via instances.
func (r *runtimePodRepository) ValidateEmptyOpenClawPool(ctx context.Context, rolloutID int64) error {
	row, err := r.sess.SQL().QueryRowContext(ctx, `SELECT
 (SELECT COUNT(*) FROM instances WHERE type='openclaw' AND runtime_type='gateway') +
 (SELECT COUNT(*) FROM instance_runtime_bindings WHERE runtime_type='openclaw') +
 (SELECT COALESCE(SUM(used_slots),0) FROM runtime_pods WHERE runtime_type='openclaw') +
 (SELECT COUNT(*) FROM runtime_rollouts WHERE runtime_type='openclaw' AND status IN ('pending','running') AND id<>?)`, rolloutID)
	if err != nil {
		return err
	}
	var count int64
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("OpenClaw pool is not empty: instances, bindings, gateway occupancy or another rollout remain")
	}
	return nil
}
