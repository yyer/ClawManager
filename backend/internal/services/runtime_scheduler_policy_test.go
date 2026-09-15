package services

import (
	"testing"
	"time"
)

func TestRuntimeSchedulerDefaultHeartbeatTimeoutSupportsJitteredReports(t *testing.T) {
	scheduler := NewRuntimeScheduler(nil, nil, nil, nil, nil, nil, nil, nil, 0)
	if got := scheduler.HeartbeatTimeout(); got != 360*time.Second {
		t.Fatalf("HeartbeatTimeout() = %s, want 360s", got)
	}
}
