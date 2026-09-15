package services

import (
	"testing"
	"time"

	"clawreef/internal/heartbeat"
	"clawreef/internal/models"
)

func TestInstanceAgentHeartbeatPolicySupportsJitteredReports(t *testing.T) {
	if heartbeat.ReportIntervalSeconds() != 120 {
		t.Fatalf("heartbeat interval = %d seconds, want 120", heartbeat.ReportIntervalSeconds())
	}

	now := time.Now().UTC()
	tests := []struct {
		name   string
		agent  *models.InstanceAgent
		status string
	}{
		{name: "missing", status: agentStatusOffline},
		{name: "online", agent: &models.InstanceAgent{LastHeartbeatAt: timePointer(now.Add(-2 * time.Minute))}, status: agentStatusOnline},
		{name: "stale", agent: &models.InstanceAgent{LastHeartbeatAt: timePointer(now.Add(-4 * time.Minute))}, status: agentStatusStale},
		{name: "offline", agent: &models.InstanceAgent{LastHeartbeatAt: timePointer(now.Add(-7 * time.Minute))}, status: agentStatusOffline},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := deriveAgentStatus(test.agent); got != test.status {
				t.Fatalf("deriveAgentStatus() = %q, want %q", got, test.status)
			}
		})
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}
