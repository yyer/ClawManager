package heartbeat

import (
	"testing"
	"time"
)

func TestPolicySupportsJitteredAgentReports(t *testing.T) {
	if got := ReportIntervalSeconds(); got != 120 {
		t.Fatalf("report interval = %d seconds, want 120", got)
	}
	if OnlineWindow != 180*time.Second {
		t.Fatalf("online window = %s, want 180s", OnlineWindow)
	}
	if Timeout != 360*time.Second {
		t.Fatalf("timeout = %s, want 360s", Timeout)
	}
	if Timeout <= ReportInterval*5/2 {
		t.Fatalf("timeout = %s, want more than two maximum jittered intervals", Timeout)
	}
}
