package outbound

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"clawreef/internal/secplane/policy"
)

// Watcher — 周期性重探所有 pinned 条目（fingerprint 非空），
// 发现指纹与基线不一致时：写 secplane_alert + 把基线更新为最新指纹。
// 通配条目（含 *）一律跳过。
type Watcher struct {
	repo      Repository
	alertRepo policy.AlertRepository
	interval  time.Duration
}

func NewWatcher(repo Repository, alertRepo policy.AlertRepository, interval time.Duration) *Watcher {
	if interval <= 0 {
		interval = time.Hour
	}
	return &Watcher{repo: repo, alertRepo: alertRepo, interval: interval}
}

// Start 启动后台 goroutine，调用方控制生命周期。
// 启动后立刻跑一次，之后每 interval 跑一次。
func (w *Watcher) Start(ctx context.Context) {
	go func() {
		w.runOnce()
		t := time.NewTicker(w.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.runOnce()
			}
		}
	}()
}

func (w *Watcher) runOnce() {
	pinned, err := w.repo.ListPinned()
	if err != nil {
		log.Printf("outbound.watcher: list pinned failed: %v", err)
		return
	}
	for _, ep := range pinned {
		if strings.ContainsAny(ep.DomainPattern, "*?") {
			continue
		}
		probe, perr := ProbeTLS(ep.DomainPattern, 443)
		if perr != nil {
			log.Printf("outbound.watcher: probe %s failed: %v", ep.DomainPattern, perr)
			continue
		}
		prev := ""
		if ep.FingerprintSHA256 != nil {
			prev = *ep.FingerprintSHA256
		}
		if prev == probe.FingerprintSHA256 {
			continue
		}
		// drift — emit alert + 更新基线
		w.emitDriftAlert(ep, prev, probe)
		if err := w.repo.UpdateFingerprint(ep.ID, probe.FingerprintSHA256); err != nil {
			log.Printf("outbound.watcher: update fingerprint id=%d failed: %v", ep.ID, err)
		}
	}
}

func (w *Watcher) emitDriftAlert(ep Endpoint, prev string, probe *ProbeResult) {
	if w.alertRepo == nil {
		return
	}
	ruleID := "defense.outboundTrust"
	ruleName := "出站可信端点指纹漂移"
	subject := ep.DomainPattern
	evidence := fmt.Sprintf(
		"domain=%s previous=%s current=%s subject_cn=%s issuer=%s not_after=%s",
		ep.DomainPattern, truncFp(prev), truncFp(probe.FingerprintSHA256),
		probe.SubjectCN, probe.Issuer, probe.NotAfter.Format(time.RFC3339),
	)
	alert := &policy.Alert{
		Source:   "aegis",
		RuleID:   &ruleID,
		RuleName: &ruleName,
		Severity: "high",
		Action:   "alert",
		Subject:  &subject,
		Evidence: &evidence,
		Ts:       time.Now(),
	}
	if err := w.alertRepo.Insert(alert); err != nil {
		log.Printf("outbound.watcher: insert drift alert failed: %v", err)
	}
}

func truncFp(fp string) string {
	if fp == "" {
		return "(empty)"
	}
	if len(fp) > 16 {
		return fp[:8] + "..." + fp[len(fp)-8:]
	}
	return fp
}
