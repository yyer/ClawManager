package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// SaveRuleInput is the canonical write payload for upsert.
type SaveRuleInput struct {
	RuleID      string
	Kind        string
	DisplayName string
	Description *string
	Pattern     string
	Target      string
	Severity    string
	Action      string
	Mode        string
	IsEnabled   bool
	SortOrder   int
	Tags        *string
}

// TestInput is the input to the rule-test endpoint. RecordAlert flips whether
// matching rules write to secplane_alert (so the "近期事件" tab fills as you
// debug from the Test tab).
type TestInput struct {
	Text         string
	Target       string
	RecordAlert  bool
	Subject      string
	TraceID      string
	AgentID      string
	Source       string
	Draft        *SaveRuleInput
}

// Match represents one matching rule for a given evaluation.
type Match struct {
	RuleID       string `json:"rule_id"`
	RuleName     string `json:"rule_name"`
	Severity     string `json:"severity"`
	Action       string `json:"action"`
	Mode         string `json:"mode"`
	MatchedText  string `json:"matched_text"`
	MatchSummary string `json:"match_summary"`
}

// AnalysisResult is the aggregate evaluation outcome.
type AnalysisResult struct {
	IsSensitive     bool    `json:"is_sensitive"`
	HighestSeverity string  `json:"highest_severity"`
	HighestAction   string  `json:"highest_action"`
	Hits            []Match `json:"hits"`
}

// Service is the FR-01 (and future prompt_filter / rule-based) facade.
type Service interface {
	List(kind string) ([]Rule, error)
	Save(in SaveRuleInput) (*Rule, error)
	Disable(ruleID string) error
	Delete(ruleID string) error
	BulkSetEnabled(ruleIDs []string, enabled bool) error
	Test(in TestInput) (AnalysisResult, error)
	ListAlerts(filter AlertFilter) ([]Alert, error)
	// RecordExternalAlert persists an Alert produced by an external emitter
	// (clawaegisex JSONL ingest, secureclaw, ksecure relay, ...).
	RecordExternalAlert(alert *Alert) error
}

type service struct {
	rules  RuleRepository
	alerts AlertRepository
}

// NewService wires the secplane policy service.
func NewService(rules RuleRepository, alerts AlertRepository) Service {
	return &service{rules: rules, alerts: alerts}
}

func (s *service) List(kind string) ([]Rule, error) {
	return s.rules.List(kind)
}

func (s *service) Save(in SaveRuleInput) (*Rule, error) {
	rule, err := buildRule(in)
	if err != nil {
		return nil, err
	}
	if err := s.rules.Upsert(rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (s *service) Disable(ruleID string) error {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return errors.New("rule id is required")
	}
	existing, err := s.rules.GetByRuleID(ruleID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.New("secplane rule not found")
	}
	existing.IsEnabled = false
	return s.rules.Upsert(existing)
}

func (s *service) Delete(ruleID string) error {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return errors.New("rule id is required")
	}
	return s.rules.Delete(ruleID)
}

func (s *service) BulkSetEnabled(ruleIDs []string, enabled bool) error {
	if len(ruleIDs) == 0 {
		return errors.New("at least one rule id is required")
	}
	cleaned := make([]string, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return errors.New("rule id is required")
		}
		cleaned = append(cleaned, id)
	}
	return s.rules.BulkSetEnabled(cleaned, enabled)
}

func (s *service) Test(in TestInput) (AnalysisResult, error) {
	text := strings.TrimSpace(in.Text)
	if text == "" {
		return AnalysisResult{}, errors.New("sample text is required")
	}

	var rules []Rule
	if in.Draft != nil {
		rule, err := buildRule(*in.Draft)
		if err != nil {
			return AnalysisResult{}, err
		}
		rules = []Rule{*rule}
	} else {
		items, err := s.rules.ListEnabled(KindPromptFilter)
		if err != nil {
			return AnalysisResult{}, err
		}
		// If a target filter is supplied, narrow the rule set so user-input
		// tests don't fire RAG-only rules.
		if in.Target != "" {
			filtered := make([]Rule, 0, len(items))
			for _, r := range items {
				if r.Target == "" || r.Target == in.Target {
					filtered = append(filtered, r)
				}
			}
			items = filtered
		}
		rules = items
	}

	result := analyze(text, rules)

	if in.RecordAlert && result.IsSensitive {
		source := strings.TrimSpace(in.Source)
		if source == "" {
			source = "platform"
		}
		var traceID, agentID, subject *string
		if in.TraceID != "" {
			t := in.TraceID
			traceID = &t
		}
		if in.AgentID != "" {
			a := in.AgentID
			agentID = &a
		}
		subj := strings.TrimSpace(in.Subject)
		if subj == "" {
			subj = "secplane.policy.test"
		}
		subject = &subj

		preview := text
		if len(preview) > 800 {
			preview = preview[:800] + "…"
		}

		for _, hit := range result.Hits {
			ev := hit.MatchSummary
			if hit.MatchedText != "" {
				ev = fmt.Sprintf("%s: %s", hit.MatchSummary, hit.MatchedText)
			}
			alert := &Alert{
				TraceID:    traceID,
				Source:     source,
				RuleID:     strPtr(hit.RuleID),
				RuleName:   strPtr(hit.RuleName),
				Severity:   hit.Severity,
				Action:     normalizeAlertAction(hit.Action, hit.Mode),
				AgentID:    agentID,
				Subject:    subject,
				Evidence:   strPtr(ev),
				RawPayload: strPtr(preview),
			}
			if err := s.alerts.Insert(alert); err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

func (s *service) ListAlerts(filter AlertFilter) ([]Alert, error) {
	return s.alerts.List(filter)
}

func (s *service) RecordExternalAlert(alert *Alert) error {
	if alert == nil {
		return errors.New("alert is required")
	}
	if strings.TrimSpace(alert.Source) == "" {
		alert.Source = "external"
	}
	if strings.TrimSpace(alert.Severity) == "" {
		alert.Severity = SeverityLow
	}
	if strings.TrimSpace(alert.Action) == "" {
		alert.Action = "observed"
	}
	return s.alerts.Insert(alert)
}

// buildRule normalizes and validates a SaveRuleInput.
func buildRule(in SaveRuleInput) (*Rule, error) {
	ruleID := strings.TrimSpace(in.RuleID)
	if ruleID == "" {
		return nil, errors.New("rule id is required")
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		return nil, errors.New("rule display name is required")
	}
	kind := strings.TrimSpace(in.Kind)
	if kind == "" {
		kind = KindPromptFilter
	}

	pattern := strings.TrimSpace(in.Pattern)
	// Toggle-shaped kinds carry no regex; only validate the pattern for
	// kinds that actually match against text or that store a resource
	// identifier (protected_*).
	patternRequired := kind == KindPromptFilter || kind == KindToolControl ||
		kind == KindFileProtect || kind == KindNetworkACL || kind == KindProcessControl
	if patternRequired {
		if pattern == "" {
			return nil, errors.New("rule pattern is required")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, errors.New("rule pattern is invalid")
		}
	}

	target := strings.TrimSpace(in.Target)
	if target == "" {
		target = TargetUserInput
	}

	severity := strings.TrimSpace(in.Severity)
	switch severity {
	case SeverityLow, SeverityMedium, SeverityHigh:
	case "":
		severity = SeverityMedium
	default:
		return nil, errors.New("severity is invalid")
	}

	action := strings.TrimSpace(in.Action)
	switch action {
	case ActionObserve, ActionRedact, ActionBlock:
	case "":
		action = ActionObserve
	default:
		return nil, errors.New("action is invalid")
	}

	mode := strings.TrimSpace(in.Mode)
	switch mode {
	case ModeEnforce, ModeObserve, ModeOff:
	case "":
		mode = ModeEnforce
	default:
		return nil, errors.New("mode is invalid")
	}

	var description *string
	if in.Description != nil {
		trimmed := strings.TrimSpace(*in.Description)
		if trimmed != "" {
			description = &trimmed
		}
	}

	return &Rule{
		RuleID:      ruleID,
		Kind:        kind,
		DisplayName: displayName,
		Description: description,
		Pattern:     pattern,
		Target:      target,
		Severity:    severity,
		Action:      action,
		Mode:        mode,
		IsEnabled:   in.IsEnabled,
		SortOrder:   in.SortOrder,
		Tags:        in.Tags,
	}, nil
}

// analyze runs all supplied rules against text and aggregates the result.
// Rules with mode=off are skipped.
func analyze(text string, rules []Rule) AnalysisResult {
	hits := []Match{}
	for _, rule := range rules {
		if rule.Mode == ModeOff {
			continue
		}
		pattern := strings.TrimSpace(rule.Pattern)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		loc := re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		matched := text[loc[0]:loc[1]]
		if len(matched) > 200 {
			matched = matched[:200] + "…"
		}
		summary := strings.TrimSpace(deref(rule.Description))
		if summary == "" {
			summary = fmt.Sprintf("命中规则 %s。", rule.DisplayName)
		}
		hits = append(hits, Match{
			RuleID:       rule.RuleID,
			RuleName:     rule.DisplayName,
			Severity:     rule.Severity,
			Action:       rule.Action,
			Mode:         rule.Mode,
			MatchedText:  matched,
			MatchSummary: summary,
		})
	}

	highestSeverity := SeverityLow
	highestAction := ActionObserve
	for _, h := range hits {
		if severityRank(h.Severity) > severityRank(highestSeverity) {
			highestSeverity = h.Severity
		}
		if actionRank(h.Action) > actionRank(highestAction) {
			highestAction = h.Action
		}
	}
	return AnalysisResult{
		IsSensitive:     len(hits) > 0,
		HighestSeverity: highestSeverity,
		HighestAction:   highestAction,
		Hits:            hits,
	}
}

func severityRank(s string) int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

func actionRank(a string) int {
	switch a {
	case ActionBlock:
		return 3
	case ActionRedact:
		return 2
	case ActionObserve:
		return 1
	}
	return 0
}

// normalizeAlertAction maps (rule.action, rule.mode) into the past-tense action
// recorded on the alert. observe-mode rules are always recorded as "observed"
// regardless of declared action.
func normalizeAlertAction(action, mode string) string {
	if mode == ModeObserve {
		return "observed"
	}
	switch action {
	case ActionBlock:
		return "blocked"
	case ActionRedact:
		return "redacted"
	default:
		return "observed"
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
