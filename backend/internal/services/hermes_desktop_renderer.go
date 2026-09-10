package services

// The pinned Desktop renderer speaks the existing Hermes REST/JSON-RPC APIs.
// These adapters project one CM-owned Runtime, never enumerate host profiles or
// expose Electron's machine-wide capabilities.
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var hermesDesktopSources = regexp.MustCompile(`^[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$`)
var hermesDesktopModelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}$`)
var hermesDesktopModelSwitch = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}) --provider ([A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}) --session$`)
var errHermesDesktopUnboundSession = errors.New("session not found; resume required")

func hermesDesktopPick(object map[string]json.RawMessage, keys string) map[string]json.RawMessage {
	result := map[string]json.RawMessage{}
	for _, key := range strings.Fields(keys) {
		if value, ok := object[key]; ok {
			result[key] = value
		}
	}
	return result
}

func hermesDesktopPickScalars(object map[string]json.RawMessage, keys string) map[string]json.RawMessage {
	result := hermesDesktopPick(object, keys)
	for key, raw := range result {
		var value any
		if json.Unmarshal(raw, &value) != nil {
			delete(result, key)
			continue
		}
		switch value.(type) {
		case nil, string, bool, float64:
		default:
			delete(result, key)
		}
	}
	return result
}

func hermesDesktopSessionRow(raw json.RawMessage) (json.RawMessage, error) {
	var row map[string]json.RawMessage
	if json.Unmarshal(raw, &row) != nil || row == nil {
		return nil, ErrHermesDesktopUpstream
	}
	var id string
	if json.Unmarshal(row["id"], &id) != nil || !hermesDesktopSessionID.MatchString(id) {
		return nil, ErrHermesDesktopUpstream
	}
	return json.Marshal(row)
}

func hermesDesktopProjectHTTP(path string, body []byte) ([]byte, error) {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil, ErrHermesDesktopUpstream
	}
	if strings.HasSuffix(path, "/messages") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, ErrHermesDesktopUpstream
		}
		messages, ok := object["messages"].([]any)
		if !ok {
			return nil, ErrHermesDesktopUpstream
		}
		for _, raw := range messages {
			message, ok := raw.(map[string]any)
			if ok && message["role"] == "system" {
				// Keep the row and all metadata so pagination and renderer state stay
				// exact, while the managed browser never receives a system prompt.
				message["content"] = ""
				if _, exists := message["display_content"]; exists {
					message["display_content"] = ""
				}
				if _, exists := message["text"]; exists {
					message["text"] = ""
				}
				message["display_kind"] = "hidden"
			}
		}
	}
	return json.Marshal(value)
}

func (s *HermesDesktopService) desktopRead(ctx context.Context, target *hermesDesktopTarget, path string, query url.Values) ([]byte, error) {
	q := url.Values{}
	for key, values := range query {
		q[key] = append([]string(nil), values...)
	}
	body, _, cookies, err := s.upstreamRequest(ctx, target, http.MethodGet, "/api"+path, q.Encode())
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	sessionProjection := len(parts) == 3 && parts[0] == "sessions" && hermesDesktopSessionID.MatchString(parts[1]) && parts[2] == "messages"
	project := sessionProjection
	if project {
		body, err = hermesDesktopProjectHTTP(path, body)
		if err != nil {
			return nil, err
		}
	}
	return hermesDesktopSanitize(body, *target.instance.AccessToken, cookies)
}

// Schema keys describe configuration fields and must remain intact even when
// their names contain words such as token or key. Only secret values are redacted.
func hermesDesktopRedactStringValues(body []byte, secrets ...string) ([]byte, error) {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil, ErrHermesDesktopUpstream
	}
	var clean func(any) any
	clean = func(v any) any {
		switch item := v.(type) {
		case map[string]any:
			for key, child := range item {
				item[key] = clean(child)
			}
			return item
		case []any:
			for i := range item {
				item[i] = clean(item[i])
			}
			return item
		case string:
			for _, secret := range secrets {
				if secret != "" {
					item = strings.ReplaceAll(item, secret, "[redacted]")
				}
			}
			return item
		default:
			return v
		}
	}
	return json.Marshal(clean(value))
}

func (s *HermesDesktopService) desktopSidebar(ctx context.Context, target *hermesDesktopTarget, query url.Values) ([]byte, error) {
	result := map[string]any{}
	for _, section := range []string{"recents", "cron", "messaging"} {
		limit := query.Get(section + "_limit")
		if limit == "" {
			limit = "40"
		}
		q := url.Values{"limit": {limit}, "offset": {"0"}, "order": {"recent"}, "archived": {"exclude"}, "min_messages": {"1"}}
		if section == "cron" {
			q.Set("source", "cron")
		} else if exclude := query.Get(section + "_exclude"); exclude != "" {
			q.Set("exclude_sources", exclude)
		}
		if profile := query.Get("recents_profile"); profile != "" && profile != "all" {
			q.Set("profile", profile)
		}
		body, err := s.desktopRead(ctx, target, "/sessions", q)
		if err != nil {
			return nil, err // Never turn unavailable real history into fake empty success.
		}
		var page struct {
			Sessions []json.RawMessage `json:"sessions"`
			Total    int               `json:"total"`
		}
		if json.Unmarshal(body, &page) != nil {
			return nil, ErrHermesDesktopUpstream
		}
		n, _ := strconv.Atoi(limit)
		profile := query.Get("recents_profile")
		if profile == "" || profile == "all" {
			profile = "default"
		}
		result[section] = map[string]any{"sessions": page.Sessions, "profiles_truncated": map[string]bool{profile: page.Total > n}}
	}
	return json.Marshal(result)
}

func (s *HermesDesktopService) desktopRPCModelAllowed(ctx context.Context, target *hermesDesktopTarget, frame []byte) bool {
	// Runtime owns provider/model validation. The BFF only binds the request to
	// the authenticated instance and workspace; a catalogue cache here would
	// silently turn Desktop's evolving model UI into a local allowlist.
	return true
}

// A socket may activate/close/change only live IDs whose create/resume reply it
// received. Reconnecting renderers re-resume stored IDs; warm activation of an
// unknown runtime fails, invoking the renderer's existing resume fallback.
type hermesDesktopRPCScope struct {
	mu        sync.Mutex
	live      map[string]bool
	pending   map[string]hermesDesktopPendingRPC
	approvals map[string]map[string]bool // session -> request -> deny-only replay
}
type hermesDesktopPendingRPC struct{ method, sessionID string }

func newHermesDesktopRPCScope() *hermesDesktopRPCScope {
	return &hermesDesktopRPCScope{live: map[string]bool{}, pending: map[string]hermesDesktopPendingRPC{}, approvals: map[string]map[string]bool{}}
}

func (scope *hermesDesktopRPCScope) admit(frame []byte) error {
	var request struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			SessionID string `json:"session_id"`
			RequestID string `json:"request_id"`
			Choice    string `json:"choice"`
		} `json:"params"`
	}
	if json.Unmarshal(frame, &request) != nil {
		return ErrHermesDesktopForbidden
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if len(scope.pending) >= 256 {
		return ErrHermesDesktopForbidden
	}
	if _, exists := scope.pending[string(request.ID)]; exists {
		return ErrHermesDesktopForbidden
	}
	// Reads are scoped by the CM-authenticated isolated target. Replay runs
	// immediately on reconnect, before the App's stored-ID resume completes.
	if request.Params.SessionID != "" && request.Method != "session.resume" && request.Method != "session.history" && request.Method != "session.status" && request.Method != "session.events.since" && !scope.live[request.Params.SessionID] {
		return errHermesDesktopUnboundSession
	}
	if request.Method == "approval.received" || request.Method == "approval.respond" {
		denyOnly, known := scope.approvals[request.Params.SessionID][request.Params.RequestID]
		if !known || (request.Method == "approval.respond" && denyOnly && request.Params.Choice != "deny") {
			return ErrHermesDesktopForbidden
		}
	}
	scope.pending[string(request.ID)] = hermesDesktopPendingRPC{request.Method, request.Params.SessionID}
	return nil
}

func (scope *hermesDesktopRPCScope) observe(frame []byte) ([]byte, error) {
	var packet map[string]json.RawMessage
	if json.Unmarshal(frame, &packet) != nil {
		return nil, ErrHermesDesktopUpstream
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if string(packet["method"]) == `"event"` {
		return scope.projectApprovalEvent(packet)
	}
	request, found := scope.pending[string(packet["id"])]
	if !found {
		return frame, nil
	}
	delete(scope.pending, string(packet["id"]))
	if len(packet["error"]) > 0 {
		if request.method == "setup.status" || request.method == "setup.runtime_check" || request.method == "approval.pending" || request.method == "approval.received" {
			// These upstream handlers stringify auth/approval exceptions. Keep
			// the real failure, not the provider's raw exception or credential.
			packet["error"] = json.RawMessage(`{"code":-32000,"message":"Runtime readiness or approval check failed"}`)
			return json.Marshal(packet)
		}
		return frame, nil
	}
	var result struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(packet["result"], &result)
	if request.method == "session.create" || request.method == "session.resume" {
		if !hermesDesktopSessionID.MatchString(result.SessionID) || len(scope.live) >= 512 {
			return nil, ErrHermesDesktopUpstream
		}
		scope.live[result.SessionID] = true
	}
	if request.method == "session.close" {
		delete(scope.live, request.sessionID)
		delete(scope.approvals, request.sessionID)
	}
	if request.method == "model.options" {
		projected, err := hermesDesktopProjectHTTP("/model/options", packet["result"])
		if err != nil {
			return nil, err
		}
		packet["result"] = projected
		return json.Marshal(packet)
	}
	if request.method == "setup.status" || request.method == "setup.runtime_check" || request.method == "approval.received" {
		projected, err := hermesDesktopProjectCheck(request.method, packet["result"])
		if err != nil {
			return nil, err
		}
		packet["result"] = projected
		return json.Marshal(packet)
	}
	var object map[string]json.RawMessage
	if request.method == "approval.pending" || request.method == "session.events.since" || request.method == "session.create" || request.method == "session.resume" || request.method == "session.activate" {
		if json.Unmarshal(packet["result"], &object) != nil || object == nil {
			return nil, ErrHermesDesktopUpstream
		}
		if request.method == "approval.pending" {
			var approvals []json.RawMessage
			if json.Unmarshal(object["approvals"], &approvals) != nil || len(approvals) > 256 {
				return nil, ErrHermesDesktopUpstream
			}
			projected := make([]json.RawMessage, 0, len(approvals))
			for _, approval := range approvals {
				safe, err := scope.projectApproval(request.sessionID, approval, false)
				if err != nil {
					return nil, err
				}
				projected = append(projected, safe)
			}
			body, _ := json.Marshal(projected)
			object = map[string]json.RawMessage{"approvals": body}
		}
		if raw, ok := object["pending_approval"]; ok && string(raw) != "null" {
			sid := result.SessionID
			if sid == "" {
				sid = request.sessionID
			}
			safe, err := scope.projectApproval(sid, raw, false)
			if err != nil {
				return nil, err
			}
			object["pending_approval"] = safe
		}
		if request.method == "session.events.since" && len(object["events"]) > 0 {
			var events []map[string]json.RawMessage
			if json.Unmarshal(object["events"], &events) != nil {
				return nil, ErrHermesDesktopUpstream
			}
			projected := make([]json.RawMessage, 0, len(events))
			for _, event := range events {
				// event_replay.events_since returns the bare frame.params,
				// not a JSON-RPC notification envelope. Preserve that shape
				// for the stock client's dispatchIfNewer/seq watermark logic.
				var sid string
				if json.Unmarshal(event["session_id"], &sid) != nil || sid != request.sessionID {
					return nil, ErrHermesDesktopUpstream
				}
				safe, err := scope.projectApprovalEventParams(event)
				if err != nil {
					return nil, err
				}
				projected = append(projected, safe)
			}
			object["events"], _ = json.Marshal(projected)
		}
		packet["result"], _ = json.Marshal(object)
		return json.Marshal(packet)
	}
	return frame, nil
}

func hermesDesktopProjectCheck(method string, raw json.RawMessage) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, ErrHermesDesktopUpstream
	}
	key := "ok"
	if method == "setup.status" {
		key = "provider_configured"
	} else if method == "approval.received" {
		key = "acknowledged"
	}
	var value bool
	if string(object[key]) != "true" && string(object[key]) != "false" {
		return nil, ErrHermesDesktopUpstream
	}
	_ = json.Unmarshal(object[key], &value)
	// Keep the Runtime's response contract intact. The websocket layer applies
	// the instance credential redactor after this validation, so readiness and
	// approval metadata are not silently replaced by a smaller local schema.
	return json.Marshal(object)
}

// Callers hold scope.mu. approval.pending in the pinned Runtime returns raw
// queue data without _redact_approval_command. Never echo its command/details
// or permit blind approval; the user must deny and request a new live prompt.
func (scope *hermesDesktopRPCScope) projectApproval(sid string, raw json.RawMessage, denyOnly bool) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	var requestID string
	if !hermesDesktopSessionID.MatchString(sid) || json.Unmarshal(raw, &object) != nil || object == nil || json.Unmarshal(object["request_id"], &requestID) != nil || !hermesDesktopSessionID.MatchString(requestID) {
		return nil, ErrHermesDesktopUpstream
	}
	count := 0
	for _, requests := range scope.approvals {
		count += len(requests)
	}
	if _, exists := scope.approvals[sid][requestID]; !exists && count >= 1024 {
		return nil, ErrHermesDesktopUpstream
	}
	if scope.approvals[sid] == nil {
		scope.approvals[sid] = map[string]bool{}
	}
	var command string
	if !denyOnly && (json.Unmarshal(object["command"], &command) != nil || strings.TrimSpace(command) == "") {
		// A malformed live/resume payload must never offer blind approval.
		denyOnly = true
	}
	allowedChoices := []string{"once", "session", "always", "deny"}
	if choices, exists := object["choices"]; exists && !denyOnly {
		var values []string
		if json.Unmarshal(choices, &values) != nil {
			return nil, ErrHermesDesktopUpstream
		}
		allowedChoices = allowedChoices[:0]
		for _, choice := range values {
			if slices.Contains([]string{"once", "session", "always", "deny"}, choice) && !slices.Contains(allowedChoices, choice) {
				allowedChoices = append(allowedChoices, choice)
			}
		}
		if len(allowedChoices) == 0 || !slices.Contains(allowedChoices, "deny") {
			allowedChoices = []string{"deny"}
		}
	}
	// Once raw replay is deny-only, another event for the same request cannot
	// re-enable it. A new approval must have a new server-generated request ID.
	denyOnly = denyOnly || scope.approvals[sid][requestID]
	scope.approvals[sid][requestID] = denyOnly
	safe := object
	if !denyOnly {
		safe["choices"], _ = json.Marshal(allowedChoices)
		safe["allow_permanent"] = json.RawMessage(strconv.FormatBool(slices.Contains(allowedChoices, "always")))
		safe["allow_session"] = json.RawMessage(strconv.FormatBool(slices.Contains(allowedChoices, "session")))
	}
	if denyOnly {
		safe["choices"] = json.RawMessage(`["deny"]`)
		safe["command"] = json.RawMessage(`"Command hidden: this Runtime did not provide safe approval details."`)
		safe["description"] = json.RawMessage(`"Deny this request and retry to receive a new live approval prompt."`)
		safe["allow_permanent"], safe["allow_session"] = json.RawMessage("false"), json.RawMessage("false")
	}
	return json.Marshal(safe)
}

func (scope *hermesDesktopRPCScope) projectApprovalEvent(packet map[string]json.RawMessage) ([]byte, error) {
	var params map[string]json.RawMessage
	if json.Unmarshal(packet["params"], &params) != nil {
		return json.Marshal(packet)
	}
	safe, err := scope.projectApprovalEventParams(params)
	if err != nil {
		return nil, err
	}
	packet["params"] = safe
	return json.Marshal(packet)
}

func (scope *hermesDesktopRPCScope) projectApprovalEventParams(params map[string]json.RawMessage) ([]byte, error) {
	if string(params["type"]) != `"approval.request"` {
		return json.Marshal(params)
	}
	var sid string
	_ = json.Unmarshal(params["session_id"], &sid)
	safe, err := scope.projectApproval(sid, params["payload"], false)
	if err != nil {
		return nil, err
	}
	params["payload"] = safe
	return json.Marshal(params)
}
