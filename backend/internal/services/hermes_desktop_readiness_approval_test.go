package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHermesDesktopRendererReadinessAndApprovalPolicy(t *testing.T) {
	for _, tc := range []struct {
		method string
		params map[string]any
	}{
		{"setup.status", map[string]any{"profile": "default", "future_field": true}},
		{"setup.runtime_check", map[string]any{"provider": "external", "api_key": "private"}},
		{"approval.respond", map[string]any{"session_id": "live", "request_id": "r", "choice": "always"}},
		{"sudo.respond", map[string]any{"session_id": "live", "request_id": "r", "password": "private"}},
		{"session.active_list", nil},
	} {
		if _, err := hermesDesktopFilterRPC(desktopRPCFrame(1, tc.method, tc.params)); err != nil {
			t.Errorf("runtime method %s was locally allowlisted: %v", tc.method, err)
		}
	}
	for _, method := range []string{"shell.exec", "desktop.respond", "terminal.start", "tools.call"} {
		if _, err := hermesDesktopFilterRPC(desktopRPCFrame(1, method, nil)); err == nil {
			t.Errorf("native host method %s was accepted", method)
		}
	}
}

func TestHermesDesktopRendererReadinessProjection(t *testing.T) {
	for _, tc := range []struct{ method, body, expected string }{
		{"setup.status", `{"provider_configured":true,"env":{"KEY":"PRIVATE"},"tools":["PRIVATE"]}`, `"provider_configured":true`},
		{"setup.status", `{"provider_configured":false,"error":"PRIVATE"}`, `"provider_configured":false`},
		{"setup.runtime_check", `{"ok":true,"provider":"managed","source":"PRIVATE","api_key":"PRIVATE"}`, `"ok":true`},
		{"setup.runtime_check", `{"ok":false,"error":"PRIVATE","command":"PRIVATE"}`, `"ok":false`},
		{"approval.received", `{"acknowledged":false,"debug":"PRIVATE"}`, `"acknowledged":false`},
		{"approval.received", `{"acknowledged":true,"debug":"PRIVATE"}`, `"acknowledged":true`},
	} {
		body, err := hermesDesktopProjectCheck(tc.method, []byte(tc.body))
		if err != nil || !strings.Contains(string(body), tc.expected) || !strings.Contains(string(body), "PRIVATE") {
			t.Fatalf("Runtime response shape was narrowed for %s: %s %v", tc.method, body, err)
		}
	}
	for _, body := range []string{`{}`, `{"ok":null}`, `{"ok":"true"}`, `{"ok":1}`, `[]`} {
		if _, err := hermesDesktopProjectCheck("setup.runtime_check", []byte(body)); err == nil {
			t.Fatalf("non-authoritative readiness accepted: %s", body)
		}
	}
	scope := newHermesDesktopRPCScope()
	if err := scope.admit(desktopRPCFrame(1, "setup.status", nil)); err != nil {
		t.Fatal(err)
	}
	body, err := scope.observe([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":5016,"message":"PRIVATE provider credential"}}`))
	if err != nil || strings.Contains(string(body), "PRIVATE") || !strings.Contains(string(body), `"error"`) {
		t.Fatal("failed readiness check exposed exception or became success")
	}
}

func TestHermesDesktopRendererApprovalScopeAndProjection(t *testing.T) {
	scope := newHermesDesktopRPCScope()
	for _, method := range []string{"approval.pending", "approval.received", "approval.respond"} {
		if !errors.Is(scope.admit(desktopRPCFrame(1, method, map[string]any{"session_id": "live-1", "request_id": "raw-1", "choice": "deny"})), errHermesDesktopUnboundSession) {
			t.Fatalf("unbound approval %s allowed", method)
		}
	}
	_ = scope.admit(desktopRPCFrame(1, "session.resume", map[string]any{"session_id": "stored-1"}))
	_, err := scope.observe([]byte(`{"jsonrpc":"2.0","id":1,"result":{"session_id":"live-1","pending_approval":{"request_id":"live-approval","command":"echo safe","description":"Command","choices":["once","session","always","deny"],"allow_permanent":true,"pattern_keys":["PRIVATE"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = scope.admit(desktopRPCFrame(2, "approval.pending", map[string]any{"session_id": "live-1"}))
	body, err := scope.observe([]byte(`{"jsonrpc":"2.0","id":2,"result":{"approvals":[{"request_id":"raw-1","command":"curl -H 'X-Api-Key: PRIVATE'","description":"PRIVATE","pattern_keys":["PRIVATE"],"choices":["once","always","deny"],"allow_permanent":true}],"debug":"PRIVATE"}}`))
	if err != nil || !strings.Contains(string(body), `"choices":["once","always","deny"]`) || !strings.Contains(string(body), `"allow_permanent":true`) {
		t.Fatalf("approval response shape was narrowed: %s %v", body, err)
	}
	for _, tc := range []struct{ sid, id, choice string }{
		{"live-1", "", "once"}, {"live-1", "unknown", "once"}, {"another", "raw-1", "deny"},
	} {
		if scope.admit(desktopRPCFrame(3, "approval.respond", map[string]any{"session_id": tc.sid, "request_id": tc.id, "choice": tc.choice})) == nil {
			t.Fatal("replay approval bypassed exact request/session boundary")
		}
	}
	if scope.admit(desktopRPCFrame(3, "approval.received", map[string]any{"session_id": "live-1", "request_id": "raw-1"})) != nil {
		t.Fatal("known request acknowledgement rejected")
	}
	body, err = scope.observe([]byte(`{"jsonrpc":"2.0","id":3,"result":{"acknowledged":false,"details":"PRIVATE"}}`))
	if err != nil || !strings.Contains(string(body), `"acknowledged":false`) || !strings.Contains(string(body), "PRIVATE") {
		t.Fatal("acknowledgement result was invented or not projected")
	}
	// A later event for the same Runtime request preserves the Runtime choices.
	body, err = scope.observe([]byte(`{"jsonrpc":"2.0","method":"event","params":{"type":"approval.request","session_id":"live-1","payload":{"request_id":"raw-1","command":"echo safe","choices":["once","deny"]}}}`))
	if err != nil || !strings.Contains(string(body), `"choices":["once","deny"]`) {
		t.Fatal("same pending request lost Runtime choices")
	}
	if scope.admit(desktopRPCFrame(4, "approval.respond", map[string]any{"session_id": "live-1", "request_id": "raw-1", "choice": "once"})) != nil {
		t.Fatal("same-ID Runtime approval was rejected")
	}
	_, _ = scope.observe([]byte(`{"jsonrpc":"2.0","id":4,"result":{"resolved":true}}`))
	body, err = scope.observe([]byte(`{"jsonrpc":"2.0","method":"event","params":{"type":"approval.request","session_id":"live-1","payload":{"request_id":"fresh-1","command":"echo safe","description":"Safe details","choices":["once","session","always","deny"],"pattern_keys":["PRIVATE"],"allow_permanent":true}}}`))
	if err != nil || !strings.Contains(string(body), `"choices":["once","session","always","deny"]`) {
		t.Fatalf("live approval shape was narrowed: %s %v", body, err)
	}
	for i, tc := range []struct{ id, choice string }{{"raw-1", "deny"}, {"fresh-1", "once"}, {"live-approval", "once"}} {
		if scope.admit(desktopRPCFrame(i+5, "approval.respond", map[string]any{"session_id": "live-1", "request_id": tc.id, "choice": tc.choice})) != nil {
			t.Fatal("safe exact approval rejected")
		}
	}
	_ = scope.admit(desktopRPCFrame(8, "session.close", map[string]any{"session_id": "live-1"}))
	_, _ = scope.observe([]byte(`{"jsonrpc":"2.0","id":8,"result":{"closed":true}}`))
	if len(scope.approvals) != 0 || scope.admit(desktopRPCFrame(9, "approval.pending", map[string]any{"session_id": "live-1"})) == nil {
		t.Fatal("closed session retained approval authority")
	}
}

func TestHermesDesktopRendererReadinessApprovalRealWebSocket(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/password-login":
			desktopTestLogin(t, w, r)
		case "/api/auth/ws-ticket":
			_, _ = w.Write([]byte(`{"ticket":"upstream-ticket"}`))
		case "/api/model/options":
			_, _ = w.Write([]byte(`{"provider":"managed","model":"m","providers":[{"slug":"managed","models":["m"],"authenticated":true},{"slug":"external","models":["x"],"authenticated":false}]}`))
		case "/api/ws":
			conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, Subprotocols: []string{hermesGatewayProtocol}}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				_, frame, err := conn.ReadMessage()
				if err != nil {
					return
				}
				var request struct {
					ID     json.RawMessage   `json:"id"`
					Method string            `json:"method"`
					Params map[string]string `json:"params"`
				}
				_ = json.Unmarshal(frame, &request)
				forwarded.Add(1)
				var result any
				switch request.Method {
				case "setup.status":
					result = map[string]any{"provider_configured": true, "secret": "PRIVATE"}
				case "setup.runtime_check":
					result = map[string]any{"ok": false, "error": "managed-Hermes-password upstream credential failure"}
				case "session.resume":
					result = map[string]any{"session_id": "live-1"}
				case "approval.pending":
					result = map[string]any{"approvals": []any{map[string]any{"request_id": "pending-1", "command": "echo safe", "description": "approval", "choices": []string{"once", "session", "always", "deny"}, "allow_permanent": true}}}
				case "approval.received":
					result = map[string]any{"acknowledged": request.Params["session_id"] == "live-1" && request.Params["request_id"] == "pending-1"}
				case "approval.respond":
					result = map[string]any{"resolved": 1}
				default:
					t.Errorf("unexpected upstream method %s", request.Method)
				}
				if conn.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}) != nil {
					return
				}
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	s := desktopFixture(t, upstream.URL)
	_, cookie, err := s.Activate(context.Background(), 45, 123)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Authenticate(context.Background(), cookie, 123)
	if err != nil {
		t.Fatal(err)
	}
	ticket, _, err := s.MintTicket(claims)
	if err != nil {
		t.Fatal(err)
	}
	ticketURL, _ := url.Parse(ticket)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ProxyWebSocket(r.Context(), claims, r.URL.Query().Get("ticket"), w, r) != nil {
			http.Error(w, "failed", 502)
		}
	}))
	defer proxy.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http")+"?ticket="+url.QueryEscape(ticketURL.Query().Get("ticket")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	id := 0
	roundtrip := func(method string, params map[string]any, expected string, failure bool) {
		t.Helper()
		id++
		if err := conn.WriteMessage(websocket.TextMessage, desktopRPCFrame(id, method, params)); err != nil {
			t.Fatal(err)
		}
		_, body, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		var response map[string]json.RawMessage
		_ = json.Unmarshal(body, &response)
		if (len(response["error"]) > 0) != failure || !strings.Contains(string(body), expected) || strings.Contains(string(body), "PRIVATE") {
			t.Fatalf("unexpected %s: %s", method, body)
		}
	}
	roundtrip("setup.status", nil, `"provider_configured":true`, false)
	roundtrip("setup.runtime_check", nil, `"ok":false`, false)
	roundtrip("setup.runtime_check", map[string]any{"provider": "managed"}, `"ok":false`, false)
	roundtrip("setup.runtime_check", map[string]any{"provider": "external"}, `"ok":false`, false)
	roundtrip("approval.pending", map[string]any{"session_id": "live-1"}, `"error"`, true)
	roundtrip("session.resume", map[string]any{"session_id": "stored-1"}, `"session_id":"live-1"`, false)
	roundtrip("approval.pending", map[string]any{"session_id": "live-1"}, `"choices":["once","session","always","deny"]`, false)
	roundtrip("approval.received", map[string]any{"session_id": "live-1", "request_id": "pending-1"}, `"acknowledged":true`, false)
	roundtrip("approval.respond", map[string]any{"session_id": "live-1", "request_id": "pending-1", "choice": "once"}, `"resolved":1`, false)
	roundtrip("approval.respond", map[string]any{"session_id": "live-1", "choice": "once"}, `"error"`, true)
	roundtrip("approval.respond", map[string]any{"session_id": "live-1", "request_id": "pending-1", "choice": "deny"}, `"resolved":1`, false)
	if forwarded.Load() != 9 {
		t.Fatalf("forbidden operations reached Runtime: %d", forwarded.Load())
	}
}

func TestHermesDesktopRendererApprovalBareEventReplay(t *testing.T) {
	scope := newHermesDesktopRPCScope()
	// Stock shared client requests event replay before it resumes a live ID.
	if err := scope.admit(desktopRPCFrame(1, "session.events.since", map[string]any{"session_id": "live-1", "last_seen": 4})); err != nil {
		t.Fatal(err)
	}
	body, err := scope.observe([]byte(`{"jsonrpc":"2.0","id":1,"result":{"events":[{"type":"approval.request","session_id":"live-1","seq":5,"payload":{"request_id":"replayed-1","command":"echo safe","choices":["once","session","always","deny"],"allow_permanent":true,"pattern_keys":["PRIVATE"]}},{"type":"assistant.delta","session_id":"live-1","seq":6,"payload":{"text":"hello"}}],"count":2,"latest_seq":6,"truncated":false,"epoch":"runtime-process-epoch"}}`))
	if err != nil || !strings.Contains(string(body), `"always"`) || strings.Contains(string(body), `"params"`) {
		t.Fatalf("bare replay bypassed projection or gained an envelope: %s %v", body, err)
	}
	var packet struct {
		Result struct {
			Events []struct {
				Type      string         `json:"type"`
				SessionID string         `json:"session_id"`
				Seq       int            `json:"seq"`
				Payload   map[string]any `json:"payload"`
			} `json:"events"`
			Count     int    `json:"count"`
			LatestSeq int    `json:"latest_seq"`
			Epoch     string `json:"epoch"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &packet) != nil || len(packet.Result.Events) != 2 || packet.Result.Count != 2 || packet.Result.LatestSeq != 6 || packet.Result.Epoch != "runtime-process-epoch" || packet.Result.Events[0].Type != "approval.request" || packet.Result.Events[0].SessionID != "live-1" || packet.Result.Events[0].Seq != 5 || packet.Result.Events[1].Payload["text"] != "hello" {
		t.Fatal("projection damaged actual Runtime replay shape/watermarks")
	}
	if scope.admit(desktopRPCFrame(2, "approval.received", map[string]any{"session_id": "live-1", "request_id": "replayed-1"})) == nil {
		t.Fatal("historical replay granted a live binding")
	}
	_ = scope.admit(desktopRPCFrame(2, "session.resume", map[string]any{"session_id": "stored-1"}))
	if _, err := scope.observe([]byte(`{"jsonrpc":"2.0","id":2,"result":{"session_id":"live-1"}}`)); err != nil {
		t.Fatal(err)
	}
	if scope.admit(desktopRPCFrame(3, "approval.received", map[string]any{"session_id": "live-1", "request_id": "replayed-1"})) != nil {
		t.Fatal("actual bare replay did not register its exact approval ID")
	}
	_, _ = scope.observe([]byte(`{"jsonrpc":"2.0","id":3,"result":{"acknowledged":false}}`))
	// Pending and event replay preserve the Runtime's approval choices.
	_ = scope.admit(desktopRPCFrame(4, "approval.pending", map[string]any{"session_id": "live-1"}))
	_, err = scope.observe([]byte(`{"jsonrpc":"2.0","id":4,"result":{"approvals":[{"request_id":"replayed-1","command":"PRIVATE"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = scope.admit(desktopRPCFrame(5, "session.events.since", map[string]any{"session_id": "live-1", "last_seen": 0}))
	body, err = scope.observe([]byte(`{"jsonrpc":"2.0","id":5,"result":{"events":[{"type":"approval.request","session_id":"live-1","seq":5,"payload":{"request_id":"replayed-1","command":"echo safe","choices":["once","deny"]}}],"count":1,"latest_seq":6,"truncated":false}}`))
	if err != nil || !strings.Contains(string(body), `"choices":["once","deny"]`) || scope.admit(desktopRPCFrame(6, "approval.respond", map[string]any{"session_id": "live-1", "request_id": "replayed-1", "choice": "once"})) != nil {
		t.Fatal("historical event lost Runtime approval choices")
	}
	_, _ = scope.observe([]byte(`{"jsonrpc":"2.0","id":6,"result":{"resolved":true}}`))
	// Do not let an inconsistent upstream reply associate another session's
	// approval with this requested replay stream.
	_ = scope.admit(desktopRPCFrame(6, "session.events.since", map[string]any{"session_id": "live-1", "last_seen": 0}))
	if _, err := scope.observe([]byte(`{"jsonrpc":"2.0","id":6,"result":{"events":[{"type":"approval.request","session_id":"other-live","seq":1,"payload":{"request_id":"other-request","command":"echo other"}}]}}`)); err == nil {
		t.Fatal("cross-session event accepted in a replay response")
	}
	_ = scope.admit(desktopRPCFrame(7, "session.close", map[string]any{"session_id": "live-1"}))
	_, _ = scope.observe([]byte(`{"jsonrpc":"2.0","id":7,"result":{"closed":true}}`))
	if len(scope.approvals) != 0 || scope.admit(desktopRPCFrame(8, "approval.respond", map[string]any{"session_id": "live-1", "request_id": "replayed-1", "choice": "deny"})) == nil {
		t.Fatal("closed session retained authority from historical events")
	}
}

func TestHermesDesktopRendererApprovalCannotApproveMissingCommand(t *testing.T) {
	for _, raw := range []string{
		`{"request_id":"request-1"}`,
		`{"request_id":"request-1","command":null}`,
		`{"request_id":"request-1","command":"  \n\t"}`,
		`{"request_id":"request-1","command":{"private":"DO-NOT-EXPOSE"}}`,
	} {
		scope := newHermesDesktopRPCScope()
		scope.live["live-1"] = true
		body, err := scope.projectApproval("live-1", []byte(raw), false)
		if err != nil || !strings.Contains(string(body), `"choices":["deny"]`) || strings.Contains(string(body), "DO-NOT-EXPOSE") {
			t.Fatalf("invalid command offered approval: %s %v", body, err)
		}
		if scope.admit(desktopRPCFrame(1, "approval.respond", map[string]any{"session_id": "live-1", "request_id": "request-1", "choice": "once"})) == nil {
			t.Fatal("invalid command could be approved by bypassing UI")
		}
	}
}
