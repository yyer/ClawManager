package services

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

var hermesDesktopSessionID = regexp.MustCompile(`^[A-Za-z0-9_:-]{1,160}$`)
var hermesDesktopAPIPath = regexp.MustCompile(`^/[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*$`)
var hermesDesktopQueryKey = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var hermesDesktopProfileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var hermesDesktopForbiddenQueryKeys = map[string]bool{"connectionid": true}
var hermesDesktopWorkspacePath = regexp.MustCompile(`^(?:\.|[A-Za-z0-9][A-Za-z0-9._/-]{0,511})$`)
var hermesDesktopRPCMethod = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)
var hermesDesktopRPCKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)
var hermesDesktopSensitiveRPCMethods = []string{"shell.", "cli.", "desktop.", "computer.", "browser.", "terminal.", "tools.call", "tool.call"}

func hermesDesktopReasoningAllowed(value string) bool {
	switch value {
	case "none", "minimal", "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

func hermesDesktopHTTPAllowed(method, path string, q url.Values, workspace ...string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	if !hermesDesktopAPIPath.MatchString(path) || len(q) > 32 {
		return false
	}
	if path == "/auth" || strings.HasPrefix(path, "/auth/") {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for key, values := range q {
		if !hermesDesktopQueryKey.MatchString(key) || len(values) != 1 || len(values[0]) > 4096 {
			return false
		}
		if hermesDesktopForbiddenQueryKeys[strings.ToLower(key)] {
			return false
		}
		if strings.EqualFold(key, "connectionId") {
			return false
		}
		if key == "profile" || key == "recents_profile" {
			if !hermesDesktopProfileName.MatchString(values[0]) {
				return false
			}
		}
		if hermesDesktopRPCPathKey(key) {
			value := values[0]
			root := ""
			if len(workspace) > 0 {
				root = workspace[0]
			}
			if !hermesDesktopWorkspacePathAllowed(value, root) || regexp.MustCompile(`^[A-Za-z]:`).MatchString(value) {
				return false
			}
		}
	}
	return true
}

/*
Runtime JSON-RPC is intentionally not maintained as a method/field allowlist.
Hermes Desktop evolves its Runtime surface frequently; the security boundary
is the instance and its workspace, not a frozen list of UI methods.
*/
func hermesDesktopWorkspacePathAllowed(value, root string) bool {
	if value == "" || value == "." {
		return true
	}
	if strings.ContainsAny(value, "\\\x00") || len(value) > 4096 {
		return false
	}
	segments := strings.Split(strings.ReplaceAll(value, "\\", "/"), "/")
	for _, segment := range segments {
		if segment == ".." {
			return false
		}
	}
	if strings.HasPrefix(value, "/") {
		if root == "" {
			return false
		}
		clean := path.Clean(value)
		base := path.Clean(root)
		return clean == base || strings.HasPrefix(clean, base+"/")
	}
	return hermesDesktopWorkspacePath.MatchString(value)
}

func hermesDesktopRPCMethodAllowed(method string) bool {
	if method == "gateway.ping" {
		return true
	}
	if !hermesDesktopRPCMethod.MatchString(method) {
		return false
	}
	for _, prefix := range hermesDesktopSensitiveRPCMethods {
		if method == prefix || strings.HasPrefix(method, prefix) {
			return false
		}
	}
	return true
}

func hermesDesktopRPCPathKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "cwd", "path", "directory", "dir", "folder", "folders", "file", "files", "primary_path", "workspace", "workspace_path", "root", "root_path", "repo_path", "project_path", "file_path", "filename":
		return true
	default:
		return false
	}
}

func hermesDesktopValidateRPCValue(key string, raw json.RawMessage, root string, depth int) bool {
	if depth > 8 || len(raw) > 5<<20 {
		return false
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch item := value.(type) {
	case string:
		if len(item) > 5<<20 {
			return false
		}
		if key == "profile" && !hermesDesktopProfileName.MatchString(item) {
			return false
		}
		if hermesDesktopRPCPathKey(key) && !hermesDesktopWorkspacePathAllowed(item, root) {
			return false
		}
	case []any:
		if len(item) > 1024 {
			return false
		}
		for _, child := range item {
			encoded, _ := json.Marshal(child)
			if !hermesDesktopValidateRPCValue(key, encoded, root, depth+1) {
				return false
			}
		}
	case map[string]any:
		if len(item) > 256 {
			return false
		}
		for childKey, child := range item {
			if !hermesDesktopRPCKey.MatchString(childKey) {
				return false
			}
			encoded, _ := json.Marshal(child)
			if !hermesDesktopValidateRPCValue(childKey, encoded, root, depth+1) {
				return false
			}
		}
	}
	return true
}

func hermesDesktopHTTPBodyAllowed(body []byte, root string) bool {
	if len(body) == 0 {
		return true
	}
	return hermesDesktopValidateRPCValue("", body, root, 0)
}

func hermesDesktopFilterRPCAtWorkspace(frame []byte, workspaceRoot string) ([]byte, error) {
	var packet struct {
		JSONRPC string                     `json:"jsonrpc"`
		ID      json.RawMessage            `json:"id"`
		Method  string                     `json:"method"`
		Params  map[string]json.RawMessage `json:"params"`
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&packet) != nil || packet.JSONRPC != "2.0" || len(packet.ID) == 0 || len(packet.ID) > 256 {
		return nil, ErrHermesDesktopForbidden
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, ErrHermesDesktopForbidden
	}
	// The shared Desktop client calls gateway.ping while the pinned server
	// registers ping. Normalize this transport-only alias at the boundary.
	if packet.Method == "gateway.ping" {
		packet.Method = "ping"
	}
	if !hermesDesktopRPCMethodAllowed(packet.Method) {
		return nil, ErrHermesDesktopForbidden
	}
	if packet.Params == nil {
		packet.Params = map[string]json.RawMessage{}
	}
	if len(packet.Params) > 128 {
		return nil, ErrHermesDesktopForbidden
	}
	for key, value := range packet.Params {
		if !hermesDesktopRPCKey.MatchString(key) || key == "connectionId" || key == "connection_id" || !hermesDesktopValidateRPCValue(key, value, workspaceRoot, 0) {
			return nil, ErrHermesDesktopForbidden
		}
	}
	if raw, ok := packet.Params["session_id"]; ok {
		var value string
		if json.Unmarshal(raw, &value) != nil || !hermesDesktopSessionID.MatchString(value) {
			return nil, ErrHermesDesktopForbidden
		}
	}
	if raw, ok := packet.Params["source"]; ok {
		var source string
		if json.Unmarshal(raw, &source) != nil || source != "web" && source != "desktop" {
			return nil, ErrHermesDesktopForbidden
		}
	}
	if strings.HasPrefix(packet.Method, "profiles.") {
		for _, key := range []string{"name", "clone_from"} {
			if raw, ok := packet.Params[key]; ok && string(raw) != "null" {
				var name string
				if json.Unmarshal(raw, &name) != nil || !hermesDesktopProfileName.MatchString(name) {
					return nil, ErrHermesDesktopForbidden
				}
			}
		}
	}
	if slices.Contains([]string{"session.activate", "session.usage", "session.close", "session.status", "session.history", "session.interrupt", "session.events.since", "prompt.submit", "approval.respond", "approval.pending", "approval.received", "clarify.respond"}, packet.Method) {
		if _, ok := packet.Params["session_id"]; !ok {
			return nil, ErrHermesDesktopForbidden
		}
	}
	// Method-specific Runtime validation remains in Hermes. CM only applies
	// generic JSON bounds, native-host method isolation, and workspace scope.
	if packet.Method == "session.create" || packet.Method == "session.resume" {
		if packet.Params == nil {
			packet.Params = map[string]json.RawMessage{}
		}
		// Upstream automatically adds native desktop_ui tools for source=desktop.
		// A browser must use the web platform even when reusing Desktop widgets.
		packet.Params["source"] = json.RawMessage(`"web"`)
		// The owning CM instance already selects the isolated Runtime home. Named
		// profiles are labels inside that same home; cwd/path values are checked
		// against the instance workspace before this frame reaches Runtime.
	}
	return json.Marshal(packet)
}

func hermesDesktopFilterRPC(frame []byte) ([]byte, error) {
	return hermesDesktopFilterRPCAtWorkspace(frame, "")
}

func hermesDesktopSensitiveResponseKey(key string) bool {
	compact := strings.ReplaceAll(strings.ToLower(strings.ReplaceAll(key, "-", "_")), "_", "")
	return compact == "password" || compact == "secret" || compact == "credential" || compact == "cookie" || compact == "authorization" || compact == "apikey" || compact == "accesstoken" || compact == "refreshtoken" || compact == "sessiontoken" || compact == "wsticket" || compact == "token"
}

func hermesDesktopSanitize(body []byte, password string, cookies []*http.Cookie, extraSecrets ...string) ([]byte, error) {
	secrets := append([]string{password}, extraSecrets...)
	for _, cookie := range cookies {
		secrets = append(secrets, cookie.Value)
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil, ErrHermesDesktopUpstream
	}
	var clean func(any) any
	clean = func(v any) any {
		switch item := v.(type) {
		case map[string]any:
			for key, child := range item {
				if hermesDesktopSensitiveResponseKey(key) {
					if _, ok := child.(string); ok {
						item[key] = "[redacted]"
					} else {
						item[key] = clean(child)
					}
					continue
				}
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
