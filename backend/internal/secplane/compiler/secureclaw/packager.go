package secureclaw

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"clawreef/internal/secplane/aegis_assets"
)

// PackageSkill rebuilds the SecureClaw plugin zip with the supplied
// user_config and (optionally) the 4 skill/configs/*.json overrides
// injected. Mirrors aegis's PackageSkill — same shape, different
// embedded base + target paths.
//
// Returns the zip bytes plus the JSON form of the user_config that was
// injected (useful for dispatch logs).
func PackageSkill(cfg UserConfig, skillConfigs map[string][]byte) ([]byte, []byte, error) {
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal user_config: %w", err)
	}

	baseBytes := aegis_assets.SecureClawBaseZip()
	if len(baseBytes) == 0 {
		return nil, nil, fmt.Errorf("secureclaw base zip not embedded (build pipeline missed it?)")
	}

	src, err := zip.NewReader(bytes.NewReader(baseBytes), int64(len(baseBytes)))
	if err != nil {
		return nil, nil, fmt.Errorf("open embedded secureclaw base zip: %w", err)
	}

	const userCfgTarget = "secureclaw/user_config.json"
	const skillCfgPrefix = "secureclaw/skill/configs/"

	// Build the set of zip entries we're going to overwrite (or add fresh).
	overrides := map[string][]byte{
		userCfgTarget: cfgJSON,
	}
	for name, payload := range skillConfigs {
		overrides[skillCfgPrefix+name+".json"] = payload
	}

	var out bytes.Buffer
	zw := zip.NewWriter(&out)

	for _, f := range src.File {
		// Skip any entry we're going to write fresh below.
		if _, replace := overrides[f.Name]; replace {
			continue
		}
		// Also drop case-insensitive matches for user_config.json (some
		// bases shipped it under a slightly different case earlier).
		if strings.EqualFold(f.Name, userCfgTarget) {
			continue
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate})
		if err != nil {
			return nil, nil, fmt.Errorf("zip header %s: %w", f.Name, err)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			rc.Close()
			return nil, nil, fmt.Errorf("copy zip entry %s: %w", f.Name, err)
		}
		rc.Close()
	}

	// Now write the overrides — user_config.json + 4 skill/configs/*.json.
	for path, payload := range overrides {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: path, Method: zip.Deflate})
		if err != nil {
			return nil, nil, fmt.Errorf("zip header %s: %w", path, err)
		}
		if _, err := w.Write(payload); err != nil {
			return nil, nil, fmt.Errorf("write %s: %w", path, err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, nil, fmt.Errorf("close zip: %w", err)
	}
	return out.Bytes(), cfgJSON, nil
}
