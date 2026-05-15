package aegis

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"clawreef/internal/secplane/aegis_assets"
)

// PackageSkill builds a fresh ClawAegis skill zip with the supplied user_config
// merged in, ready to be uploaded via the existing /api/v1/skills/import flow.
//
// The injection point is `claw-aegis/user_config.json` — the patched
// ClawAegis loader (see ClawAegis/src/config.ts) reads this file at startup
// and merges its contents on top of `api.pluginConfig`.
//
// Returns the zip bytes plus the JSON form of the user_config that was
// injected (useful for logging / dispatch result).
func PackageSkill(cfg UserConfig) ([]byte, []byte, error) {
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal user_config: %w", err)
	}

	src, err := zip.NewReader(bytes.NewReader(aegis_assets.BaseZip()), int64(len(aegis_assets.BaseZip())))
	if err != nil {
		return nil, nil, fmt.Errorf("open embedded base zip: %w", err)
	}

	var out bytes.Buffer
	zw := zip.NewWriter(&out)

	const target = "claw-aegis/user_config.json"
	wroteOverride := false
	for _, f := range src.File {
		// Drop any pre-existing user_config.json so the new one wins.
		if strings.EqualFold(f.Name, target) {
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
	{
		w, err := zw.CreateHeader(&zip.FileHeader{Name: target, Method: zip.Deflate})
		if err != nil {
			return nil, nil, fmt.Errorf("zip header %s: %w", target, err)
		}
		if _, err := w.Write(cfgJSON); err != nil {
			return nil, nil, fmt.Errorf("write %s: %w", target, err)
		}
		wroteOverride = true
	}
	_ = wroteOverride
	if err := zw.Close(); err != nil {
		return nil, nil, fmt.Errorf("close zip: %w", err)
	}
	return out.Bytes(), cfgJSON, nil
}
