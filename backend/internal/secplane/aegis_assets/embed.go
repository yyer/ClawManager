// Package aegis_assets embeds the ClawAegis plugin source as a base zip.
// secplane builds a per-policy variant of this zip by injecting
// `user_config.json` and uploads it via ClawManager's existing skills/import
// channel — that's how secplane policy changes flow through to a running
// OpenClaw pod without inventing any new control-plane protocol.
package aegis_assets

import _ "embed"

//go:embed claw-aegis-base.zip
var baseZip []byte

// BaseZip returns the raw bytes of the embedded ClawAegis source zip. Callers
// must not mutate the returned slice.
func BaseZip() []byte { return baseZip }
