// Package aegis_assets embeds the OpenClaw security plugin sources as base
// zips. secplane builds a per-policy variant of each zip by injecting
// `user_config.json` and uploads via the existing skills/import channel —
// that's how secplane policy changes flow through to a running OpenClaw pod
// without inventing any new control-plane protocol.
//
// Despite the package name (kept for backward compat) it now holds bases
// for both ClawAegis and SecureClaw. If a third plugin lands, consider
// renaming to plugin_assets in a follow-up.
package aegis_assets

import _ "embed"

//go:embed claw-aegis-base.zip
var baseZip []byte

//go:embed secureclaw-base.zip
var secureClawBaseZip []byte

// BaseZip returns the raw bytes of the embedded ClawAegis source zip.
// Callers must not mutate the returned slice.
func BaseZip() []byte { return baseZip }

// SecureClawBaseZip returns the raw bytes of the embedded SecureClaw plugin
// source zip. Empty until task 11 fills in the real artifact via
// build-bundle.sh / deploy-secplane.sh; the secureclaw packager fails
// gracefully when the zip is empty.
func SecureClawBaseZip() []byte { return secureClawBaseZip }
