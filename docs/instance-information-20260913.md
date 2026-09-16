# Instance list information release — 2026-09-13

## Changes
- Replace TEAM column with INFORMATION (ID, last online, error summary/hover).
- Move compact team link beneath creation time.
- Search numeric ID alongside existing text fields; `#ID` is exact ID search.
- Preserve query, filters and page in URL; detail return carries a validated local return path.
- Reuse Lite binding last_health_at and Pro agent last_heartbeat_at; absent history stays unknown. No schema migration. These are retained observations, not a complete historical uptime ledger.
- Sanitize common credential patterns in list error messages. Existing lifecycle and Lite-only selection remain unchanged.

## Validation
- Backend `go test ./...` passed.
- Frontend production build passed (local Node 22.11 produced Vite compatibility warning; image uses Node 24).
- Exact image startup/version check passed against isolated local MySQL.
- Local real API fixtures: exact ID, numeric/text matching, agent last-online timestamp and error redaction passed. No server instances created.
- Headless Chrome mocked-data checks: information/team placement, full error hover, browser back and refresh preserving page 2 and combined filters passed. Screenshot `.tmp/information-list.png`.
- Real model conversations and production were not involved.

## Image and deployment result
Image: `10.130.14.23:5000/clawmanager-hxc-app:instance-information-20260913-94487ab`

Digest: `sha256:01d49fe3fe1768960179f33bab723bf451942f1b49e1bc67f15f05f0489dcc37`

Pushed successfully. Requested `/home/hxc/north/clawmanager-apply.sh` was run with tenant `-hxc`, port `32443`. Existing four Runtime specs were retained in the tenant manifest to prevent rolling Hermes back to the old default. Release snapshots and apply log: `/home/hxc/north/release-instance-information-20260913`.

Deployment blocked by FailedScheduling: one node exceeded pod capacity, node1 was unreachable/NotReady. New App and Gateway never became runnable. Stopped the apply script and restored both App/Gateway image references to `runtime-compat-batch-20260911-r5-94487ab`; both rollouts and version check passed. Hermes remained 1/1. No node repair, unrelated Pod deletion, database or workspace deletion performed.

The feature is NOT live on 32443. Retry deployment only after cluster scheduling capacity is available. Full real-environment acceptance remains pending.
