# Hermes Lite Web Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the approved Hermes Lite Desktop Web, IEI, model, bot, project, and recent-log flows while preserving per-instance authentication, workspace isolation, validation, and redaction.

**Architecture:** The ClawManager Bridge and Hermes Desktop BFF will use structural API validation instead of a feature-name allowlist, while retaining instance-scoped sessions, bounded inputs, and secret redaction. IEI Lite access will activate the existing Desktop Web session and set the instance cookie. The Lite Runtime policy will permit the upstream profile/project RPCs only with strict same-instance profile and workspace constraints.

**Tech Stack:** Go/Gin backend, TypeScript/Vitest-style Node tests, Python unittest policy tests, Docker/Kubernetes deployment.

**Spec:** `docs/superpowers/specs/2026-09-10-hermes-lite-web-capabilities-design.md`

## Global Constraints

- Keep all requests bound to the authenticated instance; no external `profile` or `connectionId` routing.
- Accept only normalized `/api/...` paths, bounded query/body sizes, and single-valued query keys.
- Keep existing Hermes Desktop session authentication, Runtime compatibility checks, and secret redaction.
- Project paths are the current instance workspace root or descendants only; reject absolute paths, traversal, and escapes.
- Keep the legacy Hermes TUI/Dashboard removed.
- Preserve existing user changes in `deployments/k8s/sites/nine-node-production/20-clawmanager-production.yaml`, its README, and `.codex-tmp/`.

---

### Task 1: Replace feature-name API allowlists and enable Recent Logs

**Files:**
- Modify: `frontend/hermes-desktop-web/src/bridge.ts`
- Test: `frontend/hermes-desktop-web/test/bridge.test.ts`
- Modify: `backend/internal/services/hermes_desktop_policy.go`
- Test: `backend/internal/services/hermes_desktop_renderer_test.go` or a focused policy test file in the same package
- Modify only if required for response handling: `backend/internal/services/hermes_desktop_renderer.go`

**Interfaces:**
- `validateApiRequest(request: ApiRequest): string` accepts any structurally valid `/api/...` Runtime route and retains method/body/query safety checks.
- `hermesDesktopHTTPAllowed(method, path, q) bool` performs structural validation without a static endpoint list.
- `/api/logs` is proxied through the existing `desktopRead` path and existing redaction pipeline.

- [ ] **Step 1: Write failing Bridge tests.** Add cases proving `/api/logs?file=agent&level=ERROR&lines=200&component=all&search=route` and an arbitrary valid Runtime endpoint are accepted, while encoded paths, duplicate keys, oversized values, invalid methods, and `profile=../../outside` remain rejected.
- [ ] **Step 2: Run the focused Bridge test and verify RED.** Run the renderer test from `frontend/hermes-desktop-web` (or the repository’s configured equivalent). The new acceptance assertions must fail because `/api/logs` is currently not in `READ_QUERIES` and arbitrary routes are rejected.
- [ ] **Step 3: Write failing Go policy tests.** Add assertions that `GET /logs` with the five documented query keys and a valid arbitrary path pass, while malformed path/query inputs fail.
- [ ] **Step 4: Run the focused Go test and verify RED.** Run `go test ./internal/services -run 'HermesDesktop.*(Policy|HTTP|Logs)' -count=1` from `backend`; confirm the new assertions fail for the current allowlist.
- [ ] **Step 5: Implement structural validation.** Replace feature-prefix dispatch in the TypeScript bridge with normalized API-path validation. In Go, accept the five HTTP methods for any normalized path matching `hermesDesktopAPIPath`, bound query count/value length, reject duplicate query values, and preserve exact config-envelope validation in `ProxyAPIRequest`.
- [ ] **Step 6: Preserve profile/workspace safety.** Validate `profile` query values against the instance-local profile-name grammar and reject `connectionId`; do not forward a browser-supplied external connection selector. Keep existing session/config projections and redaction where they protect sensitive fields.
- [ ] **Step 7: Run focused tests GREEN.** Re-run the Bridge and Go tests, then run the existing Bridge and Hermes Desktop service/renderer suites.
- [ ] **Step 8: Commit.** Commit only Task 1 files with `feat: allow safe Hermes Lite runtime APIs`.

### Task 2: Make IEI Hermes Lite access activate Desktop Web

**Files:**
- Modify: `backend/internal/handlers/iei_system_handler.go`
- Test: `backend/internal/handlers/iei_system_handler_test.go`
- Modify wiring only where required: the handler construction in the backend main/router setup

**Interfaces:**
- Add an injectable owner activator matching `HermesDesktopService.Activate(context.Context, int, int) (*HermesDesktopDescriptor, string, error)`.
- `GenerateInstanceAccess` keeps the existing generic proxy path and selects the Desktop Web path for Hermes Lite gateway instances.

- [ ] **Step 1: Write a fake activator and failing IEI test.** Add a test for an owned running Hermes Lite instance whose proxy URL is empty; the handler must return a renderer URL containing `/hermes-desktop-web/?instance_id=42`, set the scoped Desktop cookie, and preserve the access expiry. Add a regression assertion that a non-Lite instance still uses the existing proxy token response.
- [ ] **Step 2: Run the focused handler test and verify RED.** Run `go test ./internal/handlers -run 'IEI.*(Access|Hermes)' -count=1`; the Lite case must fail with the current `Unable to generate access URL` response.
- [ ] **Step 3: Implement the injected activation path.** Add a setter/field, wire the real `HermesDesktopService` from the application setup, call owner activation after existing IEI owner/status checks, set `HermesDesktopCookieName(instanceID)` with path `HermesDesktopBase(instanceID)+"/"`, and return the renderer URL/expiry in the IEI response shape.
- [ ] **Step 4: Run handler and service tests GREEN.** Run the focused test plus `go test ./internal/handlers ./internal/services -run 'HermesDesktop|IEI' -count=1`.
- [ ] **Step 5: Commit.** Commit Task 2 as `fix: activate Hermes Lite Desktop Web from IEI`.

### Task 3: Restore model, Bots, and workspace-scoped Project UI flows

**Files:**
- Modify: `frontend/hermes-desktop-web/.upstream/source/apps/desktop/src/app/session/hooks/use-model-controls.ts` through the existing Web adaptation mechanism, or add the smallest Web-only adaptation in `frontend/hermes-desktop-web/scripts/web-adaptations.mjs`
- Test: the relevant renderer/adaptation tests under `frontend/hermes-desktop-web/src` or `frontend/hermes-desktop-web/test`
- Modify: `backend/internal/services/hermes_desktop_policy.go` for RPC fields/profile grammar/session title/list fields
- Test: `backend/internal/services/hermes_desktop_renderer_test.go`
- Modify: `frontend/hermes-desktop-web/scripts/web-adaptations.mjs` to remove the project unavailable replacement and retain workspace-only directory behavior
- Test: adaptation/build tests covering Bot Mode and Project Dialog behavior

**Interfaces:**
- Model switch sends `config.set` with `key=model` and a `--session` value.
- Named Profile RPCs use a strict instance-local name and cannot pass `cwd` or arbitrary host paths.
- Project actions use workspace-root/relative paths only.

- [ ] **Step 1: Write failing model/RPC tests.** Assert Web model control emits `--session`; assert Go RPC filtering accepts the required `profiles.*`, `session.title`, and `session.list` fields but rejects invalid profile names, absolute `cwd`, and traversal paths.
- [ ] **Step 2: Run the focused tests and verify RED.** Run the relevant TypeScript test command and `go test ./internal/services -run 'HermesDesktop.*RPC' -count=1`; confirm current global model/profile denials fail the new assertions.
- [ ] **Step 3: Implement model scope.** Adapt the Web model control so the primary session does not request `--global`; keep the backend catalog/provider validation and Lite `--session` requirement.
- [ ] **Step 4: Implement same-instance Profile RPC policy.** Add the upstream profile methods and Bot session fields to both ClawManager policy and its RPC sanitizer; validate names, strings, lists, and asset sizes; strip/deny `cwd` except the workspace sentinel.
- [ ] **Step 5: Implement workspace-only Project adaptation.** Remove the unavailable ProjectDialog/refresh short-circuit, wire project API calls through the generic Bridge, and ensure path selection returns workspace root or a validated relative descendant only.
- [ ] **Step 6: Run renderer/backend tests GREEN.** Run the focused tests plus the existing renderer, Bridge, and adaptation suites.
- [ ] **Step 7: Commit.** Commit Task 3 as `feat: restore instance-scoped Desktop Web controls`.

### Task 4: Extend AgentsRuntime Lite policy for Profiles and Projects

**Files:**
- Modify: `D:/code/gitlab/agentsruntime/hermes/patches/hermes-agent/lite_non_native.py`
- Test: `D:/code/gitlab/agentsruntime/hermes/tests/test_lite_non_native.py`
- Modify only if the locked upstream interface requires a patch anchor: `D:/code/gitlab/agentsruntime/hermes/patches/hermes-agent/apply_lite_non_native.py`
- Update integrity metadata only through the repository’s documented release/check tooling after code tests pass.

**Interfaces:**
- `rpc_denial()` accepts the upstream Profile and Project methods for external Web transport with strict same-instance validation.
- Profile names use `^[a-z0-9][a-z0-9_-]{0,63}$`.
- Project path values are relative/sentinel values only; the process resolves them below `CLAWMANAGER_WORKSPACE_PATH`.

- [ ] **Step 1: Write failing Python policy tests.** Add accepted cases for `profiles.list/create/describe/configure/set_asset/get_asset`, `projects.list/get/create/update/add_folder/remove_folder/set_primary/archive/delete/set_active/for_cwd`, `mcp.catalog`, `session.title`, and named-profile session list/create. Add rejected cases for unknown RPCs, invalid profile names, absolute paths, `..`, oversized assets, and external transport attempts.
- [ ] **Step 2: Run the focused Python tests and verify RED.** Run `python -m unittest hermes.tests.test_lite_non_native.RPCPolicyTests -v` from the AgentsRuntime repository; current methods must be reported unsupported or invalid.
- [ ] **Step 3: Implement minimal policy additions.** Add exact method field sets, scalar/list/object type checks, profile-name validation, workspace path validation, and safe normalization. Keep native desktop tool denial and verified internal transport behavior unchanged.
- [ ] **Step 4: Run Python tests GREEN.** Run the focused class, then the complete `python -m unittest discover -s hermes/tests -p 'test_*.py'` suite.
- [ ] **Step 5: Run image/policy smoke tests.** Run the existing Lite non-native, Desktop RPC, and image smoke commands available in the repository; record any Docker dependency blocker rather than bypassing it.
- [ ] **Step 6: Commit AgentsRuntime changes.** Commit with `feat: support instance-scoped Lite profiles and projects`, update the project’s merge-rule/commit record only if the repository process requires it.

### Task 5: Build, deploy, and verify the test cluster

**Files/Artifacts:**
- No user production manifest edits; use a new immutable image tag and the existing test-cluster deployment mechanism.
- Preserve existing dirty files listed in Global Constraints.

- [ ] **Step 1: Run complete local verification.** Run ClawManager Go tests, frontend tests/build, AgentsRuntime Python tests/smokes, and `git diff --check` in both repositories.
- [ ] **Step 2: Build immutable images.** Build backend/frontend and the updated AgentsRuntime Lite image with a unique test tag; record image digests.
- [ ] **Step 3: Verify cluster access.** Check `kubectl config current-context`, API reachability, target namespace, and current Deployments before mutating anything. If the kind tunnel is unavailable, report the exact blocker and do not claim deployment.
- [ ] **Step 4: Update only the test namespace.** Apply the new image tags to `clawmanager-system` using the existing deployment tooling, wait for rollouts, and verify pod image IDs.
- [ ] **Step 5: Execute functional smoke checks.** Test Recent Logs, IEI Lite URL, model switch, Bot create/open, Project create at workspace root, and a rejected workspace escape; confirm the external Provider no-route error remains accurately reported.
- [ ] **Step 6: Record evidence and commit deployment metadata only if required.** Capture test commands, image digests, rollout status, and endpoint checks; do not stage unrelated user files.
