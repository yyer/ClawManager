#!/usr/bin/env bash
# Method-A test runner — 编译 ClawAegis .ts → 跑 harness.mjs。
# 无需 minikube / openclaw / fake-llm。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
AEGIS_SRC="$REPO_ROOT/ClawAegis"
TSC="$REPO_ROOT/ClawManager/frontend/node_modules/.bin/tsc"
BUILD="${AEGIS_BUILD_DIR:-/tmp/aegis-method-a-build}"

if [[ ! -d "$AEGIS_SRC/src" ]]; then
  echo "ClawAegis src 不存在: $AEGIS_SRC/src" >&2
  exit 2
fi
if [[ ! -x "$TSC" ]]; then
  echo "找不到 tsc: $TSC （需要 ClawManager/frontend 已经 npm install 过）" >&2
  exit 2
fi

rm -rf "$BUILD"
mkdir -p "$BUILD"

# tsc 的 type-check 会报缺 @types/node，但带 --skipLibCheck + 没 @types/node 的话
# 它会用更宽松的 emit 路径。我们只要 emit，错误不挡 emit（无 --noEmitOnError）。
cd "$AEGIS_SRC"
"$TSC" \
  --outDir "$BUILD" \
  --target ES2022 --module NodeNext --moduleResolution NodeNext \
  --rootDir . \
  --skipLibCheck \
  --typeRoots /tmp/empty-typeroots \
  src/handlers.ts src/config.ts src/state.ts src/rules.ts \
  src/security-strategies.ts src/types.ts src/encoding-guard.ts \
  src/command-obfuscation.ts src/scan-service.ts src/scan-worker.ts \
  runtime-api.ts > /tmp/aegis-method-a-tsc.log 2>&1 || true

# 写一个 ESM package.json 让 .mjs/.js 都按 ESM 解析
cat > "$BUILD/package.json" <<'EOF'
{ "type": "module" }
EOF

# 校验关键产物
for f in src/handlers.js src/config.js src/security-strategies.js src/rules.js src/state.js; do
  if [[ ! -f "$BUILD/$f" ]]; then
    echo "编译产物缺失: $f" >&2
    echo "--- tsc 日志 (tail 30) ---" >&2
    tail -30 /tmp/aegis-method-a-tsc.log >&2
    exit 2
  fi
done

# 跑 harness（cases 通过 env 传 build 路径）
AEGIS_BUILD_DIR="$BUILD" node "$HERE/harness.mjs" "$@"
