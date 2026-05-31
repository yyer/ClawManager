#!/usr/bin/env bash
# Method-C 入口：把 pod-harness.mjs + method-a 的 cases 推进 pod，在 pod 内 node 跑
# 用 pod 上 install_skill 真部署的 ClawAegis 当被测对象。
#
# 用法:
#   bash run.sh                 # 跑全部 case
#   bash run.sh memory_guard    # 按子串过滤
#
# env:
#   METHOD_C_POD=clawreef-9-test10
#   METHOD_C_POD_NS=clawreef-user-1
#   METHOD_C_REMOTE_DIR=/usr/local/lib/node_modules/openclaw/method-c-test
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
POD="${METHOD_C_POD:-clawreef-9-test10}"
NS="${METHOD_C_POD_NS:-clawreef-user-1}"
REMOTE_DIR="${METHOD_C_REMOTE_DIR:-/usr/local/lib/node_modules/openclaw/method-c-test}"

# === sanity ===
need() { command -v "$1" >/dev/null || { echo "缺命令：$1" >&2; exit 2; }; }
need kubectl
need tar

phase=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "$phase" != "Running" ]]; then
  echo "ERROR: pod $NS/$POD 不是 Running (实际=$phase)" >&2
  echo "  先 bash ClawManager/tests/method-b/run.sh （它会自动起 instance）或手动 start" >&2
  exit 2
fi

# === pod 上 ClawAegis 必须有完整 .ts src（method-c 走 .ts 路径，因为 .js 滞后）===
if ! kubectl -n "$NS" exec "$POD" -- test -f /config/.openclaw/extensions/claw-aegis/src/handlers.ts 2>/dev/null; then
  echo "ERROR: pod 上 /config/.openclaw/extensions/claw-aegis/src/handlers.ts 不存在" >&2
  echo "  确认 instance 至少 dispatch 过一次（install_skill 把 ClawAegis 落地）" >&2
  exit 2
fi

# === tsx loader 必须在 pod 里能 reach ===
TSX="/usr/local/lib/node_modules/openclaw/node_modules/.bin/tsx"
if ! kubectl -n "$NS" exec "$POD" -- test -x "$TSX" 2>/dev/null; then
  echo "ERROR: pod 上 tsx 不存在 ($TSX)" >&2
  exit 2
fi

# === 推 harness + cases 进 pod ===
echo "[method-c] 推 harness + cases 进 pod..."
kubectl -n "$NS" exec "$POD" -- mkdir -p "$REMOTE_DIR/cases"
tar -C "$HERE" -czhf - pod-harness.mjs cases/ | \
  kubectl -n "$NS" exec -i "$POD" -- tar -xzf - -C "$REMOTE_DIR"

# === 准备 .ts-only ClawAegis 副本 ===
# pod 上 install_skill 同时把 .ts 和 .js 都落地了，但 .js 全是 stale 编译产物
# （rules.ts 2966 行 vs rules.js 2274、config.ts 605 vs config.js 509、
# handlers.ts 1931 vs handlers.js 1517）。openclaw 实际 load .ts，但 tsx 默认
# 按字面 import "./xxx.js" 解析，会把过时 .js 拉进来 → Frankenstein 状态。
# 修法：复制一份到 /tmp 然后删掉 .js，强制 tsx 走 .ts。
AEGIS_COPY=/tmp/method-c-aegis
kubectl -n "$NS" exec "$POD" -- sh -c "
rm -rf $AEGIS_COPY 2>/dev/null
mkdir -p $AEGIS_COPY
cp -r /config/.openclaw/extensions/claw-aegis/. $AEGIS_COPY/
find $AEGIS_COPY/src -name '*.js' -delete
"

# === 跑 ===
echo "[method-c] 跑 (pod node $(kubectl -n "$NS" exec "$POD" -- node --version), via tsx, .ts-only copy)"
echo
kubectl -n "$NS" exec "$POD" -- env METHOD_C_AEGIS_PATH=$AEGIS_COPY "$TSX" "$REMOTE_DIR/pod-harness.mjs" "$@"
