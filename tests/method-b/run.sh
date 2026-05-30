#!/usr/bin/env bash
# Method-B 真链路 e2e harness 入口。
# 用法：
#   bash run.sh                   # 跑全部 case
#   bash run.sh jailbreak         # 跑 name 含 substring 的 case
# 环境（可选 env 覆盖）：
#   METHOD_B_API=http://localhost:9002          # vite 代理 / 后端直访
#   METHOD_B_INSTANCE_ID=9                       # 目标 instance
#   METHOD_B_POD=clawreef-9-test10               # 实例 pod
#   METHOD_B_POD_NS=clawreef-user-1
#   METHOD_B_MYSQL_DEPLOY=deploy/mysql
#   METHOD_B_MYSQL_NS=clawreef-system
#   METHOD_B_MYSQL_PWD=123456
#   METHOD_B_SKIP_PREREQ=1                       # 跳过 prereq 自检（已确认环境就绪）
#   METHOD_B_NO_MINIKUBE_START=1                 # minikube 停了时不自动启（只报错）
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# === 基础命令 ===
need() { command -v "$1" >/dev/null || { echo "缺命令：$1" >&2; exit 2; }; }
need kubectl
need python3
need curl
need minikube

if [[ "${METHOD_B_SKIP_PREREQ:-}" == "1" ]]; then
  echo "[prereq] skipped (METHOD_B_SKIP_PREREQ=1)"
else
  # === minikube 状态 ===
  if ! minikube status >/dev/null 2>&1; then
    if [[ "${METHOD_B_NO_MINIKUBE_START:-}" == "1" ]]; then
      echo "ERROR: minikube 没起，且 METHOD_B_NO_MINIKUBE_START=1 不自动启" >&2
      exit 2
    fi
    echo "[prereq] minikube 没起，启动..."
    minikube start --driver=docker --cpus=3 --memory=5g --disk-size=30g --kubernetes-version=v1.31.0 >/dev/null
    echo "[prereq] minikube ready"
  fi

  # === 关键 pod 在 clawreef-system ===
  for label in app=clawmanager-app app=fake-llm app=mysql; do
    if ! kubectl -n clawreef-system get pod -l "$label" -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q Running; then
      echo "ERROR: 关键 pod $label 不 Running，集群没准备好" >&2
      echo "  排查：kubectl -n clawreef-system get pods" >&2
      exit 2
    fi
  done

  # === vite 9002 ===
  API="${METHOD_B_API:-http://localhost:9002}"
  if ! curl -s --max-time 2 "$API/" >/dev/null 2>&1; then
    # 只在 API 是默认 vite 代理时才自启；远程 / 自定义 base 不动
    if [[ "$API" == "http://localhost:9002" ]]; then
      FRONTEND_DIR="$(cd "$HERE/../../frontend" && pwd)"
      if [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
        echo "ERROR: 找不到 frontend 目录 ($FRONTEND_DIR)" >&2
        exit 2
      fi
      echo "[prereq] vite 9002 没起，nohup 启动 ($FRONTEND_DIR)..."
      (cd "$FRONTEND_DIR" && nohup npm run dev >"$HOME/.clawmanager-frontend.log" 2>&1 &)
      # 等就绪
      for _ in $(seq 1 30); do
        if curl -s --max-time 1 "$API/" >/dev/null 2>&1; then
          echo "[prereq] vite ready"
          break
        fi
        sleep 1
      done
    fi
  fi

  # === 后端 auth 通联 ===
  http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin123"}' "${METHOD_B_API:-http://localhost:9002}/api/v1/auth/login" 2>/dev/null || echo "000")
  if [[ "$http_code" != "200" ]]; then
    echo "ERROR: ${METHOD_B_API:-http://localhost:9002}/api/v1/auth/login → HTTP $http_code" >&2
    echo "  vite 可能还没完全 ready，等 5s 重试或手动 tail ~/.clawmanager-frontend.log" >&2
    exit 2
  fi
  echo "[prereq] all good"
fi

exec python3 "$HERE/harness.py" "$@"
