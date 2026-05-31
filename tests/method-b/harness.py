"""Method-B harness — 真链路 e2e 工具。

用法：
    python3 harness.py [case_name_filter]

每条 case 是 cases/ 下一个 .py 文件，定义 `def run(h: Harness) -> CaseResult:`。
harness 提供：Backend (后端 admin API)、Pod (kubectl exec 包装)、WSChat
(WS chat.send via ws-client.mjs in pod)、SecplaneAlerts (MySQL 直读)、
DefenseEventsTail (ClawAegis jsonl 增量观察)、assertions。

依赖：kubectl 可达 minikube、纯 stdlib + http.client + subprocess。
"""
from __future__ import annotations
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

HERE = Path(__file__).resolve().parent
CASES_DIR = HERE / "cases"
WS_CLIENT_LOCAL = HERE / "ws-client.mjs"

# 默认通过 vite 代理走（避免每次 minikube ip lookup）；可被 env 覆盖。
DEFAULT_API_BASE = os.environ.get("METHOD_B_API", "http://localhost:9002")
DEFAULT_ADMIN_USER = os.environ.get("METHOD_B_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("METHOD_B_ADMIN_PASS", "admin123")
DEFAULT_INSTANCE_ID = int(os.environ.get("METHOD_B_INSTANCE_ID", "9"))
DEFAULT_POD = os.environ.get("METHOD_B_POD", "clawreef-9-test10")
DEFAULT_POD_NS = os.environ.get("METHOD_B_POD_NS", "clawreef-user-1")
MYSQL_DEPLOY = os.environ.get("METHOD_B_MYSQL_DEPLOY", "deploy/mysql")
MYSQL_NS = os.environ.get("METHOD_B_MYSQL_NS", "clawreef-system")
MYSQL_PWD = os.environ.get("METHOD_B_MYSQL_PWD", "123456")
MYSQL_DB = os.environ.get("METHOD_B_MYSQL_DB", "clawreef")

FAKE_LLM_NS = os.environ.get("METHOD_B_FAKE_LLM_NS", "clawreef-system")
FAKE_LLM_RELAY_POD = os.environ.get("METHOD_B_FAKE_LLM_RELAY", "deploy/mysql")  # 任一带 curl 的 pod，转发请求
FAKE_LLM_URL = os.environ.get("METHOD_B_FAKE_LLM_URL", "http://fake-llm:8080")  # cluster 内 dns


# ─── 数据 ────────────────────────────────────────────────────────────────

@dataclass
class CaseResult:
    name: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


# ─── 后端 admin API ────────────────────────────────────────────────────

class Backend:
    def __init__(self, base: str = DEFAULT_API_BASE):
        self.base = base.rstrip("/")
        self.token: str | None = None

    def login(self, user=DEFAULT_ADMIN_USER, password=DEFAULT_ADMIN_PASS):
        d = self._req("POST", "/api/v1/auth/login", body={"username": user, "password": password}, auth=False)
        self.token = d["data"]["access_token"]
        return self

    def put_rule(self, rule: dict) -> dict:
        """rule_id 必须；如果不存在则创建，已存在则更新。"""
        d = self._req("PUT", "/api/v1/secplane/policy/rules", body=rule)
        return d["data"]

    def list_rules(self, kind: str | None = None, limit: int = 200) -> list[dict]:
        q = f"?limit={limit}"
        if kind:
            q += f"&kind={kind}"
        d = self._req("GET", "/api/v1/secplane/policy/rules" + q)
        return d["data"]["items"]

    def dispatch_aegis(self, instance_ids: list[int]) -> dict:
        d = self._req("POST", "/api/v1/secplane/dispatch/aegis", body={"instance_ids": instance_ids})
        return d["data"]

    def effective_config(self, instance_id: int) -> dict:
        d = self._req("GET", f"/api/v1/secplane/instances/{instance_id}/effective-config")
        return d["data"]

    # ── http 底层 ──
    def _req(self, method: str, path: str, *, body=None, auth=True, timeout=15):
        url = self.base + path
        data = None
        headers = {"Content-Type": "application/json"}
        if auth:
            if not self.token:
                raise RuntimeError("backend not logged in; call .login() first")
            headers["Authorization"] = f"Bearer {self.token}"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"{method} {path} → {e.code}: {raw[:300]}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError(f"{method} {path} returned non-JSON: {raw[:300]}")


# ─── kubectl exec 包装 ─────────────────────────────────────────────────

class Pod:
    def __init__(self, name: str = DEFAULT_POD, ns: str = DEFAULT_POD_NS):
        self.name = name
        self.ns = ns

    def exec(self, cmd: str | list[str], *, timeout: int = 30, check: bool = True) -> tuple[int, str, str]:
        if isinstance(cmd, list):
            argv = ["kubectl", "-n", self.ns, "exec", self.name, "--"] + cmd
        else:
            argv = ["kubectl", "-n", self.ns, "exec", self.name, "--", "sh", "-c", cmd]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise RuntimeError(f"pod exec failed: {cmd!r}\nstderr={p.stderr[:500]}")
        return p.returncode, p.stdout, p.stderr

    def cp_to(self, local: str | Path, remote: str) -> None:
        argv = ["kubectl", "-n", self.ns, "cp", str(local), f"{self.name}:{remote}"]
        p = subprocess.run(argv, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"kubectl cp failed: {p.stderr}")


# ─── WS chat 客户端 (delegates to ws-client.mjs in pod) ─────────────────

class WSChat:
    # 必须放在 openclaw 模块目录下，因为 node 按脚本所在目录的 node_modules 解析 ws 包；
    # 放 /tmp 找不到 ws 模块。
    REMOTE_PATH = "/usr/local/lib/node_modules/openclaw/method-b-ws-client.mjs"

    def __init__(self, pod: Pod):
        self.pod = pod
        self._uploaded = False

    def _ensure_uploaded(self) -> None:
        if self._uploaded:
            return
        self.pod.cp_to(WS_CLIENT_LOCAL, self.REMOTE_PATH)
        self._uploaded = True

    def send(self, message: str, *, session_key: str | None = None, timeout_ms: int = 30000) -> dict:
        """sessionKey 默认按调用时间生成新的（避免历史对话累积污染跨 case 的 LLM 响应）。
        显式传 session_key 可以串多轮（preHook 模式）。"""
        if session_key is None:
            session_key = f"agent:main:case-{int(time.time() * 1000)}"
        self._ensure_uploaded()
        args = json.dumps({"message": message, "sessionKey": session_key, "timeoutMs": timeout_ms})
        cmd = f"echo {shlex.quote(args)} | timeout {(timeout_ms // 1000) + 5} node {self.REMOTE_PATH}"
        rc, out, err = self.pod.exec(cmd, timeout=(timeout_ms // 1000) + 15, check=False)
        # ws-client 输出多行 stdout 时取最后一个非空行（应该是 JSON 结果）
        lines = [l for l in out.splitlines() if l.strip()]
        if not lines:
            raise RuntimeError(f"ws-client produced no output. rc={rc} stderr={err[:500]}")
        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            raise RuntimeError(f"ws-client last line not JSON: {lines[-1]!r} stderr={err[:300]}")


# ─── ClawAegis defense-events.jsonl 增量观察 ──────────────────────────

class DefenseEventsTail:
    JSONL = "/config/.openclaw/plugins/clawaegisex/defense-events.jsonl"

    def __init__(self, pod: Pod):
        self.pod = pod
        self.baseline_lines = self._count_lines()

    def _count_lines(self) -> int:
        rc, out, _ = self.pod.exec(f"wc -l {self.JSONL} 2>/dev/null | awk '{{print $1}}'", check=False)
        return int(out.strip()) if out.strip().isdigit() else 0

    def new_events(self, *, timeout_s: int = 12) -> list[dict]:
        """等到 line count > baseline 或 timeout，返回新增的 events 列表。"""
        deadline = time.monotonic() + timeout_s
        last = self.baseline_lines
        while time.monotonic() < deadline:
            curr = self._count_lines()
            if curr > last:
                last = curr
                time.sleep(0.3)  # 给可能未结束的批次留点时间
                continue
            if last > self.baseline_lines and time.monotonic() > deadline - timeout_s + 0.6:
                break
            time.sleep(0.5)
        # 抓出新增的 N 条
        n_new = last - self.baseline_lines
        if n_new <= 0:
            return []
        cmd = f"tail -n {n_new} {self.JSONL}"
        _, out, _ = self.pod.exec(cmd, check=False)
        events = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return events


# ─── pod 日志增量观察 (defense_check_result / agent_end log 行) ──────

class PodLogTail:
    """每次实例化时记一个起点 (epoch s)；wait_for(pattern) 等到 pod 日志里出现
    匹配行（kubectl logs --since=X），返 (matched_line, all_recent)."""
    def __init__(self, pod: Pod):
        self.pod = pod
        self.started_at = time.monotonic()
        self._wall_at = time.time()

    def _logs_since(self) -> str:
        # since=Ns；多留 2s buffer 避免边界
        secs = max(int(time.monotonic() - self.started_at) + 2, 1)
        rc, out, _ = self.pod.exec(
            ["sh", "-c", f"kubectl 2>/dev/null"],
            check=False,
        )  # 占位防止 lint；实际下面直接走 kubectl
        # 直接 kubectl logs，绕开 pod.exec
        argv = ["kubectl", "-n", self.pod.ns, "logs", self.pod.name, f"--since={secs}s"]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return p.stdout if p.returncode == 0 else ""

    def wait_for(self, pattern: str, *, timeout_s: int = 20) -> str | None:
        """轮询 pod logs，等到匹配行返回该行；超时返 None。pattern 是 substring 不是 regex。"""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            logs = self._logs_since()
            for line in logs.splitlines():
                if pattern in line:
                    return line
            time.sleep(0.5)
        return None

    def grep(self, pattern: str) -> list[str]:
        return [l for l in self._logs_since().splitlines() if pattern in l]


# ─── secplane_alert 表观察 ─────────────────────────────────────────────

class SecplaneAlerts:
    def __init__(self):
        self.baseline_max_id = self.max_id()

    def max_id(self) -> int:
        sql = "SELECT IFNULL(MAX(id),0) FROM secplane_alert"
        return int(self._query(sql).strip() or "0")

    def new_alerts(self, *, timeout_s: int = 10) -> list[dict]:
        """轮询直到出现 id > baseline 的新行，返回新增行（最多 20）。"""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            curr = self.max_id()
            if curr > self.baseline_max_id:
                break
            time.sleep(0.5)
        else:
            return []
        sql = (
            f"SELECT id, source, rule_id, severity, action, agent_id, subject, evidence, raw_payload, ts "
            f"FROM secplane_alert WHERE id > {self.baseline_max_id} ORDER BY id ASC LIMIT 20"
        )
        rows = []
        for line in self._query(sql).splitlines():
            cells = line.split("\t")
            if len(cells) < 10:
                continue
            row = {
                "id": int(cells[0]),
                "source": cells[1],
                "rule_id": cells[2],
                "severity": cells[3],
                "action": cells[4],
                "agent_id": cells[5],
                "subject": cells[6],
                "evidence": cells[7],
                "raw_payload": cells[8],
                "ts": cells[9],
            }
            rows.append(row)
        return rows

    def _query(self, sql: str) -> str:
        # kubectl exec mysql 直接出表头 + 行，我们 skip 表头
        cmd = [
            "kubectl", "-n", MYSQL_NS, "exec", MYSQL_DEPLOY, "--",
            "mysql", f"-uroot", f"-p{MYSQL_PWD}", "-D", MYSQL_DB, "-N", "-e", sql,
        ]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            raise RuntimeError(f"mysql query failed: {p.stderr[:300]}")
        return p.stdout


# ─── 测试环境 setup / teardown ──────────────────────────────────────

SNAPSHOT_PATH = Path(os.environ.get("METHOD_B_SNAPSHOT", "/tmp/method-b-llm-models-snapshot.json"))


def _mysql_exec(sql: str) -> str:
    """跑一条 mysql 命令（写或读都行），返 stdout。"""
    cmd = ["kubectl", "-n", MYSQL_NS, "exec", MYSQL_DEPLOY, "--",
           "mysql", "-uroot", f"-p{MYSQL_PWD}", "-D", MYSQL_DB, "-N", "-e", sql]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError(f"mysql failed: {p.stderr[:300]}")
    return p.stdout


def setup_llm_routing() -> None:
    """snapshot llm_models 现状 → 调成 method-b 需要的态（auto/sensitive 都路由到 fake-llm）。
    若 snapshot 已存在（说明上次 teardown 漏跑），不覆盖、跳过。"""
    if SNAPSHOT_PATH.exists():
        print(f"  [setup] snapshot 已存在 {SNAPSHOT_PATH}（上次 teardown 漏跑或并行运行）→ 跳过 setup")
        return
    rows_raw = _mysql_exec("SELECT display_name, is_active, is_secure FROM llm_models WHERE display_name IN ('ds', 'e2e-fake-llm')")
    snapshot = {}
    for line in rows_raw.splitlines():
        cells = line.split("\t")
        if len(cells) < 3: continue
        snapshot[cells[0]] = {"is_active": int(cells[1]), "is_secure": int(cells[2])}
    if not snapshot:
        print("  [setup] WARN: 没找到 ds 或 e2e-fake-llm 行，跳过")
        return
    SNAPSHOT_PATH.write_text(json.dumps(snapshot))
    # 改成测试态
    _mysql_exec("UPDATE llm_models SET is_active=0 WHERE display_name='ds'; UPDATE llm_models SET is_secure=1 WHERE display_name='e2e-fake-llm';")
    print(f"  [setup] llm_models 改为测试态，原状已存 {SNAPSHOT_PATH}: {snapshot}")


def ensure_instance_running(backend: "Backend", instance_id: int, *, timeout_s: int = 180) -> bool:
    """看 instance/N 的 status：running 就直接返；stopped/error 调 start API，等 pod Running。
    返 True 表示这次是我们 start 的（teardown 时可以 stop 回去）。"""
    def pod_phase() -> str:
        p = subprocess.run(
            ["kubectl", "-n", DEFAULT_POD_NS, "get", "pod", DEFAULT_POD, "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True, timeout=10
        )
        return p.stdout.strip()
    if pod_phase() == "Running":
        print(f"  [setup] instance {instance_id} 已 Running，跳过 start")
        return False
    print(f"  [setup] instance {instance_id} 不 Running (pod phase={pod_phase() or '不存在'}) → 调 start API")
    # 调 ClawManager start API
    d = backend._req("POST", f"/api/v1/instances/{instance_id}/start", body={})
    if not d.get("success"):
        raise RuntimeError(f"start instance 失败: {d}")
    # 等 pod Running
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pod_phase() == "Running":
            print(f"  [setup] pod Running ✓")
            # 还等 openclaw gateway 起来（clawaegisex 注册 + 端口 listen）
            # 简单 sleep 一段时间让 gateway 装好
            time.sleep(6)
            return True
        time.sleep(3)
    raise RuntimeError(f"等 instance {instance_id} 起来 {timeout_s}s 没等到")


def stop_instance(backend: "Backend", instance_id: int) -> None:
    d = backend._req("POST", f"/api/v1/instances/{instance_id}/stop", body={})
    if d.get("success"):
        print(f"  [teardown] instance {instance_id} stop API OK")


def teardown_llm_routing() -> None:
    """从 snapshot 还原 llm_models。"""
    if not SNAPSHOT_PATH.exists():
        print("  [teardown] 无 snapshot，跳过")
        return
    try:
        snapshot = json.loads(SNAPSHOT_PATH.read_text())
    except Exception as e:
        print(f"  [teardown] snapshot 读失败 ({e})，留着不动")
        return
    for name, vals in snapshot.items():
        _mysql_exec(f"UPDATE llm_models SET is_active={vals['is_active']}, is_secure={vals['is_secure']} WHERE display_name='{name}';")
    SNAPSHOT_PATH.unlink()
    print(f"  [teardown] llm_models 已还原到 setup 前状态")


# ─── fake-llm 控制 client (via kubectl exec into a relay pod) ───────

class FakeLLM:
    """fake-llm 的 testing API client。kubectl exec 任一 cluster 内 pod 跑 curl
    转发，避开 host → ClusterIP 的 port-forward。"""
    def __init__(self, *, relay_pod: str = FAKE_LLM_RELAY_POD, relay_ns: str = FAKE_LLM_NS, base: str = FAKE_LLM_URL):
        self.relay_pod = relay_pod
        self.relay_ns = relay_ns
        self.base = base.rstrip("/")

    def _curl(self, method: str, path: str, body: dict | None = None, *, timeout: int = 10, attempts: int = 3) -> dict:
        url = self.base + path
        cmd = ["kubectl", "-n", self.relay_ns, "exec", self.relay_pod, "--", "curl", "-s",
               f"--max-time", str(timeout), "-X", method, url]
        if body is not None:
            cmd += ["-H", "content-type: application/json", "-d", json.dumps(body)]
        last_err = None
        for i in range(attempts):
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            except subprocess.TimeoutExpired as e:
                last_err = f"timeout: {e}"
                time.sleep(1.5)
                continue
            # rc=7 = couldn't connect (kubectl exec / svc DNS flake); rc=28 = curl timeout
            if p.returncode in (7, 28) and i < attempts - 1:
                last_err = f"rc={p.returncode} stderr={p.stderr[:200]}"
                time.sleep(1.5)
                continue
            if p.returncode != 0:
                raise RuntimeError(f"fake-llm {method} {path} curl failed: rc={p.returncode} stderr={p.stderr[:300]}")
            if not p.stdout.strip():
                return {}
            try:
                return json.loads(p.stdout)
            except json.JSONDecodeError:
                raise RuntimeError(f"fake-llm {method} {path} returned non-JSON: {p.stdout[:300]}")
        raise RuntimeError(f"fake-llm {method} {path} 失败 {attempts} 次: {last_err}")

    def reset(self) -> dict:
        return self._curl("POST", "/__test__/reset", {})

    def queue(self, instruction: dict) -> dict:
        return self._curl("POST", "/__test__/next", instruction)

    # ── 便捷 wrapper ──
    def queue_text(self, text: str, *, prefix: str | None = None) -> dict:
        return self.queue({"kind": "text", "text": text, "prefix": prefix})

    def queue_refusal(self, reason: str = "测试拒绝") -> dict:
        return self.queue({"kind": "refusal", "reason": reason})

    def queue_tool_call(self, name: str, args: dict | None = None) -> dict:
        return self.queue({"kind": "tool_call", "name": name, "args": args or {}})

    def queue_tool_calls(self, calls: list[dict]) -> dict:
        return self.queue({"kind": "tool_calls", "calls": calls})

    def queue_multi_text(self, texts: list[str]) -> dict:
        return self.queue({"kind": "multi_text", "texts": texts})

    def queue_error(self, *, status: int = 500, message: str = "fake-llm injected error") -> dict:
        return self.queue({"kind": "error", "status": status, "message": message})

    # ── 观察 ──
    def inspect(self) -> dict:
        return self._curl("GET", "/__test__/inspect")

    def log_entries(self) -> list[dict]:
        return self._curl("GET", "/__test__/log").get("entries", [])

    def queue_depth(self) -> int:
        return self._curl("GET", "/__test__/queue").get("depth", 0)


# ─── 顶层 Harness 上下文 ───────────────────────────────────────────────

@dataclass
class Harness:
    backend: Backend
    pod: Pod
    wschat: WSChat
    fakellm: FakeLLM
    instance_id: int = DEFAULT_INSTANCE_ID

    # case 内部用：在动作前抓快照
    def fresh_observer(self) -> tuple[DefenseEventsTail, SecplaneAlerts]:
        return DefenseEventsTail(self.pod), SecplaneAlerts()

    def fresh_log_tail(self) -> PodLogTail:
        return PodLogTail(self.pod)

    # ── 常用快捷工具（case 复用，避免每条都重写 5 步骨架） ──

    # 8 个支持 mode（enforce/observe/off）的 defense（其余 6 个只 enable/disable）：
    # selfProtection / commandBlock / encodingGuard / scriptProvenanceGuard /
    # memoryGuard / loopGuard / exfiltrationGuard / dispatchGuard
    MODE_DEFENSES = {
        "selfProtection", "commandBlock", "encodingGuard", "scriptProvenanceGuard",
        "memoryGuard", "loopGuard", "exfiltrationGuard", "dispatchGuard",
    }

    def set_defense(self, name: str, *, enabled: bool = True, mode: str = "enforce") -> None:
        """对 defense.<name> 一发 PUT。mode 仅对 MODE_DEFENSES 生效。"""
        self.backend.put_rule({
            "rule_id": f"defense.{name}",
            "kind": "defense_toggle",
            "is_enabled": enabled,
            "mode": mode,
            "display_name": name,
            "description": f"defense {name}",
            "target": "user_input",
            "severity": "medium",
            "action": "observe",
            "sort_order": 100,
        })

    def set_user_risk_rules(self, *, scan_enabled: bool, scan_mode: str = "enforce",
                             flag_rules: list[dict] | None = None) -> None:
        """一次设好 defense.userRiskScan + 一组 urf.<flag>。
        flag_rules 每条 dict 需含 flag (urf 后缀)、is_enabled、mode。"""
        self.backend.put_rule({
            "rule_id": "defense.userRiskScan",
            "kind": "defense_toggle",
            "is_enabled": scan_enabled,
            "mode": scan_mode,
            "display_name": "用户风险标记扫描",
            "description": "扫描用户输入的风险标记",
            "target": "user_input",
            "severity": "medium",
            "action": "observe",
            "sort_order": 150,
        })
        for spec in (flag_rules or []):
            flag = spec["flag"]
            self.backend.put_rule({
                "rule_id": f"urf.{flag}",
                "kind": "user_risk_flag",
                "is_enabled": spec["is_enabled"],
                "mode": spec["mode"],
                "display_name": flag,
                "description": f"user_risk_flag {flag}",
                "target": "user_input",
                "severity": spec.get("severity", "high"),
                "action": spec.get("action", "block"),
                "sort_order": spec.get("sort_order", 900),
            })

    USER_CONFIG_PATH = "/config/.openclaw/extensions/clawaegisex/user_config.json"

    def _user_config_mtime(self) -> float:
        rc, out, _ = self.pod.exec(f"stat -c %Y {self.USER_CONFIG_PATH} 2>/dev/null", check=False)
        try:
            return float(out.strip()) if out.strip() else 0.0
        except ValueError:
            return 0.0

    def dispatch_and_wait_hot_reload(self, *, timeout_s: int = 15, hot_reload_grace_s: float = 1.5) -> dict:
        """触发 dispatch；mtime 推进则等 ClawAegis 热重载，
        没推进就是上次 dispatch 的 sha 完全相同 (idempotency dedup) → 不用等。
        无论哪种情况都确认 gateway listening。"""
        before_mtime = self._user_config_mtime()
        out = self.backend.dispatch_aegis([self.instance_id])
        deadline = time.monotonic() + timeout_s
        config_changed = False
        while time.monotonic() < deadline:
            curr = self._user_config_mtime()
            if curr > before_mtime:
                config_changed = True
                break
            time.sleep(0.5)
        self.wait_for_gateway_ready()
        if config_changed:
            time.sleep(hot_reload_grace_s)
        return out

    def send_expecting_llm(self, message: str, *, attempts: int = 3, llm_wait_s: int = 12) -> dict:
        """ws.send + 验证 fake-llm 确实被调到一次。若 attempts 内都没调到 → 抛错（agent
        runner 没 ready 或 openclaw 没 dispatch 给 LLM）。case 调用前自己 reset+queue 想要的响应。"""
        for i in range(attempts):
            ws = self.wschat.send(message)
            if not ws.get("ok"):
                if i == attempts - 1:
                    raise RuntimeError(f"ws.send 失败: {ws}")
                time.sleep(2)
                continue
            # 等 fake-llm 被调到
            deadline = time.monotonic() + llm_wait_s
            while time.monotonic() < deadline:
                if self.fakellm.inspect().get("calls", 0) >= 1:
                    return ws
                time.sleep(0.5)
            # 这次 attempt 没调到 LLM，重试前重置（case 已 queue 过响应，但被 echo 替代会污染历史）
            if i < attempts - 1:
                time.sleep(2)
        raise RuntimeError(f"openclaw 在 {attempts} 次 ws.send 后仍未调到 fake-llm — agent runner 没 ready 或 chat 没派发")

    def wait_for_gateway_ready(self, *, timeout_s: int = 30) -> bool:
        """等 pod 内 18789 端口能 connect（gateway 在 install_skill 时会重启短暂断开）。"""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            rc, _, _ = self.pod.exec(
                "node -e 'require(\"net\").connect(18789,\"127.0.0.1\",()=>process.exit(0)).on(\"error\",()=>process.exit(1))'",
                check=False, timeout=5)
            if rc == 0:
                return True
            time.sleep(0.5)
        raise RuntimeError(f"gateway 18789 in pod 没在 {timeout_s}s 内 ready")


# ─── case 加载 / runner ────────────────────────────────────────────────

def load_cases(filter_substr: str | None) -> list[tuple[str, Callable[[Harness], CaseResult]]]:
    out = []
    if not CASES_DIR.exists():
        return out
    for p in sorted(CASES_DIR.glob("*.py")):
        if p.name.startswith("_"):
            continue
        name = p.stem
        if filter_substr and filter_substr not in name:
            continue
        # 用 spec 加载，让 cases 不需要 package
        import importlib.util
        spec = importlib.util.spec_from_file_location(f"method_b_case_{name}", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not hasattr(mod, "run"):
            print(f"WARN: case {name} 没有 run() 函数，跳过")
            continue
        out.append((name, mod.run))
    return out


def main(argv: list[str]) -> int:
    filter_substr = argv[1] if len(argv) > 1 else None
    cases = load_cases(filter_substr)
    if not cases:
        print("没找到 case", file=sys.stderr)
        return 2

    print("== method-b harness ==")
    print(f"  API base: {DEFAULT_API_BASE}")
    print(f"  Pod: {DEFAULT_POD_NS}/{DEFAULT_POD} (instance_id={DEFAULT_INSTANCE_ID})")
    print(f"  Cases: {len(cases)}")

    backend = Backend().login()
    pod = Pod()
    wschat = WSChat(pod)
    fakellm = FakeLLM()
    harness = Harness(backend=backend, pod=pod, wschat=wschat, fakellm=fakellm)

    # === setup ===
    skip_setup = os.environ.get("METHOD_B_NO_SETUP") == "1"
    skip_teardown = os.environ.get("METHOD_B_NO_TEARDOWN") == "1"
    auto_stop_instance = False
    if not skip_setup:
        setup_llm_routing()
        auto_stop_instance = ensure_instance_running(backend, DEFAULT_INSTANCE_ID)

    passed = 0
    results: list[CaseResult] = []
    cooldown_s = float(os.environ.get("METHOD_B_COOLDOWN_S", "4"))
    max_attempts = int(os.environ.get("METHOD_B_MAX_ATTEMPTS", "2"))
    try:
     for i, (name, run) in enumerate(cases, 1):
        r = None
        for attempt in range(1, max_attempts + 1):
            tag = f"[{i}/{len(cases)}] {name}"
            if attempt > 1:
                tag += f" (retry {attempt}/{max_attempts})"
            print(f"\n{tag} ...")
            try:
                r = run(harness)
            except Exception as e:
                import traceback
                traceback.print_exc()
                r = CaseResult(name=name, passed=False, failures=[f"exception: {e}"])
            if r.passed:
                break
            if attempt < max_attempts:
                print(f"  ↻ flake, retrying after {cooldown_s}s")
                time.sleep(cooldown_s)
        results.append(r)
        if r.passed:
            passed += 1
            print(f"  PASS")
        else:
            print(f"  FAIL")
            for f in r.failures:
                print(f"    - {f}")
        if i < len(cases):
            time.sleep(cooldown_s)  # case 间冷却让 cluster 喘口气

     print(f"\n== {passed}/{len(cases)} passed ==")
     return 0 if passed == len(cases) else 1
    finally:
        if not skip_teardown:
            teardown_llm_routing()
            if auto_stop_instance:
                try:
                    stop_instance(backend, DEFAULT_INSTANCE_ID)
                except Exception as e:
                    print(f"  [teardown] stop instance 失败: {e}")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
