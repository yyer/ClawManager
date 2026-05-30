"""
E2E 测试 harness — 一切 ClawManager 后端交互 + fake LLM 控制 + 告警等待。

用法见 cases/outbound_trust_block.py。

环境变量:
    CLAWMANAGER_URL    — e.g. http://192.168.49.2:30901  (default: 推 minikube ip)
    CLAWMANAGER_USER   — admin 用户名 (default: admin)
    CLAWMANAGER_PASS   — admin 密码   (default: admin123)
    FAKE_LLM_URL       — e.g. http://fake-llm.clawreef-system.svc.cluster.local:8080
                          从 pod 内访问; 从 host 上 port-forward 后填 http://127.0.0.1:8080
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any


def _minikube_ip() -> str:
    try:
        return subprocess.check_output(["minikube", "ip"], text=True).strip()
    except Exception:
        return "127.0.0.1"


CLAWMANAGER_URL = os.environ.get("CLAWMANAGER_URL") or f"http://{_minikube_ip()}:30901"
CLAWMANAGER_USER = os.environ.get("CLAWMANAGER_USER", "admin")
CLAWMANAGER_PASS = os.environ.get("CLAWMANAGER_PASS", "admin123")
FAKE_LLM_URL = os.environ.get("FAKE_LLM_URL", "http://127.0.0.1:8080")


def _req(method: str, url: str, *, token: str | None = None, body: dict | None = None) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {url} → HTTP {e.code}: {raw[:300]}") from None


class Backend:
    """ClawManager 后端 admin API 客户端，最小够用。"""

    def __init__(self, base: str = CLAWMANAGER_URL) -> None:
        self.base = base.rstrip("/")
        self.token: str | None = None

    def login(self, user: str = CLAWMANAGER_USER, pwd: str = CLAWMANAGER_PASS) -> None:
        r = _req("POST", f"{self.base}/api/v1/auth/login",
                 body={"username": user, "password": pwd})
        self.token = r["data"]["access_token"]

    # ----- 策略状态 -----
    def set_defense_mode(self, rule_id: str, *, mode: str | None = None,
                         enabled: bool | None = None) -> None:
        """mode: enforce/observe/off — off 等价 enabled=False。"""
        cur = self._get_rule(rule_id)
        if cur is None:
            raise RuntimeError(f"rule_id 不存在: {rule_id}")
        body = dict(cur)
        if mode is not None:
            if mode == "off":
                body["is_enabled"] = False
            else:
                body["is_enabled"] = True
                body["mode"] = mode
        if enabled is not None:
            body["is_enabled"] = enabled
        _req("PUT", f"{self.base}/api/v1/secplane/policy/rules", token=self.token, body=body)

    def _get_rule(self, rule_id: str) -> dict | None:
        r = _req("GET", f"{self.base}/api/v1/secplane/policy/rules?kind=defense_toggle",
                 token=self.token)
        for it in r["data"]["items"]:
            if it["rule_id"] == rule_id:
                return it
        return None

    # ----- 出站白名单 -----
    def reset_outbound_trusted(self) -> None:
        items = _req("GET", f"{self.base}/api/v1/secplane/outbound/trusted",
                     token=self.token)["data"]["items"]
        for it in items:
            _req("DELETE", f"{self.base}/api/v1/secplane/outbound/trusted/{it['id']}",
                 token=self.token)

    def add_outbound_trusted(self, domain: str, *, fingerprint: str | None = None,
                             label: str | None = None) -> int:
        body = {"domain_pattern": domain}
        if fingerprint:
            body["fingerprint_sha256"] = fingerprint
        if label:
            body["label"] = label
        r = _req("POST", f"{self.base}/api/v1/secplane/outbound/trusted",
                 token=self.token, body=body)
        return r["data"]["id"]

    # ----- 应急熔断 -----
    def kill_switch_set(self, enabled: bool, *, reason: str = "e2e test") -> None:
        if enabled:
            _req("POST", f"{self.base}/api/v1/secplane/kill-switch/enable",
                 token=self.token, body={"reason": reason})
        else:
            _req("POST", f"{self.base}/api/v1/secplane/kill-switch/disable",
                 token=self.token)

    # ----- 下发 -----
    def dispatch_apply(self, instance_ids: list[int] | None = None) -> dict:
        body = {"instance_ids": instance_ids} if instance_ids else {}
        return _req("POST", f"{self.base}/api/v1/secplane/dispatch/aegis-apply",
                    token=self.token, body=body)["data"]

    # ----- 告警 -----
    def list_alerts(self, *, limit: int = 50, rule_id: str | None = None) -> list[dict]:
        url = f"{self.base}/api/v1/secplane/alerts?limit={limit}"
        if rule_id:
            url += f"&rule_id={rule_id}"
        return _req("GET", url, token=self.token)["data"]["items"]

    def wait_for_alert(self, *, rule_id_prefix: str, since_ts: float | None = None,
                       agent_id_contains: str | None = None,
                       evidence_contains: str | None = None,
                       timeout: float = 20.0) -> dict | None:
        """轮询直到出现匹配的告警；超时返回 None。"""
        deadline = time.time() + timeout
        since_ts = since_ts or 0
        while time.time() < deadline:
            for a in self.list_alerts(limit=50):
                ts = time.mktime(time.strptime(a["ts"].rstrip("Z"), "%Y-%m-%dT%H:%M:%S"))
                if ts < since_ts:
                    continue
                rid = a.get("rule_id") or ""
                if not rid.startswith(rule_id_prefix):
                    continue
                if agent_id_contains and agent_id_contains not in (a.get("agent_id") or ""):
                    continue
                if evidence_contains and evidence_contains not in (a.get("evidence") or ""):
                    continue
                return a
            time.sleep(1.0)
        return None


@dataclass
class FakeLLMClient:
    """对运行中的 fake_llm.py 的远程控制。"""

    base: str = FAKE_LLM_URL

    def reset(self) -> None:
        _req("POST", f"{self.base}/__test__/reset")

    def expect_tool_call(self, name: str, args: dict) -> None:
        _req("POST", f"{self.base}/__test__/next",
             body={"kind": "tool_call", "name": name, "args": args})

    def expect_text(self, text: str) -> None:
        _req("POST", f"{self.base}/__test__/next",
             body={"kind": "text", "text": text})

    def log(self) -> list[dict]:
        return _req("GET", f"{self.base}/__test__/log")["entries"]


# --- WebChat 输入注入 (TODO: 任选一种实现并替换 send_user_message) ---
#
# 选项 A — 浏览器 Playwright (最贴近用户，慢)：
#     pip install playwright && playwright install chromium
#     在浏览器登录后定位 webchat input → fill(text) → press Enter
#
# 选项 B — openclaw WebSocket 直注 (需实现 connect.challenge 握手)：
#     ws://<pod-ip>:18789/ → 解 challenge.payload.nonce →
#     回包带签名 → 收到 connect.ready 后发 message.create → 关
#
# 选项 C — 手工浏览器复制粘贴 + 程序等待 (当前默认，下面这个实现)：
#     程序打印 sentinel 给你，你打开 webchat 粘贴 → 程序等告警出现
def send_user_message(instance_id: int, text: str, *, mode: str = "manual") -> None:
    """把一条 user message 送进指定 openclaw 实例的 webchat。

    mode='manual' (default): 打印到 stderr, 由人粘贴。
    mode='playwright' / mode='websocket': 留作扩展。
    """
    if mode == "manual":
        print(
            f"\n  >>> 请在 instance {instance_id} 的 webchat 里粘贴这条消息（按 Enter）:\n"
            f"      {text}\n"
            f"      [harness 正在等待告警…]",
            flush=True,
        )
        return
    raise NotImplementedError(f"send_user_message mode={mode} 尚未实现，参考 send_message.py 注释")


def now() -> float:
    return time.time()
