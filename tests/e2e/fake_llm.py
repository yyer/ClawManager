"""
Fake LLM — OpenAI-compatible /v1/chat/completions + 测试控制 API。

设计：
- 默认返回 echo（assistant message），不会触发 ClawAegis。
- 测试通过 POST /__test__/next 把"下一次调用的响应"压队列；多条按 FIFO 弹。
- POST /__test__/reset 清队列 + 清日志。GET /__test__/log 看 LLM 实际收到的 prompts。
- GET /__test__/inspect 取统计摘要（请求总数、最近的 user 消息、是否见过 tool 角色消息）。

支持的 `kind`：
  - text        默认；assistant 返普通文本（含可选 prefix）
  - tool_call   返单个 tool_call（name + args）
  - tool_calls  返多个 tool_calls（list of {name, args}）
  - refusal     便捷模式：assistant 返 "[ClawAegis] <reason>"（触 ClawAegis llm_output prompt_self_block）
  - multi_text  multiple choices，每个 choice 一段 assistant 文本（测 llm_output dedup）
  - error       返 OpenAI 错误格式 HTTP 500

跑法：
    python3 fake_llm.py            # PORT 默认 8080，可被 env PORT 覆盖

OpenAI tool-call 响应 schema 参考：openai/openai-python README。
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import sys
import threading
import time
import uuid


# next-response 队列；测试驱动 POST /__test__/next 一条进来
_queue: list[dict] = []
_log: list[dict] = []
_lock = threading.Lock()

CLAW_AEGIS_PREFIX = "[ClawAegis]"


# ── response 构造工具 ───────────────────────────────────────────────

def _chatcmpl_base(model: str = "fake-llm-v0") -> dict:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def echo_response(text: str) -> dict:
    return _chatcmpl_base() | {
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": f"echo: {text[:120]}"},
            "finish_reason": "stop",
        }],
    }


def text_response(text: str, *, prefix: str | None = None) -> dict:
    """assistant 返普通文本。prefix 非空时拼在最前面（用于把 [ClawAegis] 放中间等场景）。"""
    body = f"{prefix}{text}" if prefix else text
    return _chatcmpl_base() | {
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": body},
            "finish_reason": "stop",
        }],
    }


def refusal_response(reason: str = "测试拒绝") -> dict:
    """便捷：assistant 返 [ClawAegis] 起头文本，触 ClawAegis llm_output prompt_self_block。"""
    return text_response(f"{CLAW_AEGIS_PREFIX} {reason}".strip())


def tool_call_response(name: str, args: dict) -> dict:
    return tool_calls_response([{"name": name, "args": args}])


def tool_calls_response(calls: list[dict]) -> dict:
    """支持多 tool_calls。每个元素 {name, args, id?}。"""
    return _chatcmpl_base() | {
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": c.get("id") or f"call_{uuid.uuid4().hex[:8]}",
                        "type": "function",
                        "function": {
                            "name": c["name"],
                            "arguments": json.dumps(c.get("args") or {}),
                        },
                    }
                    for c in calls
                ],
            },
            "finish_reason": "tool_calls",
        }],
    }


def multi_text_response(texts: list[str]) -> dict:
    """多 choices，每个 choice 一段 assistant 文本。用于 llm_output dedup 类测试
    (ClawAegis 应当只 emit 一个 prompt_self_block event 即使多条 text 都含 prefix)。"""
    return _chatcmpl_base() | {
        "choices": [
            {
                "index": i,
                "message": {"role": "assistant", "content": t},
                "finish_reason": "stop",
            }
            for i, t in enumerate(texts)
        ],
    }


def build_response(instruction: dict, last_user: str) -> dict | tuple[int, dict]:
    """从 instruction 构造 OpenAI response。返 (status_code, payload) 表示要 send_json 直接出。"""
    kind = instruction.get("kind", "text")
    if kind == "text":
        return text_response(instruction.get("text", ""), prefix=instruction.get("prefix"))
    if kind == "refusal":
        return refusal_response(instruction.get("reason", "测试拒绝"))
    if kind == "tool_call":
        return tool_call_response(instruction["name"], instruction.get("args") or {})
    if kind == "tool_calls":
        return tool_calls_response(instruction.get("calls") or [])
    if kind == "multi_text":
        return multi_text_response(instruction.get("texts") or [""])
    if kind == "error":
        return (
            int(instruction.get("status", 500)),
            {
                "error": {
                    "message": instruction.get("message", "fake-llm injected error"),
                    "type": instruction.get("type", "server_error"),
                    "code": instruction.get("code", "fake_injected"),
                }
            },
        )
    if kind == "echo":
        return echo_response(last_user)
    return (400, {"error": f"unknown kind {kind!r}"})


# ── HTTP handler ─────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def _read_body(self) -> dict:
        length = int(self.headers.get("content-length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("access-control-allow-origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.split("?", 1)[0]

        # ── 测试控制 API ──
        if path == "/__test__/next":
            req = self._read_body()
            with _lock:
                _queue.append(req)
            self._send_json(200, {"queued": True, "depth": len(_queue)})
            return

        if path == "/__test__/reset":
            with _lock:
                _queue.clear()
                _log.clear()
            self._send_json(200, {"reset": True})
            return

        # ── /v1/chat/completions ──
        if path.endswith("/chat/completions"):
            req = self._read_body()
            msgs = req.get("messages", []) if isinstance(req, dict) else []
            stream = bool(req.get("stream", False))
            last_user = ""
            for m in reversed(msgs):
                if isinstance(m, dict) and m.get("role") == "user":
                    content = m.get("content", "")
                    last_user = content if isinstance(content, str) else json.dumps(content)
                    break
            with _lock:
                _log.append({
                    "ts": time.time(),
                    "model": req.get("model"),
                    "stream": stream,
                    "msg_count": len(msgs),
                    "roles_seen": [m.get("role") for m in msgs if isinstance(m, dict)],
                    "last_user": last_user[:200],
                    "msgs": msgs,
                })
                instruction = _queue.pop(0) if _queue else None

            if instruction is None:
                resp = echo_response(last_user)
            else:
                built = build_response(instruction, last_user)
                if isinstance(built, tuple):
                    code, payload = built
                    self._send_json(code, payload)
                    return
                resp = built

            if stream:
                self._send_sse(resp)
            else:
                self._send_json(200, resp)
            return

        self._send_json(404, {"error": f"no route: {path}"})

    def _send_sse(self, full_response: dict) -> None:
        """把一次性 chat.completion 切成 SSE chunks 模拟流式输出。
        每个 choice 各自 emit role → content/tool_calls → finish；末尾 [DONE]。"""
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "keep-alive")
        self.end_headers()

        chunk_id = full_response.get("id", f"chatcmpl-{uuid.uuid4().hex[:12]}")
        created = full_response.get("created", int(time.time()))
        model = full_response.get("model", "fake-llm-v0")

        def emit(index: int, delta: dict, finish_reason=None) -> None:
            chunk = {
                "id": chunk_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": index, "delta": delta, "finish_reason": finish_reason}],
            }
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
            self.wfile.flush()

        for choice in full_response.get("choices", []):
            idx = choice.get("index", 0)
            msg = choice.get("message", {})
            finish = choice.get("finish_reason") or "stop"
            # role 块
            emit(idx, {"role": "assistant"})
            if msg.get("tool_calls"):
                for i, tc in enumerate(msg["tool_calls"]):
                    emit(idx, {"tool_calls": [{
                        "index": i,
                        "id": tc["id"],
                        "type": "function",
                        "function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]},
                    }]})
            else:
                content = msg.get("content") or ""
                if content:
                    emit(idx, {"content": content})
            emit(idx, {}, finish_reason=finish)
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/__test__/log":
            with _lock:
                self._send_json(200, {"entries": list(_log)})
            return

        if path == "/__test__/queue":
            with _lock:
                self._send_json(200, {"depth": len(_queue), "items": list(_queue)})
            return

        if path == "/__test__/inspect":
            # 摘要：调用次数、最近的 user/tool 消息、tool_call 出现次数。
            with _lock:
                entries = list(_log)
                queue_depth = len(_queue)
            n_calls = len(entries)
            last_user = entries[-1]["last_user"] if entries else None
            saw_tool_role = any("tool" in (e.get("roles_seen") or []) for e in entries)
            tool_role_count = sum(
                sum(1 for r in (e.get("roles_seen") or []) if r == "tool")
                for e in entries
            )
            self._send_json(200, {
                "calls": n_calls,
                "queue_depth": queue_depth,
                "last_user": last_user,
                "saw_tool_role": saw_tool_role,
                "tool_role_count": tool_role_count,
            })
            return

        if path == "/v1/models":
            self._send_json(200, {
                "object": "list",
                "data": [{"id": "fake-llm-v0", "object": "model", "owned_by": "test"}],
            })
            return

        if path in ("/", "/healthz"):
            self._send_json(200, {"ok": True, "queue_depth": len(_queue), "log_size": len(_log)})
            return

        self._send_json(404, {"error": f"no route: {path}"})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[fake-llm] {self.address_string()} {fmt % args}\n")


def main():
    port = int(os.environ.get("PORT", "8080"))
    print(f"fake-llm listening on :{port}", file=sys.stderr, flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
