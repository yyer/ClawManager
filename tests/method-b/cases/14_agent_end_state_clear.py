"""Case 14: agent_end 在 turn 结束时 fire + 清 state.

简化版：只验单 turn agent_end log 出现且 sessionKey 匹配。
agent_end hook 在 embedded runner 末尾被调（已实证），这条 case 是个最小烟雾测试。
"""
import time
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "14_agent_end_state_clear"
    fails: list[str] = []

    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])  # 减少其他噪声
    h.dispatch_and_wait_hot_reload()

    h.fakellm.reset()
    for _ in range(3):
        h.fakellm.queue_text("OK")

    session_key = f"agent:main:agent-end-{int(time.time() * 1000)}"
    logs = h.fresh_log_tail()
    try:
        h.wschat.send("聊聊天气", session_key=session_key)
    except Exception as e:
        return CaseResult(name=name, passed=False, failures=[f"WS 失败: {e}"])

    # agent_end 在 LLM 调用 + 后续 hooks 全完之后；fake-llm 慢的话整 turn 可能 30-40s
    line = logs.wait_for(f'"hook":"agent_end","sessionKey":"{session_key}"', timeout_s=45)
    if not line:
        fails.append(f"45s 内没等到 agent_end log for sessionKey={session_key}")
    elif '"event":"agent_runtime_state_cleared"' not in line:
        fails.append(f"agent_end log 缺 agent_runtime_state_cleared event 字段: {line[-200:]}")

    return CaseResult(name=name, passed=not fails, failures=fails)
