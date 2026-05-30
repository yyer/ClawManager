"""Case 12: before_prompt_build - promptGuard enabled + 干净 session → 静态 system context 注入。

期望 pod log 出现:
  defense_check_result hook=before_prompt_build mechanism=prompt_guard result=static_only_injected

不验 jsonl/alert，因为 static-only 不 emit defense event（只有 dynamic context
才 emit prompt_guard observed）。
"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "12_prompt_guard_static_only"
    fails: list[str] = []

    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])  # 干净 session
    h.set_defense("promptGuard", enabled=True)
    h.dispatch_and_wait_hot_reload()

    h.fakellm.reset()
    h.fakellm.queue_text("OK")

    logs = h.fresh_log_tail()
    try:
        h.send_expecting_llm("聊聊天气")
    except RuntimeError as e:
        return CaseResult(name=name, passed=False, failures=[str(e)])

    # 等 pod log 出现 prompt_guard 防御检查结果
    line = logs.wait_for('"event":"defense_check_result","hook":"before_prompt_build","mechanism":"prompt_guard"', timeout_s=20)
    if not line:
        fails.append("没在 pod log 找到 defense_check_result + prompt_guard 行")
    elif '"result":"static_only_injected"' not in line:
        fails.append(f"prompt_guard result 应为 static_only_injected，实际行: {line[-200:]}")

    return CaseResult(name=name, passed=not fails, failures=fails)
