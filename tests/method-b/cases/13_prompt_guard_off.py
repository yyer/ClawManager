"""Case 13: promptGuard off → before_prompt_build 早 return disabled。

pod log 期望:
  defense_check_result hook=before_prompt_build mechanism=prompt_guard result=disabled
"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "13_prompt_guard_off"
    fails: list[str] = []

    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])
    h.set_defense("promptGuard", enabled=False)
    disp = h.dispatch_and_wait_hot_reload()
    if disp.get("user_config", {}).get("promptGuardEnabled"):
        fails.append(f"promptGuardEnabled 应=False，实际={disp.get('user_config',{}).get('promptGuardEnabled')}")

    h.fakellm.reset()
    h.fakellm.queue_text("OK")

    logs = h.fresh_log_tail()
    try:
        h.send_expecting_llm("聊聊天气")
    except RuntimeError as e:
        return CaseResult(name=name, passed=False, failures=[str(e)])

    line = logs.wait_for('"event":"defense_check_result","hook":"before_prompt_build","mechanism":"prompt_guard"', timeout_s=20)
    if not line:
        fails.append("没找到 prompt_guard defense_check_result 行")
    elif '"result":"disabled"' not in line:
        fails.append(f"prompt_guard result 应=disabled，实际行: {line[-200:]}")

    return CaseResult(name=name, passed=not fails, failures=fails)
