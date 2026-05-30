"""Case 09: 普通 assistant text → 不脱敏，无 output_redaction event。"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "09_output_redaction_clean"
    fails: list[str] = []

    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])
    h.set_defense("outputRedaction", enabled=True)
    h.dispatch_and_wait_hot_reload()

    h.fakellm.reset()
    h.fakellm.queue_text("今天天气不错，你想做什么呢？")

    events_tail, alerts_tail = h.fresh_observer()
    try:
        h.send_expecting_llm("聊聊天气吧")
    except RuntimeError as e:
        return CaseResult(name=name, passed=False, failures=[str(e)])

    events = events_tail.new_events(timeout_s=10)
    bad = [e for e in events if e.get("defense") == "output_redaction" and e.get("result") != "clear"]
    if bad:
        fails.append(f"clean assistant text 不应触 output_redaction 非 clear event，实际 {bad}")

    alerts = alerts_tail.new_alerts(timeout_s=6)
    bad_a = [a for a in alerts if a.get("rule_id") == "output_redaction"]
    if bad_a:
        fails.append(f"clean 不应有 output_redaction alert，实际 {len(bad_a)} 条")

    return CaseResult(name=name, passed=not fails, failures=fails)
