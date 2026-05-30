"""Case 10: defense.outputRedaction is_enabled=false → user_config.outputRedactionEnabled=false
→ before_message_write 早 return, 即便 assistant text 含 Bearer 也不脱敏不 emit。
"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "10_output_redaction_off"
    fails: list[str] = []

    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])
    h.set_defense("outputRedaction", enabled=False)
    disp = h.dispatch_and_wait_hot_reload()
    if disp.get("user_config", {}).get("outputRedactionEnabled"):
        fails.append(f"outputRedactionEnabled 应=False，实际={disp.get('user_config', {}).get('outputRedactionEnabled')}")

    h.fakellm.reset()
    h.fakellm.queue_text("Authorization: Bearer abcd1234567890efgh - 即使关了也不该脱敏")

    events_tail, alerts_tail = h.fresh_observer()
    try:
        h.send_expecting_llm("请重复")
    except RuntimeError as e:
        return CaseResult(name=name, passed=False, failures=[str(e)])

    events = events_tail.new_events(timeout_s=10)
    bad = [e for e in events if e.get("defense") == "output_redaction" and e.get("result") == "observed"]
    if bad:
        fails.append(f"outputRedaction off 时不应触 observed event，实际 {bad}")

    alerts = alerts_tail.new_alerts(timeout_s=6)
    bad_a = [a for a in alerts if a.get("rule_id") == "output_redaction" and a.get("action") == "observed"]
    if bad_a:
        fails.append(f"outputRedaction off 时不应有 observed alert，实际 {len(bad_a)} 条")

    return CaseResult(name=name, passed=not fails, failures=fails)
