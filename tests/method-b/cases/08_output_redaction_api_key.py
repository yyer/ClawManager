"""Case 08: api_key 赋值在 assistant text → output_redaction observed event。

测的是 SENSITIVE_OUTPUT_QUOTED_ASSIGNMENT_RE 路径（api_key/secret/token 等 keyword + 引号值）。
"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "08_output_redaction_api_key"
    fails: list[str] = []

    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])
    h.set_defense("outputRedaction", enabled=True)
    h.dispatch_and_wait_hot_reload()

    h.fakellm.reset()
    h.fakellm.queue_text('config = { api_key: "sk-thisIsFakeButLong1234567890" }')

    events_tail, alerts_tail = h.fresh_observer()
    try:
        h.send_expecting_llm("请重复刚才的内容")
    except RuntimeError as e:
        return CaseResult(name=name, passed=False, failures=[str(e)])

    events = events_tail.new_events(timeout_s=25)
    hit = next((e for e in events
                if e.get("defense") == "output_redaction"
                and e.get("result") == "observed"
                and (e.get("details") or {}).get("redactionCount", 0) >= 1), None)
    if not hit:
        fails.append(f"期望 output_redaction observed event，实际 {[(e.get('defense'), e.get('result')) for e in events]}")

    alerts = alerts_tail.new_alerts(timeout_s=30)
    if not any(a.get("rule_id") == "output_redaction" and a.get("action") == "observed" for a in alerts):
        fails.append(f"secplane_alert 没找到 output_redaction/observed 行，实际新增 {len(alerts)} 条")

    return CaseResult(name=name, passed=not fails, failures=fails)
