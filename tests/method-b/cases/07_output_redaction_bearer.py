"""Case 07: before_message_write (assistant) - Bearer token in assistant text → output_redaction observed event。

fake-llm 返带 Bearer 的 assistant text → openclaw 收完 LLM 响应后跑 before_message_write
→ ClawAegis output_redaction 命中 SENSITIVE_OUTPUT_BEARER_RE → emit observed event。
"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "07_output_redaction_bearer"
    fails: list[str] = []

    # 关 userRiskScan 防止输入文本误触
    h.set_user_risk_rules(scan_enabled=False, flag_rules=[])
    h.set_defense("outputRedaction", enabled=True)
    h.dispatch_and_wait_hot_reload()

    h.fakellm.reset()
    h.fakellm.queue_text("上次的 Authorization: Bearer abcd1234567890efgh 是测试值，请保留")

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
        fails.append(f"期望 output_redaction observed event redactionCount>=1，实际 {[(e.get('defense'), e.get('result'), (e.get('details') or {}).get('redactionCount')) for e in events]}")

    alerts = alerts_tail.new_alerts(timeout_s=30)
    if not any(a.get("rule_id") == "output_redaction" and a.get("action") == "observed" for a in alerts):
        fails.append(f"secplane_alert 没找到 output_redaction/observed 行，实际新增 {len(alerts)} 条")

    return CaseResult(name=name, passed=not fails, failures=fails)
