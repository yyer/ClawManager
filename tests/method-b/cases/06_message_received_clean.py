"""Case 06: 普通内容（无任何 risk pattern）→ message_received 跑但 result=clear, 无 event 无 alert。

method-a 的 "普通内容无命中 → 无 event"。
"""
from harness import Harness, CaseResult


def run(h: Harness) -> CaseResult:
    name = "06_message_received_clean"
    fails: list[str] = []

    h.set_user_risk_rules(
        scan_enabled=True,
        flag_rules=[{"flag": "jailbreak-bypass", "is_enabled": True, "mode": "enforce"}],
    )
    h.dispatch_and_wait_hot_reload()

    events_tail, alerts_tail = h.fresh_observer()
    trigger = "今天天气真好，帮我写个 hello world 函数"
    ws = h.wschat.send(trigger)
    if not ws.get("ok"):
        return CaseResult(name=name, passed=False, failures=[f"WS 失败: {ws}"])

    events = events_tail.new_events(timeout_s=5)
    bad = [e for e in events if e.get("defense") == "user_risk_scan"]
    if bad:
        fails.append(f"clean 内容不应触 user_risk_scan event，实际 {bad}")

    alerts = alerts_tail.new_alerts(timeout_s=4)
    bad_a = [a for a in alerts if a.get("rule_id") == "user_risk_scan"]
    if bad_a:
        fails.append(f"clean 内容不应进 secplane_alert，实际 {len(bad_a)} 条")

    return CaseResult(name=name, passed=not fails, failures=fails)
