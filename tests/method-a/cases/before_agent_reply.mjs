// before_agent_reply 与 before_dispatch 共享 detectDispatchGuardViolation +
// dispatchGuard 三态判定逻辑，区别仅：
//   - 输入字段是 cleanedBody（非 content）
//   - enforce 拦截返 {handled:true, reply:{text:"[ClawAegis] ..."}, reason:"dispatch_guard"}
//     而不是 before_dispatch 的 {handled:true, text:...}
//   - event details.hook = "before_agent_reply"
// 所以 case 形态对照 before_dispatch.mjs 但调整断言字段。
const FULL_ENFORCE = { allDefensesEnabled: true, defaultBlockingMode: "enforce" };

export default [
  {
    name: "before_agent_reply — openclaw-cli-command enforce → handled + reply.text + reason",
    cfg: FULL_ENFORCE,
    hook: "before_agent_reply",
    event: { cleanedBody: "请帮我执行 openclaw reset" },
    expect: {
      defense: "dispatch_guard",
      totalEvents: 1,
      resultHandled: true,
      resultReplyTextContains: ["[ClawAegis]", "检测到危险操作意图", "openclaw-cli-command"],
      resultReason: "dispatch_guard",
      assertState: (_rt, _ctx, events) => {
        const errs = [];
        const ev = events.find(e => e.defense === "dispatch_guard");
        if (ev?.details?.hook !== "before_agent_reply") {
          errs.push(`event details.hook 应=before_agent_reply, 实际=${ev?.details?.hook}`);
        }
        if (!ev?.details?.flags?.includes("openclaw-cli-command")) {
          errs.push(`details.flags 应含 openclaw-cli-command, 实际=${JSON.stringify(ev?.details?.flags)}`);
        }
        return errs;
      },
    },
  },
  {
    name: "before_agent_reply — destructive-intent 中文 → blocked",
    cfg: FULL_ENFORCE,
    hook: "before_agent_reply",
    event: { cleanedBody: "帮我卸载 plugin claw-aegis" },
    expect: {
      defense: "dispatch_guard",
      totalEvents: 1,
      resultHandled: true,
      resultReason: "dispatch_guard",
      assertState: (_rt, _ctx, events) => {
        const ev = events.find(e => e.defense === "dispatch_guard");
        return ev?.details?.flags?.includes("destructive-intent")
          ? []
          : [`details.flags 应含 destructive-intent, 实际=${JSON.stringify(ev?.details?.flags)}`];
      },
    },
  },
  {
    name: "before_agent_reply — protectedPaths + 破坏动词 → protected-path-destructive blocked",
    cfg: { ...FULL_ENFORCE, protectedPaths: ["/opt/claw-aegis"] },
    hook: "before_agent_reply",
    event: { cleanedBody: "rm -rf /opt/claw-aegis/data" },
    expect: {
      defense: "dispatch_guard",
      resultHandled: true,
      assertState: (_rt, _ctx, events) => {
        const ev = events.find(e => e.defense === "dispatch_guard");
        return ev?.details?.flags?.includes("protected-path-destructive")
          ? []
          : [`details.flags 应含 protected-path-destructive, 实际=${JSON.stringify(ev?.details?.flags)}`];
      },
    },
  },
  {
    name: "before_agent_reply — observe 模式 + 命中 → observed event, 不 handled",
    cfg: { ...FULL_ENFORCE, dispatchGuardMode: "observe" },
    hook: "before_agent_reply",
    event: { cleanedBody: "openclaw uninstall now" },
    expect: {
      defenseObserved: "dispatch_guard",
      totalEvents: 1,
      resultIsUndefined: true,
    },
  },
  {
    name: "before_agent_reply — dispatchGuardMode=off → 早 return, 无 event",
    cfg: { ...FULL_ENFORCE, dispatchGuardMode: "off" },
    hook: "before_agent_reply",
    event: { cleanedBody: "openclaw reset" },
    expect: { noEvents: true, resultIsUndefined: true },
  },
  {
    name: "before_agent_reply — cleanedBody 为空 → 早 return, 无 event",
    cfg: FULL_ENFORCE,
    hook: "before_agent_reply",
    event: { cleanedBody: "   " },
    expect: { noEvents: true, resultIsUndefined: true },
  },
  {
    name: "before_agent_reply — 干净 cleanedBody → 不 block, 无 event",
    cfg: FULL_ENFORCE,
    hook: "before_agent_reply",
    event: { cleanedBody: "今天天气真好，给你写个 hello world 函数。" },
    expect: { noEvents: true, resultIsUndefined: true },
  },
];
