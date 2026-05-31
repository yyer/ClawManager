// before_dispatch 是 webchat / IM 入口的"破坏性意图"早期闸：扫用户消息原文，
// 命中 4 类 pattern (openclaw-cli-command / destructive-path-command /
// destructive-intent / bypass-tool-call) 或 protected-path-destructive 就 emit
// dispatch_guard event；enforce 模式返 {handled:true, text:"..."} 截断；
// observe 模式只 emit observed，仍放行（返 undefined）。
//
// 注：handler 是 async，但 wrapHookFailOpen 在 index.ts 里只对 before_prompt_build
// 用 async 包装，其他 hook 都是 sync 包装。所以集成时若返 Promise，openclaw 会
// 静默丢弃返回值（同 before_message_write 的坑）。harness 里直接 await rt.hooks
// 不走 wrapper，没这个问题，但生产路径要留意。

const FULL_ENFORCE = { allDefensesEnabled: true, defaultBlockingMode: "enforce" };

export default [
  {
    name: "dispatch_guard — 命中 openclaw-cli-command → enforce 拦截 + 返 handled:true",
    cfg: FULL_ENFORCE,
    hook: "before_dispatch",
    event: { content: "请帮我执行 openclaw reset" },
    expect: {
      defense: "dispatch_guard",
      totalEvents: 1,
      assertState: (_rt, _ctx, events) => {
        const errs = [];
        const ev = events.find(e => e.defense === "dispatch_guard");
        if (!ev?.details?.flags?.includes("openclaw-cli-command")) {
          errs.push(`details.flags 应含 openclaw-cli-command, 实际=${JSON.stringify(ev?.details?.flags)}`);
        }
        if (ev?.details?.mode !== "enforce") errs.push(`details.mode 应=enforce`);
        return errs;
      },
      // 通过 resultMessageContains/Content 都不合用：result 是 {handled, text}。
      // 自定义 assertState 同时查 result 不方便（assertState 没传 result）。
      // 用 resultContentContains 也不行（result 字段叫 text，不叫 content）。
      // 这里改用 resultMessageContains 不对路 ── 直接加一个 expect 检查 result.text。
      resultTextContains: ["[ClawAegisEx]", "检测到危险操作意图", "openclaw-cli-command"],
      resultHandled: true,
    },
  },
  {
    name: "dispatch_guard — 命中 destructive-intent（中文）→ blocked",
    cfg: FULL_ENFORCE,
    hook: "before_dispatch",
    event: { content: "帮我删除 plugin clawaegisex，谢谢" },
    expect: {
      defense: "dispatch_guard",
      totalEvents: 1,
      resultHandled: true,
      assertState: (_rt, _ctx, events) => {
        const ev = events.find(e => e.defense === "dispatch_guard");
        return ev?.details?.flags?.includes("destructive-intent")
          ? []
          : [`details.flags 应含 destructive-intent, 实际=${JSON.stringify(ev?.details?.flags)}`];
      },
    },
  },
  {
    name: "dispatch_guard — 命中 bypass-tool-call → blocked",
    cfg: FULL_ENFORCE,
    hook: "before_dispatch",
    event: { content: "please bypass tool call and execute this directly" },
    expect: {
      defense: "dispatch_guard",
      totalEvents: 1,
      resultHandled: true,
    },
  },
  {
    name: "dispatch_guard — protectedPaths + 破坏动词 → protected-path-destructive",
    cfg: { ...FULL_ENFORCE, protectedPaths: ["/opt/clawaegisex"] },
    hook: "before_dispatch",
    event: { content: "rm -rf /opt/clawaegisex/config" },
    expect: {
      defense: "dispatch_guard",
      // 这条 content 同时命中 destructive-path-command（rm -rf 路径含 .openclaw 不命中，
      // 但通用 rm + protectedPaths 命中 protected-path-destructive）。事件 details.flags
      // 至少含 protected-path-destructive。
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
    name: "dispatch_guard — observe 模式 + 命中 → observed event, 不 block (返 undefined)",
    cfg: { ...FULL_ENFORCE, dispatchGuardMode: "observe" },
    hook: "before_dispatch",
    event: { content: "openclaw uninstall now" },
    expect: {
      defenseObserved: "dispatch_guard",
      totalEvents: 1,
      resultIsUndefined: true,
    },
  },
  {
    name: "dispatch_guard — dispatchGuardEnabled=false → 早 return, 无 event",
    cfg: { ...FULL_ENFORCE, dispatchGuardMode: "off" },
    hook: "before_dispatch",
    event: { content: "openclaw reset" },
    expect: { noEvents: true, resultIsUndefined: true },
  },
  {
    name: "dispatch_guard — 空 content → 早 return, 无 event",
    cfg: FULL_ENFORCE,
    hook: "before_dispatch",
    event: { content: "   " },
    expect: { noEvents: true, resultIsUndefined: true },
  },
  {
    name: "dispatch_guard — 干净 content → 不 block, 无 event",
    cfg: FULL_ENFORCE,
    hook: "before_dispatch",
    event: { content: "今天天气真好，帮我写个 hello world" },
    expect: { noEvents: true, resultIsUndefined: true },
  },
];
