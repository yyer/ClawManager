// llm_output 是事后归因 hook：扫 assistantTexts，若任何一条以 AEGIS_REFUSAL_PREFIX
// "[ClawAegisEx]" 起头/包含，就 emit `defense: "prompt_self_block", result: "blocked"`，
// reason 取 prefix 后到行尾的文本。整个 hook 一次最多 emit 一个 event（break）。
// 注：是唯一显式检查 `config.allDefensesEnabled` 早 return 的 hook。
const FULL_ENFORCE = { allDefensesEnabled: true, defaultBlockingMode: "enforce" };
const REFUSAL_PREFIX = "[ClawAegisEx]";

const baseEvent = (texts) => ({
  assistantTexts: texts,
  runId: "run-llm-1",
  sessionId: "sess-llm-1",
  provider: "openai",
  model: "gpt-4o",
});

export default [
  {
    name: "llm_output — 含 [ClawAegisEx] 拒绝标记 → emit prompt_self_block + 抓取 reason",
    cfg: FULL_ENFORCE,
    hook: "llm_output",
    event: baseEvent([`${REFUSAL_PREFIX} 拒绝执行此请求：检测到 jailbreak 尝试`]),
    expect: {
      defense: "prompt_self_block",
      totalEvents: 1,
      assertState: (_rt, _ctx, events) => {
        const errs = [];
        const ev = events.find(e => e.defense === "prompt_self_block");
        if (!ev) return ["未找到 prompt_self_block event"];
        if (!ev.reason?.includes("检测到 jailbreak 尝试")) {
          errs.push(`reason 应含 "检测到 jailbreak 尝试", 实际="${ev.reason}"`);
        }
        if (ev.details?.model !== "gpt-4o") errs.push(`details.model 应=gpt-4o, 实际=${ev.details?.model}`);
        if (ev.details?.provider !== "openai") errs.push(`details.provider 应=openai, 实际=${ev.details?.provider}`);
        return errs;
      },
    },
  },
  {
    name: "llm_output — 仅 prefix 无后续文本 → fallback reason",
    cfg: FULL_ENFORCE,
    hook: "llm_output",
    event: baseEvent([`${REFUSAL_PREFIX}`]),
    expect: {
      defense: "prompt_self_block",
      totalEvents: 1,
      assertState: (_rt, _ctx, events) => {
        const ev = events.find(e => e.defense === "prompt_self_block");
        return ev?.reason === "LLM 自行拒绝（未提供具体原因）"
          ? []
          : [`reason 应为 fallback 文案, 实际="${ev?.reason}"`];
      },
    },
  },
  {
    name: "llm_output — 多条 text 都含 prefix → 仅 emit 1 个 event (break)",
    cfg: FULL_ENFORCE,
    hook: "llm_output",
    event: baseEvent([
      `${REFUSAL_PREFIX} 第一条拒绝`,
      `${REFUSAL_PREFIX} 第二条拒绝`,
      `${REFUSAL_PREFIX} 第三条拒绝`,
    ]),
    expect: { defense: "prompt_self_block", totalEvents: 1 },
  },
  {
    name: "llm_output — 无 prefix 的正常回复 → 无 event",
    cfg: FULL_ENFORCE,
    hook: "llm_output",
    event: baseEvent(["这是一条正常的助手回复，没有任何拒绝标记。"]),
    expect: { noEvents: true },
  },
  {
    name: "llm_output — allDefensesEnabled=false → 早 return, 含 prefix 也不 emit",
    // 注意：必须用对象覆写 user_config.json 里的 allDefensesEnabled。
    cfg: { ...FULL_ENFORCE, allDefensesEnabled: false },
    hook: "llm_output",
    event: baseEvent([`${REFUSAL_PREFIX} 拒绝执行`]),
    expect: { noEvents: true },
  },
  {
    name: "llm_output — prefix 出现在 text 中部（非行首）→ 仍命中",
    cfg: FULL_ENFORCE,
    hook: "llm_output",
    event: baseEvent([`好的，分析了你的请求后我决定 ${REFUSAL_PREFIX} 不能继续\n详情见下方。`]),
    expect: {
      defense: "prompt_self_block",
      totalEvents: 1,
      assertState: (_rt, _ctx, events) => {
        const ev = events.find(e => e.defense === "prompt_self_block");
        // reason = prefix 之后到换行的内容
        return ev?.reason === "不能继续" ? [] : [`reason 应=不能继续, 实际="${ev?.reason}"`];
      },
    },
  },
];
