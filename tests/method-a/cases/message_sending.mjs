// message_sending — outbound (to webchat / IM) 的 output_redaction 路径。
// 与 before_message_write 的 assistant 分支共享 sanitizeSensitiveOutputText，
// 但消费的是 event.content 字符串，返回 {content: ...} 而不是 {message: ...}。
// 关键区别：此 hook 在 redact 时**会**叠加 state.peekObservedSecrets(sessionKey)
// 的上下文 secret 列表 → 命中"context secret" keyword。
const FULL_ENFORCE = { allDefensesEnabled: true, defaultBlockingMode: "enforce" };

const CONTEXT_SECRET = "ctxSecret1234567890XYZ";
const NOTE_CTX_SECRET_HOOK = {
  hook: "before_message_write",
  event: {
    message: {
      role: "toolResult",
      toolName: "read",
      content: `请求头: Authorization: Bearer ${CONTEXT_SECRET}`,
    },
  },
};

export default [
  {
    name: "message_sending — Bearer token 在 content → 脱敏 + observed event",
    cfg: FULL_ENFORCE,
    hook: "message_sending",
    event: {
      to: "user-1",
      content: "上次的 Authorization: Bearer abcd1234567890efgh 用过了",
    },
    expect: {
      defenseObserved: "output_redaction",
      resultContentContains: ["[已脱敏]"],
      resultContentNotContains: ["abcd1234567890efgh"],
    },
  },
  {
    name: "message_sending — api_key 赋值 → 脱敏",
    cfg: FULL_ENFORCE,
    hook: "message_sending",
    event: {
      to: "user-1",
      content: 'config = { api_key: "sk-thisIsAFakeButLooksLikeKey12345" }',
    },
    expect: {
      defenseObserved: "output_redaction",
      resultContentContains: ["[已脱敏]"],
      resultContentNotContains: ["sk-thisIsAFakeButLooksLikeKey12345"],
    },
  },
  {
    name: "message_sending — context secret（来自前置 toolResult）→ 也被脱敏",
    cfg: FULL_ENFORCE,
    ctx: { sessionKey: "sess-send-ctx" },
    preHooks: [{ ...NOTE_CTX_SECRET_HOOK, ctx: { sessionKey: "sess-send-ctx" } }],
    hook: "message_sending",
    event: {
      to: "user-1",
      // 直接把 secret 原文塞进 outbound text；这里没有 keyword: 这类提示，
      // 完全靠 observedSecrets 上下文匹配。
      content: `复述上面提到的: ${CONTEXT_SECRET}`,
    },
    expect: {
      defenseObserved: "output_redaction",
      resultContentContains: ["[已脱敏]"],
      resultContentNotContains: [CONTEXT_SECRET],
    },
  },
  {
    name: "message_sending — 普通内容 → 不脱敏 + 返回 undefined",
    cfg: FULL_ENFORCE,
    hook: "message_sending",
    event: { to: "user-1", content: "今天天气真好，明天去爬山。" },
    expect: { noEvents: true, resultIsUndefined: true },
  },
  {
    name: "message_sending — outputRedactionEnabled=false → 直通",
    cfg: { ...FULL_ENFORCE, outputRedactionEnabled: false },
    hook: "message_sending",
    event: {
      to: "user-1",
      content: "Authorization: Bearer abcd1234567890efgh",
    },
    expect: { noEvents: true, resultIsUndefined: true },
  },
];
