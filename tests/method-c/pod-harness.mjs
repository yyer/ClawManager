// Method-C harness — 在 pod 内跑，import pod 上 install_skill 真部署的 ClawAegis。
// 跟 method-a 的 harness 99% 一样，仅 import 路径不同 + STATE_ROOT 走 pod /tmp。
//
// 调用方式（在 pod 里）:
//   node /usr/local/lib/node_modules/openclaw/method-c-test/harness.mjs [filter]
//
// env 覆盖:
//   METHOD_C_AEGIS_PATH  — 默认 /config/.openclaw/extensions/claw-aegis
//   METHOD_C_STATE_ROOT  — 默认 /tmp/aegis-method-c-state
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const POD_AEGIS = process.env.METHOD_C_AEGIS_PATH ?? "/config/.openclaw/extensions/claw-aegis";
const STATE_ROOT = process.env.METHOD_C_STATE_ROOT ?? "/tmp/aegis-method-c-state";

// pod 上 .js 是 stale 编译产物（不含 before_dispatch / 仍有 outbound_trust），
// 跟 .ts 不同步；openclaw 实际 load 的是 .ts。所以 method-c 也必须 import .ts。
// 用 tsx 跑这个 harness 就能 import .ts 路径下游也 transpile。
const handlersPath = path.join(POD_AEGIS, "src/handlers.ts");
if (!fs.existsSync(handlersPath)) {
  console.error(`pod ClawAegis 不存在: ${handlersPath}`);
  console.error(`确认 instance 跑过 dispatch（install_skill 把 sources 落地）`);
  process.exit(2);
}
const { createClawAegisRuntime } = await import(pathToFileURL(handlersPath).href);

function makeRuntime(userConfig, caseLabel, apiOverride) {
  const safeLabel = caseLabel.replace(/[^a-z0-9-]+/gi, "_").slice(0, 32);
  const stateRoot = path.join(STATE_ROOT, `${safeLabel}-${Math.random().toString(36).slice(2, 6)}`);
  const rootDir = path.join(stateRoot, "root");
  fs.mkdirSync(rootDir, { recursive: true });
  fs.writeFileSync(path.join(rootDir, "user_config.json"), JSON.stringify(userConfig));
  const logs = [];
  const fakeApi = {
    rootDir,
    pluginConfig: {},
    config: { plugins: { entries: { "claw-aegis": { enabled: true } } } },
    logger: {
      debug: (m, meta) => logs.push(["debug", m, meta]),
      info:  (m, meta) => logs.push(["info",  m, meta]),
      warn:  (m, meta) => logs.push(["warn",  m, meta]),
      error: (m, meta) => logs.push(["error", m, meta]),
    },
    runtime: { state: { resolveStateDir: () => stateRoot } },
    on: () => {},
    getPluginConfig: () => undefined,
    resolvePath: (p) => path.resolve(p),
    ...(apiOverride ?? {}),
  };
  return { rt: createClawAegisRuntime(fakeApi), stateRoot, logs };
}

function readEvents(stateRoot) {
  const p = path.join(stateRoot, "plugins", "claw-aegis", "defense-events.jsonl");
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map(l => JSON.parse(l));
}

async function loadCases() {
  const casesDir = path.join(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname), "cases");
  const files = fs.readdirSync(casesDir).filter(f => f.endsWith(".mjs")).sort();
  const all = [];
  for (const f of files) {
    const mod = await import(pathToFileURL(path.join(casesDir, f)).href);
    const arr = mod.default;
    if (!Array.isArray(arr)) {
      console.error(`case 文件 ${f} 没有 default-export 数组，跳过`);
      continue;
    }
    for (const c of arr) all.push({ ...c, _file: f });
  }
  return all;
}

async function runOne(c, idx) {
  const { rt, stateRoot, logs } = makeRuntime(c.cfg, c.name, c.apiOverride);
  const hookName = c.hook ?? "before_tool_call";
  const handler = rt.hooks[hookName];
  if (typeof handler !== "function") {
    return { name: c.name, failures: [`hook ${hookName} 不存在`], events: [], result: null };
  }
  const ctx = c.ctx ?? { sessionKey: `sess-${idx}`, runId: `run-${idx}` };
  for (const ph of c.preHooks ?? []) {
    const h = rt.hooks[ph.hook];
    if (typeof h !== "function") {
      return { name: c.name, failures: [`preHook ${ph.hook} 不存在`], events: [], result: null };
    }
    const phMaybe = h(ph.event, ph.ctx ?? ctx);
    if (phMaybe && typeof phMaybe.then === "function") await phMaybe;
  }
  const maybe = handler(c.event, ctx);
  const result = maybe && typeof maybe.then === "function" ? await maybe : maybe;
  await new Promise(r => setTimeout(r, 50));
  const events = readEvents(stateRoot);
  const failures = [];
  const blocked = Boolean(result?.block);
  if (c.expect.block !== undefined && blocked !== Boolean(c.expect.block)) {
    failures.push(`block 期望=${Boolean(c.expect.block)} 实际=${blocked} reason=${result?.blockReason ?? "-"}`);
  }
  if (c.expect.defense) {
    const ev = events.find(e => e.result === "blocked" && e.defense === c.expect.defense);
    if (!ev) {
      failures.push(`期望 blocked defense=${c.expect.defense}, 实际 events=${JSON.stringify(events.map(e => ({d: e.defense, r: e.result})))}`);
    }
  }
  if (c.expect.defenseObserved) {
    const ev = events.find(e => e.result === "observed" && e.defense === c.expect.defenseObserved);
    if (!ev) {
      failures.push(`期望 observed defense=${c.expect.defenseObserved}, 实际 events=${JSON.stringify(events.map(e => ({d: e.defense, r: e.result})))}`);
    }
  }
  if (c.expect.noEvents) {
    if (events.length > 0) {
      failures.push(`期望 0 个 event, 实际 ${events.length}: ${JSON.stringify(events.map(e => ({d: e.defense, r: e.result})))}`);
    }
  }
  if (c.expect.resultMessageContains) {
    const text = JSON.stringify(result?.message ?? null);
    for (const sub of c.expect.resultMessageContains) {
      if (!text.includes(sub)) {
        failures.push(`期望返回 message 包含 "${sub}", 实际=${text.slice(0, 200)}`);
      }
    }
  }
  if (c.expect.resultContentContains) {
    const text = typeof result?.content === "string" ? result.content : JSON.stringify(result?.content ?? null);
    for (const sub of c.expect.resultContentContains) {
      if (!text.includes(sub)) {
        failures.push(`期望返回 content 包含 "${sub}", 实际=${text.slice(0, 200)}`);
      }
    }
  }
  if (c.expect.resultContentNotContains) {
    const text = typeof result?.content === "string" ? result.content : JSON.stringify(result?.content ?? null);
    for (const sub of c.expect.resultContentNotContains) {
      if (text.includes(sub)) {
        failures.push(`期望返回 content 不包含 "${sub}", 实际=${text.slice(0, 200)}`);
      }
    }
  }
  if (typeof c.expect.assertState === "function") {
    try {
      const stateFailures = c.expect.assertState(rt, ctx, events) ?? [];
      for (const f of stateFailures) failures.push(`assertState: ${f}`);
    } catch (e) {
      failures.push(`assertState threw: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (c.expect.resultTextContains) {
    const text = typeof result?.text === "string" ? result.text : JSON.stringify(result?.text ?? null);
    for (const sub of c.expect.resultTextContains) {
      if (!text.includes(sub)) {
        failures.push(`期望返回 text 包含 "${sub}", 实际=${text.slice(0, 200)}`);
      }
    }
  }
  if (c.expect.resultHandled !== undefined) {
    const handled = result?.handled === true;
    if (handled !== c.expect.resultHandled) {
      failures.push(`期望 result.handled=${c.expect.resultHandled} 实际=${handled} (full result=${(JSON.stringify(result) ?? "undefined").slice(0, 200)})`);
    }
  }
  if (c.expect.resultReplyTextContains) {
    const text = typeof result?.reply?.text === "string" ? result.reply.text : JSON.stringify(result?.reply ?? null);
    for (const sub of c.expect.resultReplyTextContains) {
      if (!text.includes(sub)) {
        failures.push(`期望返回 reply.text 包含 "${sub}", 实际=${text.slice(0, 200)}`);
      }
    }
  }
  if (c.expect.resultReason !== undefined) {
    if (result?.reason !== c.expect.resultReason) {
      failures.push(`期望 result.reason="${c.expect.resultReason}" 实际="${result?.reason}"`);
    }
  }
  if (typeof c.expect.totalEvents === "number") {
    if (events.length !== c.expect.totalEvents) {
      failures.push(`期望 events 数量=${c.expect.totalEvents}, 实际=${events.length}: ${JSON.stringify(events.map(e => ({d: e.defense, r: e.result})))}`);
    }
  }
  if (c.expect.resultIsUndefined && result !== undefined) {
    failures.push(`期望 result === undefined, 实际=${JSON.stringify(result).slice(0, 200)}`);
  }
  if (c.expect.resultPrependContextNonEmpty) {
    const v = result?.prependSystemContext;
    if (typeof v !== "string" || v.length === 0) {
      failures.push(`期望 result.prependSystemContext 非空字符串, 实际=${typeof v} len=${v?.length ?? 0}`);
    }
  }
  if (c.expect.resultPrependContextContains) {
    const v = result?.prependSystemContext ?? "";
    for (const sub of c.expect.resultPrependContextContains) {
      if (!v.includes(sub)) {
        failures.push(`期望 result.prependSystemContext 包含 "${sub}", 实际开头=${v.slice(0, 200)}`);
      }
    }
  }
  return { name: c.name, failures, events, result, logs };
}

async function main() {
  fs.rmSync(STATE_ROOT, { recursive: true, force: true });
  fs.mkdirSync(STATE_ROOT, { recursive: true });
  // ClawAegis userConfigCandidatePaths 优先级: ~/.openclaw/workspace/skills/claw-aegis/user_config.json
  // 高于 <rootDir>/user_config.json。pod 上这条路径已有 method-b 上次 dispatch 留下的 cfg →
  // 我们 fake 的 rootDir cfg 完全被覆盖。把 HOME 指到隔离 STATE_ROOT 让首候选不存在。
  process.env.HOME = STATE_ROOT;
  console.log(`[method-c] pod-installed ClawAegis: ${POD_AEGIS}`);
  console.log(`[method-c] HOME 临时改为 ${STATE_ROOT} 避免上次 dispatch 的 user_config 污染`);
  const filter = process.argv[2];
  let all = await loadCases();
  if (filter) {
    all = all.filter(c => c.name.includes(filter) || c._file.includes(filter));
    if (all.length === 0) {
      console.error(`filter "${filter}" 没匹配到 case`);
      process.exit(2);
    }
  }
  let passed = 0;
  for (let i = 0; i < all.length; i++) {
    const r = await runOne(all[i], i);
    if (r.failures.length === 0) {
      passed++;
      console.log(`PASS  [${i + 1}/${all.length}] ${r.name}`);
    } else {
      console.log(`FAIL  [${i + 1}/${all.length}] ${r.name}`);
      for (const f of r.failures) console.log("        ", f);
    }
  }
  console.log(`\n${passed}/${all.length} passed`);
  process.exit(passed === all.length ? 0 : 1);
}

main().catch(err => { console.error(err); process.exit(2); });
