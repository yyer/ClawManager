// gateway_start 是 async void hook，只写 state，不返值不写 defense-events.jsonl。
// 主要副作用：
//   1. state.loadPersistentState()  恢复磁盘上的 trusted skills / self-integrity 记录
//   2. selfProtectionEnabled=true  → resolveProtectedRoots(api, stateDir) → state.setProtectedRoots(...)
//   3. selfProtectionEnabled=true  → buildSelfIntegrityRecord + state.setSelfIntegrityRecord
//   4. skillScanEnabled=true        → scanService.start() (+ 可选 startupSkillScan)
//
// 用 assertState 直接读 rt.state.getProtectedRoots / getSelfIntegrityRecord 来验。
const FULL_ENFORCE = { allDefensesEnabled: true, defaultBlockingMode: "enforce" };

export default [
  {
    name: "gateway_start — 默认 cfg → rootDir + stateDir 进 protectedRoots, 有 self-integrity 记录, 0 event",
    cfg: FULL_ENFORCE,
    hook: "gateway_start",
    event: {},
    expect: {
      noEvents: true,
      resultIsUndefined: true,
      assertState: (rt) => {
        const errs = [];
        const roots = rt.state.getProtectedRoots();
        if (!Array.isArray(roots) || roots.length === 0) {
          errs.push(`protectedRoots 应非空, 实际=${JSON.stringify(roots)}`);
        }
        // rootDir 形如 /tmp/aegis-method-a-state/<label>/root，应该在 protectedRoots 里
        if (!roots.some(r => r.endsWith("/root"))) {
          errs.push(`protectedRoots 应含 rootDir (.../root), 实际=${JSON.stringify(roots)}`);
        }
        // stateDir 形如 .../plugins/clawaegisex
        if (!roots.some(r => r.endsWith("/plugins/clawaegisex"))) {
          errs.push(`protectedRoots 应含 stateDir (.../plugins/clawaegisex), 实际=${JSON.stringify(roots)}`);
        }
        const integrity = rt.state.getSelfIntegrityRecord();
        if (!integrity) errs.push(`getSelfIntegrityRecord() 应非空（selfProtection 开时启动应刷新）`);
        return errs;
      },
    },
  },
  {
    name: "gateway_start — 自定义 protectedPaths → 解析进 protectedRoots",
    cfg: { ...FULL_ENFORCE, protectedPaths: ["/etc", "/opt/secret"] },
    hook: "gateway_start",
    event: {},
    expect: {
      noEvents: true,
      assertState: (rt) => {
        const roots = rt.state.getProtectedRoots();
        const errs = [];
        if (!roots.includes("/etc")) errs.push(`protectedRoots 应含 /etc, 实际=${JSON.stringify(roots)}`);
        if (!roots.includes("/opt/secret")) errs.push(`protectedRoots 应含 /opt/secret, 实际=${JSON.stringify(roots)}`);
        return errs;
      },
    },
  },
  {
    name: "gateway_start — protectedSkills + protectedPlugins → stateRoot 下子目录进 protectedRoots",
    cfg: { ...FULL_ENFORCE, protectedSkills: ["clawaegisex"], protectedPlugins: ["clawaegisex"] },
    hook: "gateway_start",
    event: {},
    expect: {
      noEvents: true,
      assertState: (rt) => {
        const roots = rt.state.getProtectedRoots();
        const errs = [];
        if (!roots.some(r => r.endsWith("/skills/clawaegisex"))) {
          errs.push(`期望含 .../skills/clawaegisex, 实际=${JSON.stringify(roots)}`);
        }
        if (!roots.some(r => r.endsWith("/workspace/skills/clawaegisex"))) {
          errs.push(`期望含 .../workspace/skills/clawaegisex, 实际=${JSON.stringify(roots)}`);
        }
        if (!roots.some(r => r.endsWith("/extensions/clawaegisex"))) {
          errs.push(`期望含 .../extensions/clawaegisex, 实际=${JSON.stringify(roots)}`);
        }
        if (!roots.some(r => r.endsWith("/plugins/clawaegisex"))) {
          errs.push(`期望含 .../plugins/clawaegisex, 实际=${JSON.stringify(roots)}`);
        }
        return errs;
      },
    },
  },
  {
    name: "gateway_start — selfProtectionMode=off → protectedRoots 空 + 无 self-integrity 记录",
    cfg: { ...FULL_ENFORCE, selfProtectionMode: "off" },
    hook: "gateway_start",
    event: {},
    expect: {
      noEvents: true,
      assertState: (rt) => {
        const errs = [];
        const roots = rt.state.getProtectedRoots();
        if (roots.length > 0) errs.push(`selfProtection off 时 protectedRoots 应为空, 实际=${JSON.stringify(roots)}`);
        const integrity = rt.state.getSelfIntegrityRecord();
        if (integrity) errs.push(`selfProtection off 时 self-integrity 不应被刷新，实际有记录`);
        return errs;
      },
    },
  },
  {
    name: "gateway_start — 重复调用幂等 → 第二次 protectedRoots 仍正确",
    cfg: FULL_ENFORCE,
    hook: "gateway_start",
    preHooks: [{ hook: "gateway_start", event: {} }],
    event: {},
    expect: {
      noEvents: true,
      assertState: (rt) => {
        const roots = rt.state.getProtectedRoots();
        return Array.isArray(roots) && roots.length > 0
          ? []
          : [`两次 gateway_start 后 protectedRoots 仍应非空, 实际=${JSON.stringify(roots)}`];
      },
    },
  },
];
