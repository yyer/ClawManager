/**
 * 测试场景4 - 组内用户频繁发布消息识别测试 (reviewer 角色 + 有意义内容)
 * ============================================================
 * 在 team 详情页 (URL: /teams/:id) 的浏览器控制台 (F12 -> Console) 粘贴执行。
 *
 * 发送目标: 默认按 role="reviewer" 自动从 team 详情找 member, 派发给它
 *           (target_member_id = 其 member_key)。也可在 CONFIG.targetMemberId 直接填 member_key 覆盖。
 * 消息内容: 模拟代码审查发现 ("发现潜在空指针:..."), 每条不同, 避免去重且更真实。
 *
 * 原理: POST /api/v1/teams/:id/tasks  body { target_member_id, payload:{ title, prompt } }
 *   后端 collab_quota_throttle 按 (teamId:目标member) 滑动窗口计数:
 *     len(窗口) > xaddRps -> enforce 模式 HTTP 403 拦截 + 告警 (落 secplane_alert)
 *   允许 xaddRps 条, 第 xaddRps+1 条起拦。
 *
 * 注意: 该 API 发送方 from 固定为 clawmanager (登录用户), 无法冒充 member;
 *       target_member_id 指定的是【接收方】。故 "reviewer 角色" = 派发给 reviewer member。
 *
 * mode: serial (默认, 严格串行看清晰拐点) | burst (并发灌入, 大阈值小窗口)
 * 中止: window.__stopFloodTest = true
 */
(async () => {
  const CONFIG = {
    teamId: null,            // null = 从 URL /teams/:id 自动解析;否则填数字
    count: 25,               // 发送总条数
    intervalMs: 30,          // 每条间隔(ms)。serial: 两条之间额外等待; burst: 发送节奏
    targetRole: "reviewer",  // 按 role 自动找目标 member (不区分大小写包含匹配)
    targetMemberId: "",      // 直接指定 member_key;非空则优先,跳过 targetRole
    mode: "serial",          // serial=严格串行(看清晰拐点) | burst=并发灌入(大阈值小窗口)
  };

  // 1) 解析 teamId
  let teamId = CONFIG.teamId;
  if (teamId == null) {
    const m = window.location.pathname.match(/\/teams\/(\d+)/);
    if (!m) { console.error("❌ 无法从 URL 解析 teamId。请打开 /teams/:id 页面,或在 CONFIG.teamId 手动填写。"); return; }
    teamId = m[1];
  }

  // 2) 取 token (登录时写入 localStorage.access_token)
  const token = localStorage.getItem("access_token");
  if (!token) { console.error("❌ localStorage 无 access_token,请先登录。"); return; }

  // 3) (可选) 拉取当前协同策略阈值。注意 teamService 有 10s policy 缓存,刚改完立即跑可能拿旧值
  let xaddRps = 20, windowSecs = 1, quotaMode = "enforce";
  try {
    const r = await fetch("/api/v1/secplane/collab/policy", { headers: { Authorization: `Bearer ${token}` } });
    if (r.ok) {
      const j = await r.json();
      const p = j?.data ?? j;
      xaddRps = p?.xaddRps ?? p?.policy?.xaddRps ?? 20;
      windowSecs = p?.xaddWindowSeconds ?? p?.policy?.xaddWindowSeconds ?? 1;
      quotaMode = p?.quotaMode ?? p?.policy?.quotaMode ?? "enforce";
    }
  } catch (_) { /* 拉不到就用默认值 */ }

  // 4) 解析目标 member (默认 reviewer)
  let targetMemberId = (CONFIG.targetMemberId || "").trim();
  if (!targetMemberId) {
    const r = await fetch(`/api/v1/teams/${teamId}`, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) { console.error(`❌ 拉取 team 详情失败: HTTP ${r.status}`); return; }
    const j = await r.json();
    const team = j?.data ?? j;
    const members = team?.members ?? [];
    if (!members.length) { console.error("❌ 该 team 没有 member。"); return; }
    console.log("  team members:");
    members.forEach((m) => console.log(`    - role=${m.role || "?"}  member_key=${m.member_key}  name=${m.display_name || m.name || ""}`));
    const found = members.find((m) => String(m.role || "").toLowerCase().includes(CONFIG.targetRole.toLowerCase()));
    if (!found) {
      console.error(`❌ 没找到 role 含 "${CONFIG.targetRole}" 的 member。请把对应 member_key 填到 CONFIG.targetMemberId 后重跑。`);
      return;
    }
    targetMemberId = found.member_key;
    console.log(`  → 选中目标: role=${found.role}  member_key=${found.member_key}`);
  }

  console.log(
    `%c[频繁消息测试] team=${teamId} mode=${CONFIG.mode} ${quotaMode} 阈值=${xaddRps}条/${windowSecs}s  发送=${CONFIG.count}条 @${CONFIG.intervalMs}ms  目标=${targetMemberId}`,
    "color:#0a0;font-weight:bold"
  );
  console.log(`  发送节奏: ${CONFIG.count} 条耗时约 ${(CONFIG.count * CONFIG.intervalMs / 1000).toFixed(2)}s (policy 缓存 10s,刚改完立即跑可能拿到旧值)`);

  // 5) 消息内容生成器: 模拟代码审查发现, 每条不同
  const FINDINGS = [
    (v, n) => `发现潜在空指针:变量 ${v} 在第 ${n} 行未判空即使用`,
    (v, n) => `命名不规范:函数 ${v} 不符合驼峰命名约定`,
    (v, n) => `缺少错误处理:${v}() 调用未检查返回错误`,
    (v, n) => `潜在并发问题:共享变量 ${v} 未加锁访问`,
    (v, n) => `硬编码凭证:在 ${v} 处发现明文密码`,
    (v, n) => `资源未释放:${v} 未在 defer 中关闭`,
    (v, n) => `逻辑缺陷:${v} 的边界条件处理缺失`,
    (v, n) => `SQL 注入风险:${v} 直接拼接用户输入`,
    (v, n) => `日志缺失:${v} 异常路径未记录日志`,
    (v, n) => `重复代码:${v} 与现有实现重复,建议抽取`,
  ];
  const VARS = ["ctx", "req", "resp", "data", "cfg", "node", "buf", "item", "val", "ptr", "idx", "conn", "msg", "err"];
  const genFinding = (i) => {
    const tpl = FINDINGS[i % FINDINGS.length];
    const v = VARS[(i * 7 + 3) % VARS.length] + (i % 5); // 加序号保证变量名不重复
    const n = 100 + ((i * 13) % 400);                    // 行号
    return tpl(v, n);
  };

  // 6) 发送
  const url = `/api/v1/teams/${teamId}/tasks`;
  const results = new Array(CONFIG.count).fill(null);
  window.__stopFloodTest = false;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // 把后端英文 reason 翻成中文可读 (去掉 XADD 等 redis 术语)
  // "XADD rate 13 in 10s exceeds limit 2" -> "10秒内已发送13条,超过上限2条,触发限流拦截"
  const humanizeReason = (reason) => {
    const m = /rate\s+(\d+)\s+in\s+(\d+)s\s+exceeds\s+limit\s+(\d+)/.exec(reason || "");
    if (m) return `${m[2]}秒内已发送${m[1]}条,超过上限${m[3]}条,触发限流拦截`;
    return reason || "";
  };

  const sendOne = (i) => {
    const finding = genFinding(i);
    const body = {
      target_member_id: targetMemberId,
      payload: { title: `代码审查发现 #${i + 1}`, prompt: finding },
    };
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    })
      .then(async (res) => {
        const text = await res.text();
        let json = null; try { json = JSON.parse(text); } catch (_) {}
        if (res.status === 201) results[i] = { ok: true, status: 201, finding };
        else if (res.status === 403 && json?.data?.rule_id === "collab_quota_throttle")
          results[i] = { blocked: true, status: 403, reason: json.data.reason, finding };
        else if (res.status === 403)
          results[i] = { blocked: true, status: 403, reason: text, finding };
        else
          results[i] = { other: true, status: res.status, body: text, finding };
      })
      .catch((e) => { results[i] = { error: true, reason: String(e), finding }; });
  };

  const t0 = performance.now();
  if (CONFIG.mode === "burst") {
    const pending = [];
    for (let i = 0; i < CONFIG.count; i++) {
      if (window.__stopFloodTest) { console.log("⏹ 已中止"); break; }
      pending.push(sendOne(i));
      if (i < CONFIG.count - 1) await sleep(CONFIG.intervalMs);
    }
    await Promise.allSettled(pending);
  } else {
    // 串行: 等每条响应再发下一条, 保证窗口按发送顺序累积
    for (let i = 0; i < CONFIG.count; i++) {
      if (window.__stopFloodTest) { console.log("⏹ 已中止"); break; }
      await sendOne(i);
      if (i < CONFIG.count - 1 && CONFIG.intervalMs > 0) await sleep(CONFIG.intervalMs);
    }
  }
  const dur = ((performance.now() - t0) / 1000).toFixed(2);

  // 7) 按顺序打印 + 汇总
  const stat = { ok201: 0, blocked403: 0, other: 0, error: 0 };
  let firstBlock = -1, lastAllowed = -1, lastBlock = -1;
  results.forEach((r, i) => {
    if (!r) return;
    if (r.ok) { stat.ok201++; lastAllowed = i + 1; console.log(`  #${i + 1} ✅ 201  ${r.finding}`); }
    else if (r.blocked) {
      stat.blocked403++;
      if (firstBlock < 0) firstBlock = i + 1;
      lastBlock = i + 1;
      console.log(`  #${i + 1} 🚫 403 ${humanizeReason(r.reason)}`);
    }
    else if (r.error) { stat.error++; console.warn(`  #${i + 1} ⚠️ 网络错误 ${r.reason}`); }
    else { stat.other++; console.warn(`  #${i + 1} ⚠️ ${r.status} ${r.body}`); }
  });

  // 序列图: 一眼看出拐点
  const seq = results.map((r) => {
    if (!r) return "·";
    if (r.ok) return "✓";
    if (r.blocked) return "✗";
    if (r.error) return "!";
    return "?";
  }).join("");
  const legend = "(✓=201 ✗=403 !=网络错误 ?=其他 ·=未发出)";

  console.log(`%c完成 耗时 ${dur}s`, "color:#0a0;font-weight:bold");
  console.table(stat);
  console.log(`  序列: ${seq}  ${legend}`);
  if (firstBlock > 0) {
    console.log(`%c✅ 已识别频繁消息 (quotaMode=${quotaMode} -> HTTP 403)`, "color:#0a0;font-weight:bold");
    console.log(`   实际拐点: 前 ${lastAllowed} 条通过 (#1-${lastAllowed}), 第 ${firstBlock}-${lastBlock} 条被拦截`);
    console.log(`   耗时: ${dur}s | 参考阈值: ${xaddRps}条/${windowSecs}s (滑动窗口计数,实际拐点可能因窗口边界/缓存而略有差异)`);
  } else {
    console.log(`ℹ️ 本次未触发 403,可能原因:`);
    if (quotaMode !== "enforce") console.log(`   • quotaMode=${quotaMode} (非 enforce,只告警不拦)`);
    if (CONFIG.mode === "serial" && CONFIG.intervalMs > 0 && CONFIG.intervalMs >= windowSecs * 1000)
      console.log(`   • serial 间隔 ${CONFIG.intervalMs}ms ≥ 窗口 ${windowSecs * 1000}ms,滑动窗口内累积未超阈值`);
    if (CONFIG.mode === "burst")
      console.log(`   • burst 模式下请求分散到不同窗口,可能没在同一窗口内堆到阈值`);
    if (CONFIG.count <= xaddRps) console.log(`   • count(${CONFIG.count}) ≤ 阈值 ${xaddRps}`);
    console.log(`   调 CONFIG: 加大 count、减小 intervalMs、或把阈值改小后重试`);
  }
  console.log(`下一步: 去「告警/安全事件」界面,或查 secplane_alert 表 (rule_id=collab_quota_throttle / rate_limit_exceeded) 确认告警已记录。`);
})();
