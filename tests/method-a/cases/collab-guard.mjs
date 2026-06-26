// collab_guard defense — 4 sub-rules (identity / schema / quota / approval)
// each tested in enforce / observe / off modes. All cases use a bash tool
// call whose command contains XADD against claw:team:12:inbox:<member>.
const ENFORCE_TEAM_12 = {
  allDefensesEnabled: true,
  defaultBlockingMode: "enforce",
  collabGuardEnabled: true,
  collabGuardMode: "enforce",
  collabTeamId: "12",
  collabIdentityMode: "enforce",
  collabSchemaMode: "enforce",
  collabQuotaMode: "enforce",
  collabApprovalMode: "enforce",
  collabXaddRps: 20,
  collabStreamMaxLen: 1000,
  collabApprovalThreshold: 85,
};

const OBSERVE_TEAM_12 = {
  ...ENFORCE_TEAM_12,
  collabGuardMode: "observe",
  collabIdentityMode: "observe",
  collabSchemaMode: "observe",
  collabQuotaMode: "observe",
  collabApprovalMode: "observe",
};

const OFF_TEAM_12 = {
  ...ENFORCE_TEAM_12,
  collabGuardMode: "off",
  collabIdentityMode: "off",
  collabSchemaMode: "off",
  collabQuotaMode: "off",
  collabApprovalMode: "off",
};

export default [
  {
    name: "collab_guard — identity breach enforce → block + collab_identity_breach",
    cfg: ENFORCE_TEAM_12,
    event: {
      toolName: "shell",
      params: {
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from coder to reviewer ts 1234567890 type msg hello",
      },
    },
    expect: { block: true, defense: "collab_guard" },
  },
  {
    name: "collab_guard — identity ok enforce → clear (sender matches member, to=member)",
    cfg: ENFORCE_TEAM_12,
    event: {
      toolName: "shell",
      params: {
        // to=reviewer (== member), type=msg (not broadcast), sender=reviewer (== member)
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from reviewer to reviewer ts 1234567890 type msg hello",
      },
    },
    expect: { block: false, noEvents: true },
  },
  {
    name: "collab_guard — schema violation observe → observed event collab_schema_violation",
    cfg: { ...OBSERVE_TEAM_12, collabIdentityMode: "off" },
    event: {
      toolName: "shell",
      params: {
        // missing type field → schema violation
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from reviewer to coder ts 1234567890 hello",
      },
    },
    expect: { block: false, defenseObserved: "collab_guard" },
  },
  {
    name: "collab_guard — approval required enforce → block (type=broadcast)",
    cfg: { ...ENFORCE_TEAM_12, collabIdentityMode: "off", collabSchemaMode: "off", collabQuotaMode: "off" },
    event: {
      toolName: "shell",
      params: {
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from reviewer to all ts 1234567890 type broadcast hello",
      },
    },
    expect: { block: true, defense: "collab_guard" },
  },
  {
    name: "collab_guard — approval required enforce → block (to != member)",
    cfg: { ...ENFORCE_TEAM_12, collabIdentityMode: "off", collabSchemaMode: "off", collabQuotaMode: "off" },
    event: {
      toolName: "shell",
      params: {
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from reviewer to coder ts 1234567890 type msg hello",
      },
    },
    expect: { block: true, defense: "collab_guard" },
  },
  {
    name: "collab_guard — mode off → no event even with violations",
    cfg: OFF_TEAM_12,
    event: {
      toolName: "shell",
      params: {
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from attacker to all ts 1234567890 type broadcast evil",
      },
    },
    expect: { block: false, noEvents: true },
  },
  {
    name: "collab_guard — non-redis command → clear (appliesTo filters)",
    cfg: ENFORCE_TEAM_12,
    event: {
      toolName: "shell",
      params: { command: "ls -la /tmp" },
    },
    expect: { block: false, noEvents: true },
  },
  {
    name: "collab_guard — wrong team → clear (not our team)",
    cfg: ENFORCE_TEAM_12,
    event: {
      toolName: "shell",
      params: {
        command:
          "redis-cli XADD claw:team:99:inbox:reviewer * from attacker to all ts 1234567890 type broadcast evil",
      },
    },
    expect: { block: false, noEvents: true },
  },
  {
    name: "collab_guard — empty teamId → clear (appliesTo filters)",
    cfg: { ...ENFORCE_TEAM_12, collabTeamId: "" },
    event: {
      toolName: "shell",
      params: {
        command:
          "redis-cli XADD claw:team:12:inbox:reviewer * from attacker to all ts 1234567890 type broadcast evil",
      },
    },
    expect: { block: false, noEvents: true },
  },
];
