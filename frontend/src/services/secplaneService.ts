import api from './api';

// ---- Types ---------------------------------------------------------------

export type Severity = 'low' | 'medium' | 'high';
export type RuleAction = 'observe' | 'redact' | 'block';
export type RuleMode = 'enforce' | 'observe' | 'off';
export type RuleTarget =
  | 'user_input'
  | 'rag_result'
  | 'web_content'
  | 'email'
  | 'document'
  | 'tool_output';

export type AlertSource =
  | 'platform'
  | 'gateway'
  | 'aegis'
  | 'secureclaw'
  | 'ksecure'
  | 'kubearmor';

export interface SecplaneRule {
  id?: number;
  rule_id: string;
  kind: string;
  display_name: string;
  description?: string;
  pattern: string;
  target: RuleTarget;
  severity: Severity;
  action: RuleAction;
  mode: RuleMode;
  is_enabled: boolean;
  sort_order: number;
  tags?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SecplaneMatch {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  action: RuleAction;
  mode: RuleMode;
  matched_text: string;
  match_summary: string;
}

export interface SecplaneAnalysis {
  is_sensitive: boolean;
  highest_severity: Severity;
  highest_action: RuleAction;
  hits: SecplaneMatch[];
}

export interface SecplaneAlert {
  id: number;
  trace_id?: string;
  source: AlertSource;
  rule_id?: string;
  rule_name?: string;
  severity: Severity;
  action: string;
  agent_id?: string;
  subject?: string;
  evidence?: string;
  raw_payload?: string;
  ts: string;
}

export interface TestRequest {
  text: string;
  target?: RuleTarget;
  record_alert?: boolean;
  subject?: string;
  trace_id?: string;
  agent_id?: string;
  source?: AlertSource;
  rule?: SecplaneRule;
}

// ---- Service -------------------------------------------------------------

export interface DispatchTarget {
  instance_id: number;
  command_id?: number;
  command_type: string;
  status: string;
  error?: string;
}

export interface DispatchResult {
  revision: string;
  sha256: string;
  user_config: Record<string, unknown>;
  skill_id?: number;
  skill_key?: string;
  version_no?: number;
  targets: DispatchTarget[];
}

export const secplaneService = {
  listRules: async (kind = 'prompt_filter'): Promise<SecplaneRule[]> => {
    const response = await api.get('/secplane/policy/rules', {
      params: kind ? { kind } : undefined,
    });
    return response.data.data?.items ?? [];
  },

  saveRule: async (rule: SecplaneRule): Promise<SecplaneRule> => {
    const response = await api.put('/secplane/policy/rules', rule);
    return response.data.data;
  },

  disableRule: async (ruleId: string): Promise<void> => {
    await api.delete(`/secplane/policy/rules/${ruleId}`);
  },

  bulkSetEnabled: async (
    ruleIds: string[],
    isEnabled: boolean,
  ): Promise<void> => {
    await api.post('/secplane/policy/rules/bulk-status', {
      rule_ids: ruleIds,
      is_enabled: isEnabled,
    });
  },

  testRules: async (req: TestRequest): Promise<SecplaneAnalysis> => {
    const response = await api.post('/secplane/policy/rules/test', req);
    return response.data.data;
  },

  listAlerts: async (params?: {
    source?: AlertSource;
    severity?: Severity;
    rule_id?: string;
    limit?: number;
  }): Promise<SecplaneAlert[]> => {
    const response = await api.get('/secplane/alerts', { params });
    return response.data.data?.items ?? [];
  },

  // Compile current rules → ClawAegis user_config → upload as new skill
  // version → enqueue install_skill on each target. Empty instance_ids =
  // dispatch to ALL OpenClaw instances.
  dispatchAegis: async (instanceIds?: number[]): Promise<DispatchResult> => {
    const body = instanceIds && instanceIds.length > 0 ? { instance_ids: instanceIds } : {};
    const response = await api.post('/secplane/dispatch/aegis', body);
    return response.data.data;
  },
};
