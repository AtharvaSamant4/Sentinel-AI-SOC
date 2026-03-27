export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ActionResult = {
  action_id: string;
  action: string;
  status: string;
  target: string;
  message?: string;
};

export type ThreatEvent = {
  timestamp: string;
  source_ip: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  event_type: string;
  status: string;
  username?: string | null;
  country?: string;
  is_attack?: boolean;
  attack_type: string;
  attempted_attack_type?: string;
  anomaly_score: number;
  risk_score: number;
  score_breakdown?: Array<{
    label: string;
    points: number;
  }>;
  severity: Severity;
  mitre?: {
    technique: string;
    tactic: string;
  };
  reason?: string;
  analysis?: string;
  dwell_seconds?: number;
  event_count?: number;
  is_persistent?: boolean;
  actions?: ActionResult[];
  auto_detected?: boolean;
  analysis_mode?: string;
  threat_actor?: {
    name: string;
    aka: string;
    origin: string;
    description: string;
    confidence: string;
  } | null;
  ip_intel?: {
    abuse_score: number;
    total_reports: number;
    last_reported: string;
    country: string;
    is_mock: boolean;
  } | null;
  ip_reputation?: {
    abuseConfidenceScore: number;
    totalReports: number;
    lastReportedAt: string;
    countryCode: string;
    isWhitelisted: boolean;
    source: "abuseipdb" | "mock";
  } | null;
  kill_chain?: {
    stage_order: string[];
    active_stages: Array<{
      stage: string;
      trigger_event: string;
      activated_at: string;
      just_activated: boolean;
    }>;
    active_stage_names: string[];
    active_count: number;
    campaign_active: boolean;
  } | null;
};

export type ResponseFiredEvent = {
  type: "response_fired";
  timestamp: string;
  source_ip?: string;
  attack_type?: string;
  severity?: Severity;
  actions: string[];
  counterfactual?: {
    title: string;
    text: string;
    badge: string;
  } | null;
};

export type CounterfactualPanel = {
  id: string;
  source_ip: string;
  attack_type: string;
  title: string;
  text: string;
  badge: string;
  timestamp: string;
  next_move: string;
  at_risk: string;
  time_to_breach: string;
  blast_radius: string;
  hovered?: boolean;
};

export type CoordinatedCampaignEvent = {
  type: "campaign_detected";
  timestamp: string;
  vector_count: number;
  attack_types: string[];
  source_countries: string[];
  confidence: "HIGH" | "MEDIUM";
  analysis?: string;
};

export type MetricState = {
  critical: number;
  high: number;
  blockedIps: number;
  failedLogins: number;
};

export type TrafficPoint = {
  second: string;
  normal: number;
  anomaly: number;
};

export type ClassificationState = {
  BRUTE_FORCE: number;
  PORT_SCAN: number;
  PHISHING: number;
  OTHERS: number;
};

export type ToastEvent = {
  id: string;
  text: string;
  level: "critical" | "high";
};

export type ResponseToast = {
  id: string;
  title: string;
  lines: string[];
  exiting?: boolean;
};

export type DwellEntry = {
  first_seen: string;
  last_seen: string;
  count: number;
  dwell_seconds: number;
  is_persistent: boolean;
};

export type UserBehaviorAnomalyEvent = {
  username: string;
  timestamp: string;
  severity: Severity;
  source_ip: string;
  attack_type: string;
  anomaly_score: number;
};
