import { useEffect, useMemo, useRef, useState } from "react";
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip as ChartTooltip,
} from "chart.js";
import { Bar } from "react-chartjs-2";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ComposableMap, Geographies, Geography } from "react-simple-maps";
import { useSocStream } from "./hooks/useSocStream";
import { useAnalystStream } from "./hooks/useAnalystStream";
import { ThreatEvent } from "./types";

const WS_URL =
  (import.meta.env.VITE_WS_URL as string | undefined) ??
  "ws://localhost:8001/api/events/stream";
const API_BASE =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8001";
const WORLD_MAP_GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

ChartJS.register(CategoryScale, LinearScale, BarElement, ChartTooltip, Legend);

const riskFill = (risk: number): string => {
  if (risk >= 90) return "#ff334f";
  if (risk >= 75) return "#ff8b2c";
  if (risk >= 40) return "#e5d24f";
  return "#3ddc84";
};

const compactTime = (timestamp: string): string => {
  const d = new Date(timestamp);
  return `${d.getHours().toString().padStart(2, "0")}:${d
    .getMinutes()
    .toString()
    .padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
};

const prettifyAttackType = (value: string): string =>
  String(value || "UNKNOWN")
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const COUNTRY_POINTS: Record<string, { x: number; y: number }> = {
  US: { x: 22, y: 35 },
  CA: { x: 19, y: 22 },
  MX: { x: 17, y: 46 },
  BR: { x: 32, y: 67 },
  AR: { x: 30, y: 82 },
  GB: { x: 47, y: 28 },
  FR: { x: 48, y: 33 },
  DE: { x: 51, y: 30 },
  ES: { x: 46, y: 37 },
  NL: { x: 50, y: 29 },
  RU: { x: 68, y: 22 },
  TR: { x: 57, y: 38 },
  IR: { x: 61, y: 40 },
  CN: { x: 77, y: 34 },
  JP: { x: 85, y: 33 },
  IN: { x: 67, y: 46 },
  SG: { x: 76, y: 60 },
  KP: { x: 82, y: 34 },
  UA: { x: 56, y: 31 },
  BY: { x: 55, y: 28 },
  PK: { x: 63, y: 41 },
  SA: { x: 59, y: 46 },
  AU: { x: 82, y: 72 },
  ZA: { x: 54, y: 75 },
  NG: { x: 50, y: 53 },
  EG: { x: 55, y: 42 },
  ID: { x: 79, y: 60 },
  TH: { x: 76, y: 51 },
  VN: { x: 78, y: 50 },
  MX: { x: 17, y: 46 },
};

const hashedPoint = (country: string): { x: number; y: number } => {
  const text = country.toUpperCase();
  const hash = Array.from(text).reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  const x = 14 + (hash % 72);
  const y = 18 + ((hash * 7) % 66);
  return { x, y };
};

const pointForCountry = (country: string): { x: number; y: number } => {
  return COUNTRY_POINTS[country.toUpperCase()] ?? hashedPoint(country);
};

const COUNTRY_LABELS: Record<string, string> = {
  US: "United States",
  CA: "Canada",
  MX: "Mexico",
  BR: "Brazil",
  AR: "Argentina",
  GB: "United Kingdom",
  FR: "France",
  DE: "Germany",
  ES: "Spain",
  NL: "Netherlands",
  RU: "Russia",
  TR: "Turkey",
  IR: "Iran",
  CN: "China",
  JP: "Japan",
  IN: "India",
  SG: "Singapore",
  KP: "North Korea",
  UA: "Ukraine",
  PK: "Pakistan",
  SA: "Saudi Arabia",
  AU: "Australia",
  ZA: "South Africa",
  NG: "Nigeria",
  EG: "Egypt",
  ID: "Indonesia",
  TH: "Thailand",
  VN: "Vietnam",
  BY: "Belarus",
  XX: "Unknown",
};

const countryLabel = (countryCode: string): string => {
  const code = String(countryCode || "XX").toUpperCase();
  return COUNTRY_LABELS[code] ?? code;
};

// Reverse map: "russia" → "RU", "united states" → "US", etc.
const COUNTRY_NAME_TO_CODE: Record<string, string> = Object.fromEntries(
  Object.entries(COUNTRY_LABELS).map(([code, name]) => [name.toLowerCase(), code])
);

const anomalyInterpretation = (
  zScore: number
): { tone: "high" | "medium" | "low"; headline: string } => {
  if (zScore >= 2.5) {
    return { tone: "high", headline: "Very unusual login time" };
  }
  if (zScore >= 1.2) {
    return { tone: "medium", headline: "Somewhat unusual login time" };
  }
  return { tone: "low", headline: "Login time looks normal" };
};

const tooltipStyle = {
  background: "#060f1e",
  border: "1px solid rgba(255,255,255,0.12)",
  borderRadius: "8px",
  color: "#e2e8f0",
  boxShadow: "0 8px 32px rgba(0,0,0,0.65)",
  fontSize: "12px",
};

const tooltipLabelStyle = {
  color: "#94a3b8",
  fontWeight: 600,
  marginBottom: 4,
};

const tooltipItemStyle = {
  color: "#e2e8f0",
  fontWeight: 600,
};

const scoreBreakdown = (threat: ThreatEvent): string => {
  const score = Math.max(0, Math.min(100, Math.round(threat.risk_score || 0)));
  const top3 = (threat.score_breakdown ?? [])
    .filter((item) => item && Number(item.points) > 0)
    .sort((a, b) => Number(b.points) - Number(a.points))
    .slice(0, 3);

  if (top3.length === 0) {
    return "";
  }

  const factors = top3
    .map((item) => `${item.label} (+${Math.max(0, Math.round(Number(item.points) || 0))})`)
    .join(" · ");
  return `Score ${score}: ${factors}`;
};

const formatDwellDuration = (dwellSecondsRaw: number): string => {
  const dwellSeconds = Math.max(0, Math.floor(Number(dwellSecondsRaw || 0)));
  const totalMinutes = Math.floor(dwellSeconds / 60);
  if (totalMinutes < 1) return "< 1 min";
  if (totalMinutes < 60) return `${totalMinutes} min`;

  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours}h ${minutes.toString().padStart(2, "0")}m`;
};

const dwellSummary = (
  dwellSeconds: number,
  count: number,
  isPersistent: boolean
): { label: string; persistent: boolean } => {
  const duration = formatDwellDuration(dwellSeconds);
  const eventLabel = `${Math.max(1, Math.round(Number(count) || 1))} events`;
  return {
    label: isPersistent
      ? `⚠ Persistent — ${duration} · ${eventLabel}`
      : `⏱ Active ${duration} · ${eventLabel}`,
    persistent: isPersistent,
  };
};

const INCIDENT_HEADERS = new Set([
  "EXECUTIVE SUMMARY",
  "TIMELINE OF EVENTS",
  "ATTACK VECTORS IDENTIFIED",
  "ASSETS AT RISK",
  "AUTOMATED ACTIONS TAKEN",
  "RECOMMENDED NEXT STEPS",
]);

const BOARD_BORDER_BY_KEY: Record<string, string> = {
  "THREAT LEVEL": "#FF3B5C",
  "WHAT HAPPENED": "#FF8B2C",
  "DID WE STOP IT": "#00B96A",
  "WHAT'S AT RISK": "#FF8B2C",
  "WHAT WE'RE DOING": "#2F7DF6",
};

type BoardRow = { key: string; value: string };

type DashboardView =
  | "overview"
  | "live"
  | "queue"
  | "progress"
  | "ai"
  | "traffic"
  | "origins"
  | "reports";

type StageHistoryEntry = {
  stage: string;
  event: string;
  source_ip: string;
  time: string;
};

const formatGeneratedAt = (iso: string | null): string => {
  if (!iso) return new Date().toISOString().replace("T", " ").slice(0, 19);
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 19);
};

const parseBoardReport = (text: string): { rows: BoardRow[]; bottomLine: string } => {
  const rows: BoardRow[] = [];
  let bottomLine = "";
  const lines = String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  for (const line of lines) {
    const cleaned = line.replace(/^-\s*/, "");
    const match = cleaned.match(/^([^:]+):\s*(.+)$/);
    if (!match) continue;
    const key = String(match[1] || "").trim().toUpperCase();
    const value = String(match[2] || "").trim();
    if (key === "BOTTOM LINE") {
      bottomLine = value;
      continue;
    }
    rows.push({ key, value });
  }

  return { rows, bottomLine };
};

const KILL_CHAIN_DEFAULT_ORDER = [
  "Reconnaissance",
  "Initial Access",
  "Persistence",
  "Privilege Escalation",
  "Credential Access",
  "Lateral Movement",
  "Command & Control",
  "Exfiltration",
];

const THREAT_NAME_MAP: Record<string, string> = {
  BRUTE_FORCE: "Password Attack",
  PHISHING: "Email Phishing",
  PORT_SCAN: "Network Probe",
  SQL_INJECTION: "Database Attack",
  C2_BEACON: "Remote Control Attempt",
  BLOCKED_SOURCE: "Suspicious Connection Blocked",
  ANOMALOUS_LOGIN: "Suspicious Login",
  DATA_EXFILTRATION: "Data Theft Attempt",
  NORMAL: "Normal Activity",
};

const STAGE_DISPLAY_NAME: Record<string, string> = {
  Reconnaissance: "Scouting",
  "Initial Access": "Breaking In",
  Persistence: "Getting Comfortable",
  "Privilege Escalation": "Escalating Power",
  "Credential Access": "Stealing Credentials",
  "Lateral Movement": "Moving Around",
  "Command & Control": "Phoning Home",
  Exfiltration: "Stealing Data",
};

const plainThreatName = (threatType: string): string => {
  const key = String(threatType || "UNKNOWN").trim().toUpperCase().replace(/\s+/g, "_");
  return THREAT_NAME_MAP[key] ?? prettifyAttackType(key);
};

const eventDescription = (event: ThreatEvent): string => {
  const attackType = String(event.attack_type || "NORMAL").toUpperCase();
  if (attackType === "NORMAL") return "Normal web request";
  if (attackType === "BLOCKED_SOURCE") return "Suspicious connection blocked";
  if (attackType === "BRUTE_FORCE") return "Password attack attempt";
  if (attackType === "PORT_SCAN") return "Port scan detected";
  if (attackType === "PHISHING") return "Phishing delivery attempt detected";
  if (attackType === "SQL_INJECTION") return "Database attack attempt";
  if (attackType === "C2_BEACON") return "Remote control traffic detected";
  return plainThreatName(attackType);
};

const localAnalystFallback = (threat: ThreatEvent | null, query: string): string => {
  const attack = plainThreatName(String(threat?.attack_type || "UNKNOWN"));
  const source = String(threat?.source_ip || "unknown");
  const country = countryLabel(String(threat?.country || "XX"));
  const risk = Math.round(Number(threat?.risk_score || 0));
  const mitre = String(threat?.mitre?.technique || "N/A");
  const cleanedQuery = String(query || "").trim();

  return [
    "Analyst endpoint temporarily unreachable. Showing local fallback guidance.",
    cleanedQuery ? `Question: ${cleanedQuery}` : null,
    `Current threat: ${attack} from ${source} (${country}), risk ${risk}/100, MITRE ${mitre}.`,
    "Immediate actions: keep source blocked, verify target system integrity, and monitor for follow-on attempts from adjacent IP ranges.",
  ]
    .filter(Boolean)
    .join(" ");
};

const isAnalystOutageMessage = (text: string): boolean => {
  const value = String(text || "").toLowerCase();
  if (!value) return false;
  return (
    value.includes("temporarily unavailable") ||
    value.includes("model outage") ||
    value.includes("unable to query analyst") ||
    value.includes("service unavailable")
  );
};

const hasKnownField = (value: unknown): boolean => {
  const text = String(value ?? "").trim().toLowerCase();
  return Boolean(text) && text !== "unknown" && text !== "xx" && text !== "n/a";
};

const isMeaningfulThreat = (
  threat: ThreatEvent | null | undefined
): threat is ThreatEvent => {
  if (!threat) return false;

  const attackType = String(threat.attack_type || "").trim().toUpperCase();
  if (attackType && attackType !== "UNKNOWN" && attackType !== "NORMAL") return true;

  if (Number(threat.risk_score || 0) > 0 || Number(threat.anomaly_score || 0) > 0) return true;
  if (hasKnownField(threat.source_ip) || hasKnownField(threat.destination_ip)) return true;
  if (Number(threat.destination_port || 0) > 0) return true;

  const reason = String(threat.reason || "").trim().toLowerCase();
  if (reason && reason !== "no recent events") return true;
  return false;
};

const stageDisplayName = (stage: string): string => STAGE_DISPLAY_NAME[stage] ?? stage;

const stageTriggerText = (eventType: string): string => {
  const normalized = String(eventType || "").trim().toLowerCase();
  if (normalized.includes("login")) return "Password spray";
  if (normalized.includes("request")) return "Web probe";
  if (normalized.includes("bytes")) return "Outbound transfer";
  if (normalized.includes("connection")) return "Network session";
  return normalized ? normalized.replace(/_/g, " ") : "Threat event";
};

type KillChainStageDetail = {
  eventType: string;
  timestamp: string;
  activatedAtMs: number;
};

const normalizeAttackTag = (threat: ThreatEvent): string => {
  return String(threat.attack_type || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
};

const killChainStageFromThreat = (
  threat: ThreatEvent,
  persistenceActive: boolean
): string | null => {
  const attackTag = normalizeAttackTag(threat);
  const eventType = String(threat.event_type || "").trim().toLowerCase();

  // Breach scenario events carry explicit breach_stage — use it directly
  const breachStage = String((threat as ThreatEvent & { breach_stage?: string }).breach_stage ?? "").toUpperCase();
  if (breachStage) {
    const BREACH_TO_KILL: Record<string, string> = {
      RECONNAISSANCE:       "Reconnaissance",
      INITIAL_ACCESS:       "Initial Access",
      PERSISTENCE:          "Persistence",
      PRIVILEGE_ESCALATION: "Privilege Escalation",
      LATERAL_MOVEMENT:     "Lateral Movement",
      EXFILTRATION:         "Exfiltration",
      IMPACT:               "Exfiltration",
    };
    return BREACH_TO_KILL[breachStage] ?? null;
  }

  if (eventType === "bytes_out" && Number(threat.risk_score || 0) >= 75) return "Exfiltration";
  if (attackTag === "PORT_SCAN") return "Reconnaissance";
  if (attackTag === "PHISHING" || attackTag === "SQL_INJECTION") return "Initial Access";
  if (attackTag === "ANOMALOUS_LOGIN") return "Persistence";
  if (attackTag === "BRUTE_FORCE") return persistenceActive ? "Lateral Movement" : "Credential Access";
  if (attackTag === "C2_BEACON") return "Command & Control";
  if (attackTag === "PRIVILEGE_ESCALATION") return "Privilege Escalation";
  if (attackTag === "LATERAL_MOVEMENT") return "Lateral Movement";
  if (attackTag === "DATA_EXFILTRATION") return "Exfiltration";

  return null;
};

const hoursOfDay = Array.from({ length: 24 }).map((_, idx) => idx);

const baselineForUser = (usernameRaw: string): number[] => {
  const username = usernameRaw.toLowerCase();

  if (username === "admin" || username === "root") {
    return hoursOfDay.map((hour) => (hour >= 9 && hour <= 17 ? 8 : hour >= 7 && hour <= 19 ? 3 : 0));
  }

  if (username === "postgres" || username === "oracle") {
    return hoursOfDay.map((hour) => (hour >= 2 && hour <= 4 ? 8 : hour >= 1 && hour <= 5 ? 3 : 0));
  }

  if (username === "test" || username === "guest") {
    return hoursOfDay.map(() => 2);
  }

  return hoursOfDay.map((hour) => (hour >= 8 && hour <= 18 ? 6 : hour >= 6 && hour <= 20 ? 2 : 0));
};

const deriveUserBaselineFromHistory = (usernameRaw: string, history: ThreatEvent[]): number[] => {
  const username = usernameRaw.toLowerCase();
  const counts = Array.from({ length: 24 }).map(() => 0);
  const fallback = baselineForUser(usernameRaw);

  for (const event of history) {
    if (String(event.event_type || "").toLowerCase() !== "login") continue;
    if (String(event.username || "").toLowerCase() !== username) continue;

    const ts = new Date(String(event.timestamp || ""));
    if (Number.isNaN(ts.getTime())) continue;
    counts[ts.getHours()] += 1;
  }

  const total = counts.reduce((sum, value) => sum + value, 0);
  if (total <= 0) {
    return fallback;
  }

  const smoothed = counts.map((value, hour) => {
    const prev = counts[(hour + 23) % 24];
    const next = counts[(hour + 1) % 24];
    return value * 0.7 + prev * 0.15 + next * 0.15;
  });

  const maxValue = Math.max(...smoothed, 0);
  if (maxValue <= 0) {
    return fallback;
  }

  const scale = 8 / maxValue;
  const historyBaseline = smoothed.map((value) => Number((value * scale).toFixed(1)));

  // Blend toward history as evidence grows to avoid static fallback behavior.
  const alpha = Math.min(1, total / 8);
  return historyBaseline.map((value, idx) => Number((value * alpha + fallback[idx] * (1 - alpha)).toFixed(1)));
};

const stdDeviation = (values: number[]): number => {
  if (values.length === 0) return 0;
  const mean = values.reduce((acc, value) => acc + value, 0) / values.length;
  const variance = values.reduce((acc, value) => acc + (value - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
};

function NavIcon({ kind }: { kind: string }) {
  const baseProps = {
    viewBox: "0 0 24 24",
    width: 18,
    height: 18,
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  if (kind === "overview") return <svg {...baseProps}><rect x="3" y="3" width="8" height="8" /><rect x="13" y="3" width="8" height="5" /><rect x="13" y="10" width="8" height="11" /><rect x="3" y="13" width="8" height="8" /></svg>;
  if (kind === "live") return <svg {...baseProps}><path d="M3 12h4l2-4 4 8 2-4h6" /></svg>;
  if (kind === "queue") return <svg {...baseProps}><path d="M12 3l8 4v6c0 5-3.6 7.8-8 8-4.4-.2-8-3-8-8V7l8-4z" /><path d="M9 12l2 2 4-4" /></svg>;
  if (kind === "progress") return <svg {...baseProps}><path d="M4 18h16" /><path d="M6 16V8" /><path d="M12 16V5" /><path d="M18 16V10" /></svg>;
  if (kind === "ai") return <svg {...baseProps}><rect x="5" y="7" width="14" height="10" rx="3" /><path d="M9 11h.01M15 11h.01" /><path d="M12 7V4" /></svg>;
  if (kind === "traffic") return <svg {...baseProps}><path d="M4 18l4-6 4 3 4-7 4 10" /></svg>;
  if (kind === "origins") return <svg {...baseProps}><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a13 13 0 0 1 0 18" /><path d="M12 3a13 13 0 0 0 0 18" /></svg>;
  return <svg {...baseProps}><path d="M6 3h9l3 3v15H6z" /><path d="M15 3v3h3" /></svg>;
}

function App() {
  const {
    events,
    queue,
    metrics,
    traffic,
    responseToasts,
    dismissResponseToast,
    counterfactualPanels,
    setCounterfactualHover,
    dwellByIp,
    coordinatedCampaign,
    latestAuthAnomaly,
    latestHighRisk,
  } = useSocStream(WS_URL);

  const [theme, setTheme] = useState<"dark" | "light">(() => {
    return (localStorage.getItem("sentinel-theme") as "dark" | "light") ?? "dark";
  });
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);
  const [currentView, setCurrentView] = useState<DashboardView>("overview");
  const [liveSeverityFilter, setLiveSeverityFilter] = useState<"all" | "high" | "medium" | "low">("all");
  const [threatSort, setThreatSort] = useState<"Highest Risk" | "Most Recent" | "Persistent">("Highest Risk");
  const [focusLiveSearch, setFocusLiveSearch] = useState(false);
  const [aiNavPulse, setAiNavPulse] = useState(false);
  const [overrideMode, setOverrideMode] = useState(false);
  const [pendingThreats, setPendingThreats] = useState<Array<{ threat_id: string; source_ip: string; attack_type: string; severity: string; risk_score: number; status: string }>>([]);
  const [hitlBusy, setHitlBusy] = useState<string | null>(null);
  const [dismissedIps, setDismissedIps] = useState<Set<string>>(new Set());
  const [hitlToast, setHitlToast] = useState<{ message: string; type: "approve" | "reject" } | null>(null);
  const [killChainStages, setKillChainStages] = useState<Record<string, KillChainStageDetail>>({});
  const [stageHistory, setStageHistory] = useState<StageHistoryEntry[]>([]);
  const [clockMs, setClockMs] = useState(Date.now());
  const [queryInput, setQueryInput] = useState("");
  const [activeQuery, setActiveQuery] = useState<string | null>(null);
  const [filteredEvents, setFilteredEvents] = useState<ThreatEvent[] | null>(null);
  const [isQueryLoading, setIsQueryLoading] = useState(false);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [incidentReport, setIncidentReport] = useState<string | null>(null);
  const [incidentReportGeneratedAt, setIncidentReportGeneratedAt] = useState<string | null>(null);
  const [isReportLoading, setIsReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [boardReport, setBoardReport] = useState<string | null>(null);
  const [boardReportGeneratedAt, setBoardReportGeneratedAt] = useState<string | null>(null);
  const [isBoardReportLoading, setIsBoardReportLoading] = useState(false);
  const [boardReportError, setBoardReportError] = useState<string | null>(null);
  const [analystQuestion, setAnalystQuestion] = useState("");
  const [lastSubmittedQuestion, setLastSubmittedQuestion] = useState<string | null>(null);
  const [manualAnalystAnswer, setManualAnalystAnswer] = useState<string | null>(null);
  const [isAnalystQueryLoading, setIsAnalystQueryLoading] = useState(false);
  const [analystQueryError, setAnalystQueryError] = useState<string | null>(null);
  const { streamedText, isStreaming, startStream, reset: resetStream } = useAnalystStream();
  const streamRef = useRef<HTMLDivElement | null>(null);
  const liveSearchRef = useRef<HTMLInputElement | null>(null);
  const processedKillChainEventsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setClockMs(Date.now());
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  // Poll pending threats & override mode every 4 seconds
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const [pendingRes, overrideRes] = await Promise.all([
          fetch(`${API_BASE}/api/operator/pending`),
          fetch(`${API_BASE}/api/operator/override`),
        ]);
        if (cancelled) return;
        if (pendingRes.ok) {
          const json = await pendingRes.json();
          setPendingThreats(Array.isArray(json.data) ? json.data : []);
        }
        if (overrideRes.ok) {
          const json = await overrideRes.json();
          setOverrideMode(Boolean(json.data?.override_mode));
        }
      } catch { /* ignore */ }
    };
    void poll();
    const id = window.setInterval(poll, 4000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  const toggleOverrideMode = async () => {
    const next = !overrideMode;
    setOverrideMode(next);
    try {
      await fetch(`${API_BASE}/api/operator/override`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: next }),
      });
    } catch { /* ignore */ }
  };

  const approveThreat = async (sourceIp: string) => {
    setHitlBusy(sourceIp);
    // Find all pending threats matching this IP and approve them
    const matching = pendingThreats.filter((p) => p.source_ip === sourceIp && p.status === "PENDING");
    try {
      for (const p of matching) {
        await fetch(`${API_BASE}/api/operator/approve`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ threat_id: p.threat_id }),
        });
      }
      setPendingThreats((prev) => prev.filter((t) => t.source_ip !== sourceIp));
      setDismissedIps((prev) => new Set(prev).add(sourceIp));
      setHitlToast({ message: `✅ Approved — ${sourceIp} blocked & ticket created`, type: "approve" });
      setTimeout(() => setHitlToast(null), 4000);
    } catch { /* ignore */ }
    setHitlBusy(null);
  };

  const rejectThreat = async (sourceIp: string) => {
    setHitlBusy(sourceIp);
    const matching = pendingThreats.filter((p) => p.source_ip === sourceIp && p.status === "PENDING");
    try {
      for (const p of matching) {
        await fetch(`${API_BASE}/api/operator/reject`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ threat_id: p.threat_id }),
        });
      }
      setPendingThreats((prev) => prev.filter((t) => t.source_ip !== sourceIp));
      setDismissedIps((prev) => new Set(prev).add(sourceIp));
      setHitlToast({ message: `❌ Rejected — ${sourceIp} dismissed, no action taken`, type: "reject" });
      setTimeout(() => setHitlToast(null), 4000);
    } catch { /* ignore */ }
    setHitlBusy(null);
  };

  const mergedStreamEvents = useMemo(() => {
    const filteredQueue = queue.filter((t) => !dismissedIps.has(t.source_ip));
    const merged = [...filteredQueue, ...events];
    const seen = new Set<string>();
    const deduped: ThreatEvent[] = [];

    for (const item of merged) {
      const key = [
        String(item.timestamp || ""),
        String(item.source_ip || ""),
        String(item.attack_type || ""),
        String(item.event_type || ""),
        String(item.severity || ""),
      ].join("|");

      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(item);
    }

    deduped.sort(
      (a, b) => new Date(String(b.timestamp || "")).getTime() - new Date(String(a.timestamp || "")).getTime()
    );
    return deduped;
  }, [events, queue]);

  const analystContextThreat = useMemo(() => {
    const candidates: Array<ThreatEvent | null | undefined> = [
      selectedThreat,
      latestHighRisk,
      ...queue,
      ...mergedStreamEvents,
    ];
    return candidates.find((item): item is ThreatEvent => isMeaningfulThreat(item)) ?? null;
  }, [latestHighRisk, mergedStreamEvents, queue, selectedThreat]);

  // Live instant filter — runs on every keystroke, no API needed
  const liveFilteredEvents = useMemo(() => {
    const text = queryInput.trim().toLowerCase();
    if (!text) return null;
    // Resolve country name to code so "russia" matches events with country="RU"
    const resolvedCountryCode = COUNTRY_NAME_TO_CODE[text] ?? null;
    return mergedStreamEvents.filter((e) => {
      const countryCode = String(e.country || "").toUpperCase();
      if (resolvedCountryCode && countryCode === resolvedCountryCode) return true;
      return [
        e.source_ip,
        e.destination_ip,
        e.attack_type,
        e.country,
        countryLabel(String(e.country || "")),
        e.severity,
        e.username,
        e.reason,
        e.protocol,
        e.event_type,
        e.status,
        String(e.risk_score ?? ""),
        String(e.destination_port ?? ""),
      ]
        .filter(Boolean)
        .some((field) => String(field).toLowerCase().includes(text));
    });
  }, [queryInput, mergedStreamEvents]);

  const submitFeedQuery = async () => {
    const text = queryInput.trim();
    if (!text) return;
    // For complex NL queries hit the backend; simple keyword handled live above
    setIsQueryLoading(true);
    setQueryError(null);
    try {
      const resp = await fetch(`${API_BASE}/api/logs/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: text, event_history: mergedStreamEvents.slice(0, 300) }),
      });
      if (!resp.ok) throw new Error("query_failed");
      const payload = (await resp.json()) as { events?: ThreatEvent[]; query?: string };
      setFilteredEvents(Array.isArray(payload.events) ? payload.events : []);
      setActiveQuery(payload.query ?? text);
    } catch {
      setQueryError("Unable to run query right now.");
    } finally {
      setIsQueryLoading(false);
    }
  };

  const clearFilteredView = () => {
    setFilteredEvents(null);
    setActiveQuery(null);
    setQueryError(null);
    setQueryInput("");
  };

  const generateIncidentReport = async () => {
    setIsReportLoading(true);
    setReportError(null);
    setIncidentReport(null);
    try {
      const resp = await fetch(`${API_BASE}/api/analyst/incident_report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          events: events.slice(0, 300),
          actions: events
            .flatMap((event) =>
              (event.actions ?? []).map((action) => ({
                timestamp: event.timestamp,
                action: action.action,
                target: action.target,
                status: action.status,
              }))
            )
            .slice(0, 300),
        }),
      });
      if (!resp.ok) {
        throw new Error("report_failed");
      }
      const json = (await resp.json()) as { data?: { report?: string; generated_at?: string }; report?: string; generated_at?: string };
      const data = json.data ?? json;
      setIncidentReport((data.report || "").trim() || "No report generated.");
      setIncidentReportGeneratedAt(data.generated_at ?? new Date().toISOString());
    } catch {
      setReportError("Report generation failed. Try again.");
    } finally {
      setIsReportLoading(false);
    }
  };

  const copyReportToClipboard = async () => {
    if (!incidentReport) return;
    try {
      await navigator.clipboard.writeText(incidentReport);
    } catch {
      // no-op: modal remains available for manual copy.
    }
  };

  const generateBoardReport = async () => {
    setIsBoardReportLoading(true);
    setBoardReportError(null);
    setBoardReport(null);
    try {
      const resp = await fetch(`${API_BASE}/api/analyst/board_report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          events: events.slice(0, 300),
          actions: events
            .flatMap((event) =>
              (event.actions ?? []).map((action) => ({
                timestamp: event.timestamp,
                action: action.action,
                target: action.target,
                status: action.status,
              }))
            )
            .slice(0, 300),
        }),
      });
      if (!resp.ok) {
        throw new Error("board_report_failed");
      }
      const json = (await resp.json()) as { data?: { report?: string; generated_at?: string }; report?: string; generated_at?: string };
      const data = json.data ?? json;
      setBoardReport((data.report || "").trim() || "No board summary generated.");
      setBoardReportGeneratedAt(data.generated_at ?? new Date().toISOString());
    } catch {
      setBoardReportError("Report generation failed. Try again.");
    } finally {
      setIsBoardReportLoading(false);
    }
  };

  const copyBoardReport = async () => {
    if (!boardReport) return;
    try {
      await navigator.clipboard.writeText(boardReport);
    } catch {
      // no-op
    }
  };

  const heroClock = useMemo(() => {
    return new Date(clockMs).toUTCString().replace("GMT", "UTC");
  }, [clockMs]);

  const incidentGeneratedLabel = useMemo(
    () => `${formatGeneratedAt(incidentReportGeneratedAt)} UTC`,
    [incidentReportGeneratedAt]
  );

  const boardGeneratedLabel = useMemo(
    () => `${formatGeneratedAt(boardReportGeneratedAt)} UTC`,
    [boardReportGeneratedAt]
  );

  const isIncidentModalOpen = isReportLoading || Boolean(reportError) || Boolean(incidentReport);
  const isBoardModalOpen = isBoardReportLoading || Boolean(boardReportError) || Boolean(boardReport);

  const closeIncidentModal = () => {
    setIsReportLoading(false);
    setReportError(null);
    setIncidentReport(null);
  };

  const closeBoardModal = () => {
    setIsBoardReportLoading(false);
    setBoardReportError(null);
    setBoardReport(null);
  };

  useEffect(() => {
    if (!isIncidentModalOpen && !isBoardModalOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      if (isIncidentModalOpen) closeIncidentModal();
      if (isBoardModalOpen) closeBoardModal();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isBoardModalOpen, isIncidentModalOpen]);

  const boardReportParsed = useMemo(() => parseBoardReport(boardReport || ""), [boardReport]);

  useEffect(() => {
    if (!streamRef.current) return;
    streamRef.current.scrollTop = 0;
  }, [events.length]);

  useEffect(() => {
    if (!isMeaningfulThreat(latestHighRisk)) return;
    // Keep analyst context stable while user is interacting in AI view.
    if (currentView === "ai" || isAnalystQueryLoading) return;
    setSelectedThreat(latestHighRisk);
  }, [currentView, isAnalystQueryLoading, latestHighRisk]);

  useEffect(() => {
    if (currentView !== "ai") return;
    if (isMeaningfulThreat(selectedThreat)) return;
    if (analystContextThreat) {
      setSelectedThreat(analystContextThreat);
    }
  }, [analystContextThreat, currentView, selectedThreat]);

  useEffect(() => {
    setManualAnalystAnswer(null);
    setAnalystQueryError(null);
    resetStream();
  }, [selectedThreat?.timestamp, resetStream]);

  // Sync streaming state → loading indicator.
  useEffect(() => {
    if (!isStreaming) {
      setIsAnalystQueryLoading(false);
    }
  }, [isStreaming]);

  const askAnalyst = () => {
    const query = analystQuestion.trim();
    if (!query) return;
    setAnalystQueryError(null);
    setManualAnalystAnswer(null);
    setLastSubmittedQuestion(query);
    setIsAnalystQueryLoading(true);
    // Stream word-by-word via WebSocket; isAnalystQueryLoading clears when streaming ends.
    startStream(query, analystContextThreat);
  };

  const runQuickAnalystPrompt = (prompt: string) => {
    setAnalystQuestion(prompt);
    setAnalystQueryError(null);
    setManualAnalystAnswer(null);
    setLastSubmittedQuestion(prompt);
    setIsAnalystQueryLoading(true);
    startStream(prompt, analystContextThreat);
  };

  const originHotspots = useMemo(() => {
    const recentThreats = [...queue, ...events]
      .filter((item) => item.attack_type !== "NORMAL" && item.country && item.source_ip)
      .slice(0, 220);

    const countryBySource = new Map<string, string>();
    const sourceCountryTally = new Map<string, Map<string, number>>();

    for (const threat of recentThreats) {
      const source = String(threat.source_ip || "").trim().toLowerCase();
      const country = String(threat.country ?? "XX").toUpperCase();
      if (!source) continue;

      const tally = sourceCountryTally.get(source) ?? new Map<string, number>();
      tally.set(country, (tally.get(country) ?? 0) + 1);
      sourceCountryTally.set(source, tally);
    }

    for (const [source, tally] of sourceCountryTally.entries()) {
      const sorted = Array.from(tally.entries()).sort((a, b) => b[1] - a[1]);
      countryBySource.set(source, sorted[0]?.[0] ?? "XX");
    }

    const grouped = new Map<string, number>();
    for (const country of countryBySource.values()) {
      grouped.set(country, (grouped.get(country) ?? 0) + 1);
    }

    return Array.from(grouped.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([country, count]) => ({
        country,
        count,
        ...pointForCountry(country),
      }));
  }, [events, queue]);

  const originTotalSources = useMemo(
    () => originHotspots.reduce((sum, item) => sum + item.count, 0),
    [originHotspots]
  );

  const topOriginSpot = originHotspots[0] ?? null;

  const killChainStageOrder = KILL_CHAIN_DEFAULT_ORDER;
  const killChainActiveCount = useMemo(
    () => Object.keys(killChainStages).length,
    [killChainStages]
  );

  useEffect(() => {
    const merged = [...events, ...queue];
    if (merged.length === 0) return;

    const pending: ThreatEvent[] = [];
    for (const threat of merged) {
      const key = [
        String(threat.timestamp || ""),
        String(threat.source_ip || ""),
        String(threat.attack_type || ""),
        String(threat.event_type || ""),
        String(threat.status || ""),
      ].join("|");

      if (processedKillChainEventsRef.current.has(key)) {
        continue;
      }
      processedKillChainEventsRef.current.add(key);
      pending.push(threat);
    }

    if (pending.length === 0) return;

    pending.sort((a, b) => {
      const aTs = new Date(a.timestamp).getTime();
      const bTs = new Date(b.timestamp).getTime();
      return (Number.isNaN(aTs) ? 0 : aTs) - (Number.isNaN(bTs) ? 0 : bTs);
    });

    setKillChainStages((prev) => {
      const next = { ...prev };
      let persistenceActive = Boolean(next["Persistence"]);

      for (const threat of pending) {
        const stage = killChainStageFromThreat(threat, persistenceActive);
        if (!stage || next[stage]) {
          continue;
        }

        next[stage] = {
          eventType: String(threat.event_type || "event").toLowerCase(),
          timestamp: compactTime(String(threat.timestamp || new Date().toISOString())),
          activatedAtMs: Date.now(),
        };

        if (stage === "Persistence") {
          persistenceActive = true;
        }

        setStageHistory((prev) => {
          const nextHistory = [
            {
              stage: stageDisplayName(stage),
              event: stageTriggerText(String(threat.event_type || "")),
              source_ip: String(threat.source_ip || "unknown"),
              time: compactTime(String(threat.timestamp || new Date().toISOString())),
            },
            ...prev,
          ];
          return nextHistory.slice(0, 10);
        });
      }

      return next;
    });
  }, [events, queue]);

  const liveFeedBaseEvents = useMemo(
    () => filteredEvents ?? liveFilteredEvents ?? mergedStreamEvents.slice(0, 300),
    [filteredEvents, liveFilteredEvents, mergedStreamEvents]
  );
  const displayQueue = useMemo(() => queue.filter((t) => !dismissedIps.has(t.source_ip)), [queue, dismissedIps]);

  useEffect(() => {
    if (focusLiveSearch && currentView === "live") {
      liveSearchRef.current?.focus();
      setFocusLiveSearch(false);
    }
  }, [currentView, focusLiveSearch]);

  useEffect(() => {
    if (currentView === "ai") {
      setAiNavPulse(false);
      return;
    }
    if (latestHighRisk?.auto_detected && (latestHighRisk.severity === "HIGH" || latestHighRisk.severity === "CRITICAL")) {
      setAiNavPulse(true);
    }
  }, [currentView, latestHighRisk]);

  const totalEventsAnalyzed = useMemo(() => {
    const total = Object.values(dwellByIp).reduce((sum, entry) => sum + Number(entry.count || 0), 0);
    return total > 0 ? total : events.length;
  }, [dwellByIp, events.length]);

  const highestThreatNarrative = useMemo(() => {
    if (!latestHighRisk) return "All traffic appears normal. No urgent threat right now.";
    const vector = plainThreatName(latestHighRisk.attack_type);
    const origin = countryLabel(String(latestHighRisk.country || "XX"));
    return `${vector} detected from ${origin} - system responding`;
  }, [latestHighRisk]);

  const heroState = useMemo(() => {
    if (displayQueue.length > 0) {
      return { label: "⚡ THREAT DETECTED", tone: "threat" as const };
    }
    if (metrics.blockedIps > 0) {
      return { label: "THREAT CONTAINED", tone: "contained" as const };
    }
    return { label: "ALL SYSTEMS NORMAL", tone: "normal" as const };
  }, [metrics.blockedIps, displayQueue.length]);

  const analystPrimaryText = useMemo(() => {
    // While streaming, show the progressively revealed text (with cursor).
    if (isStreaming || streamedText) {
      return streamedText || "▍";
    }
    const raw =
      manualAnalystAnswer ?? analystContextThreat?.analysis ?? selectedThreat?.analysis ?? "No analysis available yet.";
    if (isAnalystOutageMessage(raw)) {
      return localAnalystFallback(
        analystContextThreat ?? selectedThreat,
        lastSubmittedQuestion || analystQuestion || ""
      );
    }
    if (raw.includes("Automated analysis unavailable. Likely attack detected.")) {
      return "AI is analyzing this threat. Mitigation steps are shown on the right.";
    }
    return raw;
  }, [analystContextThreat, analystQuestion, isStreaming, lastSubmittedQuestion, manualAnalystAnswer, selectedThreat, streamedText]);

  const liveEvents = useMemo(() => {
    if (liveSeverityFilter === "all") return liveFeedBaseEvents;
    return liveFeedBaseEvents.filter((event) => {
      const severity = String(event.severity || "LOW").toLowerCase();
      if (liveSeverityFilter === "high") return severity === "high" || severity === "critical";
      return severity === liveSeverityFilter;
    });
  }, [liveFeedBaseEvents, liveSeverityFilter]);

  const sortedQueue = useMemo(() => {
    const copy = [...displayQueue];
    if (threatSort === "Highest Risk") {
      return copy.sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
    }
    if (threatSort === "Most Recent") {
      return copy.sort(
        (a, b) =>
          new Date(String(b.timestamp || "")).getTime() - new Date(String(a.timestamp || "")).getTime()
      );
    }
    return copy.sort((a, b) => Number(b.dwell_seconds || 0) - Number(a.dwell_seconds || 0));
  }, [displayQueue, threatSort]);

  const sidebarTitle = useMemo(() => {
    const map: Record<DashboardView, string> = {
      overview: "Overview",
      live: "Live Feed",
      queue: "Threat Queue",
      progress: "Attack Progress",
      ai: "AI Analyst",
      traffic: "Network Traffic",
      origins: "Attack Origins",
      reports: "Reports",
    };
    return map[currentView];
  }, [currentView]);

  const saveReportAsFile = (name: string, content: string) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const saveReportAsPdf = (title: string, content: string, filename: string) => {
    import("jspdf").then(({ jsPDF }) => {
      const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const pageW = doc.internal.pageSize.getWidth();
      const pageH = doc.internal.pageSize.getHeight();
      const marginL = 18;
      const marginR = 18;
      const contentW = pageW - marginL - marginR;
      const now = new Date();
      const dateStr = now.toUTCString();
      const isBoardReport = filename.includes("board");

      // ── Helper: draw page header + footer ────────────────────────────────
      const drawPageChrome = (pageNum: number, totalPages: number) => {
        // Top dark header band
        doc.setFillColor(10, 20, 48);
        doc.rect(0, 0, pageW, 22, "F");

        // Red accent stripe
        doc.setFillColor(220, 38, 38);
        doc.rect(0, 22, pageW, 1.5, "F");

        // Logo / system name
        doc.setFont("helvetica", "bold");
        doc.setFontSize(11);
        doc.setTextColor(255, 255, 255);
        doc.text("SENTINEL AI-SOC", marginL, 14);

        // Classification badge (right side of header)
        doc.setFillColor(220, 38, 38);
        doc.roundedRect(pageW - marginR - 38, 7, 38, 9, 1.5, 1.5, "F");
        doc.setFontSize(7);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(255, 255, 255);
        doc.text("CONFIDENTIAL", pageW - marginR - 20, 13, { align: "center" });

        // Footer band
        doc.setFillColor(240, 242, 248);
        doc.rect(0, pageH - 12, pageW, 12, "F");
        doc.setDrawColor(200, 205, 220);
        doc.line(0, pageH - 12, pageW, pageH - 12);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(100, 110, 130);
        doc.text("SENTINEL AI-SOC  ·  Automated Security Intelligence Platform", marginL, pageH - 5);
        doc.text(`Page ${pageNum} of ${totalPages}`, pageW - marginR, pageH - 5, { align: "right" });
      };

      // ── Pre-pass: count pages ─────────────────────────────────────────────
      const CONTENT_TOP = 34;
      const CONTENT_BOTTOM = pageH - 16;
      const lineHeight = 5.5;
      const headerLineHeight = 8;

      // Known section header keywords — defined here so both the pre-pass and render loop can use it.
      // Board report lines like "- THREAT LEVEL: ..." are key-value bullets, NOT section headers,
      // so they must NOT be in this set (they would swallow the value after the colon).
      const SECTION_KEYWORDS = new Set([
        "EXECUTIVE SUMMARY","TIMELINE OF EVENTS","ATTACK VECTORS IDENTIFIED","ASSETS AT RISK",
        "AUTOMATED ACTIONS TAKEN","RECOMMENDED NEXT STEPS","OVERVIEW",
        "INCIDENT SUMMARY","RESPONSE ACTIONS","KEY FINDINGS","RISK ASSESSMENT","RAW EVENT LOG",
      ]);

      const lines = content.split("\n");
      let totalPages = 1;
      let yProbe = CONTENT_TOP;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) { yProbe += 3; continue; }
        const probeT = trimmed.replace(/^[-•]\s*/, "").split(":")[0].trim().toUpperCase();
        const isSection = SECTION_KEYWORDS.has(probeT);
        const wrapped = doc.splitTextToSize(line, contentW) as string[];
        const lh = isSection ? headerLineHeight : lineHeight;
        for (const _ of wrapped) {
          if (yProbe + lh > CONTENT_BOTTOM) { totalPages++; yProbe = CONTENT_TOP; }
          yProbe += lh;
        }
      }

      // ── Page 1 chrome ────────────────────────────────────────────────────
      drawPageChrome(1, totalPages);

      // Title block
      let y = CONTENT_TOP;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(20);
      doc.setTextColor(10, 20, 48);
      doc.text(title, marginL, y);
      y += 9;

      // Subtitle / meta bar
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(100, 110, 130);
      doc.text(`Generated by SENTINEL AI-SOC  ·  ${dateStr}`, marginL, y);
      y += 5;

      // Decorative rule under title
      doc.setDrawColor(220, 38, 38);
      doc.setLineWidth(0.8);
      doc.line(marginL, y, marginL + 60, y);
      doc.setDrawColor(220, 225, 235);
      doc.setLineWidth(0.4);
      doc.line(marginL + 61, y, pageW - marginR, y);
      doc.setLineWidth(0.2);
      y += 8;

      // ── Content rendering ─────────────────────────────────────────────────
      let currentPage = 1;
      let inRawLogTable = false;

      const isSectionHeader = (raw: string): boolean => {
        // Only match explicit known section keywords — never guess from all-caps
        const t = raw.trim().replace(/^[-•]\s*/, "").split(":")[0].trim().toUpperCase();
        return SECTION_KEYWORDS.has(t);
      };

      // Alternating row colors for board report key-value lines
      let rowIndex = 0;

      for (const line of lines) {
        const trimmed = line.trim();

        // Blank line → small gap
        if (!trimmed) {
          y += 3;
          continue;
        }

        const isSection = isSectionHeader(trimmed);

        if (isSection) {
          // Section header: colored pill background
          y += 2;
          if (y + 10 > CONTENT_BOTTOM) {
            doc.addPage();
            currentPage++;
            drawPageChrome(currentPage, totalPages);
            y = CONTENT_TOP;
          }
          doc.setFillColor(10, 20, 48);
          doc.roundedRect(marginL - 2, y - 5, contentW + 4, 8, 1, 1, "F");
          doc.setFont("helvetica", "bold");
          doc.setFontSize(9);
          doc.setTextColor(255, 255, 255);
          // Strip leading "- " if present
          const headerText = trimmed.replace(/^[-•]\s*/, "").split(":")[0].trim();
          doc.text(headerText, marginL + 1, y);
          y += 7;
          rowIndex = 0;
          // Track whether we've entered the raw log table section
          if (headerText === "RAW EVENT LOG") {
            inRawLogTable = true;
          } else {
            inRawLogTable = false;
          }
          continue;
        }

        // Raw log table lines: monospaced, smaller font, no bullet processing
        if (inRawLogTable) {
          doc.setFont("courier", "normal");
          doc.setFontSize(6.5);
          doc.setTextColor(30, 30, 30);
          const tableLines = doc.splitTextToSize(line, contentW + 10) as string[];
          for (const tline of tableLines) {
            if (y + 4 > CONTENT_BOTTOM) {
              doc.addPage();
              currentPage++;
              drawPageChrome(currentPage, totalPages);
              y = CONTENT_TOP;
            }
            doc.text(tline, marginL - 2, y);
            y += 3.8;
          }
          continue;
        }

        // Check if it's a key: value line (board report style)
        const kvMatch = /^[-•]?\s*([^:]{2,40}):\s*(.+)$/.exec(trimmed);
        if (kvMatch && isBoardReport) {
          const key = kvMatch[1].trim();
          const val = kvMatch[2].trim();
          const rowH = 7;

          if (y + rowH > CONTENT_BOTTOM) {
            doc.addPage();
            currentPage++;
            drawPageChrome(currentPage, totalPages);
            y = CONTENT_TOP;
          }

          // Alternating row background
          if (rowIndex % 2 === 0) {
            doc.setFillColor(246, 248, 252);
            doc.rect(marginL - 2, y - 4.5, contentW + 4, rowH, "F");
          }

          // Left accent bar
          doc.setFillColor(220, 38, 38);
          doc.rect(marginL - 2, y - 4.5, 2, rowH, "F");

          doc.setFont("helvetica", "bold");
          doc.setFontSize(8.5);
          doc.setTextColor(10, 20, 48);
          doc.text(key.toUpperCase(), marginL + 3, y);

          doc.setFont("helvetica", "normal");
          doc.setFontSize(8.5);
          doc.setTextColor(40, 50, 70);
          const valLines = doc.splitTextToSize(val, contentW - 52) as string[];
          doc.text(valLines[0], marginL + 55, y);
          y += rowH;
          rowIndex++;
          continue;
        }

        // Regular body text
        const wrapped = doc.splitTextToSize(trimmed.replace(/^[-•]\s*/, "• "), contentW) as string[];
        doc.setFont("helvetica", "normal");
        doc.setFontSize(9);
        doc.setTextColor(40, 50, 70);

        for (const wline of wrapped) {
          if (y + lineHeight > CONTENT_BOTTOM) {
            doc.addPage();
            currentPage++;
            drawPageChrome(currentPage, totalPages);
            y = CONTENT_TOP;
          }
          doc.text(wline, marginL, y);
          y += lineHeight;
        }
      }

      doc.save(`${filename}-${now.toISOString().slice(0, 10)}.pdf`);
    });
  };

  const jumpToLiveSearch = () => {
    setCurrentView("live");
    setFocusLiveSearch(true);
  };

  const openThreatInAnalyst = (threat: ThreatEvent) => {
    setSelectedThreat(threat);
    setCurrentView("ai");
  };

  const anomalyPanelData = useMemo(() => {
    if (!latestAuthAnomaly) return null;
    const history = [...events, ...queue];
    const baseline = deriveUserBaselineFromHistory(latestAuthAnomaly.username, history);
    const eventDate = new Date(latestAuthAnomaly.timestamp);
    const eventHour = Number.isNaN(eventDate.getTime()) ? 0 : eventDate.getHours();
    const expectedAtHour = baseline[eventHour] ?? 0;

    const hourlyLogins = history.filter((event) => {
      if (String(event.event_type || "").toLowerCase() !== "login") return false;
      if (String(event.username || "").toLowerCase() !== String(latestAuthAnomaly.username || "").toLowerCase()) {
        return false;
      }
      const ts = new Date(String(event.timestamp || ""));
      if (Number.isNaN(ts.getTime())) return false;
      return ts.getHours() === eventHour;
    }).length;

    const anomalyScore = Math.max(0, Math.min(1, Number(latestAuthAnomaly.anomaly_score || 0)));
    const severityFactor =
      latestAuthAnomaly.severity === "CRITICAL"
        ? 1.2
        : latestAuthAnomaly.severity === "HIGH"
        ? 0.8
        : latestAuthAnomaly.severity === "MEDIUM"
        ? 0.4
        : 0.2;

    const observedValueRaw = Math.min(
      10,
      Math.max(0.5, hourlyLogins + anomalyScore * 3 + severityFactor)
    );
    const observedValue = Number(observedValueRaw.toFixed(1));
    const eventBars = hoursOfDay.map((hour) => (hour === eventHour ? observedValue : 0));

    const sd = stdDeviation(baseline) || 1;
    const zScore = (observedValue - expectedAtHour) / sd;
    const deviation = Math.abs(zScore);
    const deltaFromBaseline = Number((observedValue - expectedAtHour).toFixed(1));
    const interpretation = anomalyInterpretation(deviation);

    return {
      username: latestAuthAnomaly.username,
      eventHour,
      timeLabel: compactTime(latestAuthAnomaly.timestamp),
      deviation,
      zScore,
      expectedAtHour,
      observedValue,
      deltaFromBaseline,
      interpretation,
      chartData: {
        labels: hoursOfDay.map((hour) => hour.toString()),
        datasets: [
          {
            label: "Normal baseline",
            data: baseline,
            backgroundColor: "rgba(112, 189, 255, 0.7)",
            borderColor: "rgba(112, 189, 255, 0.9)",
            borderWidth: 1,
          },
          {
            label: "This event",
            data: eventBars,
            backgroundColor: "rgba(255, 66, 90, 0.85)",
            borderColor: "rgba(255, 66, 90, 1)",
            borderWidth: 1,
          },
        ],
      },
    };
  }, [latestAuthAnomaly]);

  const anomalyChartOptions = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: "top" as const,
          labels: {
            color: "#8A9BB5",
            boxWidth: 8,
            font: { size: 10, family: "DM Mono" },
          },
        },
      },
      scales: {
        x: {
          ticks: {
            color: "#8A9BB5",
            maxRotation: 0,
            autoSkip: true,
            maxTicksLimit: 12,
            font: { size: 10, family: "DM Mono" },
          },
          grid: { color: "rgba(0, 0, 0, 0.04)" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#8A9BB5", font: { size: 10, family: "DM Mono" } },
          grid: { color: "rgba(0, 0, 0, 0.04)" },
        },
      },
    }),
    []
  );

  const toggleTheme = () => {
    setTheme((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      localStorage.setItem("sentinel-theme", next);
      return next;
    });
  };

  return (
    <div className={`app-shell theme-${theme}`}>
      <aside className="sidebar">
        <div className="sidebar-logo">
          <strong>SENTINEL</strong>
          <span>AI-SOC</span>
          <p><i />LIVE</p>
        </div>

        <nav className="sidebar-nav">
          {[
            ["overview", "Overview"],
            ["live", "Live Feed"],
            ["queue", "Threat Queue"],
            ["progress", "Attack Progress"],
            ["ai", "AI Analyst"],
            ["traffic", "Network Traffic"],
            ["origins", "Attack Origins"],
            ["reports", "Reports"],
          ].map(([id, label]) => {
            const view = id as DashboardView;
            const isActive = currentView === view;
            return (
              <button key={id} type="button" className={`nav-item ${isActive ? "active" : ""}`} onClick={() => setCurrentView(view)}>
                <NavIcon kind={id} />
                <span>{label}</span>
                {id === "queue" && displayQueue.length > 0 ? <em className="queue-badge">{displayQueue.length}</em> : null}
                {id === "ai" && aiNavPulse ? <em className="ai-pulse-dot" /> : null}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-status">
          <p>● Anomaly detection</p>
          <p>● Phishing classifier</p>
          <p>● Risk scoring</p>
          <p>● Auto-response</p>
        </div>
      </aside>

      <section className="main-zone">
        <header className="view-topbar">
          <div className="view-topbar-left">
            <h1>{sidebarTitle}</h1>
            <p className={`topbar-state ${heroState.tone}`}>{heroState.label} · {highestThreatNarrative}</p>
          </div>
          <div className="view-topbar-right">
            <span className="mini-live-pill"><i /> LIVE</span>
            <span className="hero-clock">{heroClock}</span>
            <button type="button" className="theme-toggle" onClick={toggleTheme} aria-label="Toggle theme" title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
              {theme === "dark" ? (
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
              ) : (
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              )}
              <span>{theme === "dark" ? "Light" : "Dark"}</span>
            </button>
            <button type="button" className="board-report-btn light" onClick={() => void generateBoardReport()} disabled={isBoardReportLoading}>
              {isBoardReportLoading ? "Generating..." : "📊 Board Report"}
            </button>
          </div>
        </header>

        <div className="view-content">
          {currentView === "overview" ? (
            <div className="view-fade view-overview">
              <section className="stats-row">
                <article key={`ov-active-${displayQueue.length}`} className="stat-tile threat">
                  <div className="stat-tile-head"><span className="stat-icon">🚨</span><h3>Active Threats</h3></div>
                  <strong>{displayQueue.length}</strong>
                  <p className={displayQueue.length > 0 ? "danger" : "safe"}>{displayQueue.length > 0 ? "Needs your attention" : "None right now"}</p>
                </article>
                <article key={`ov-failed-${metrics.failedLogins}`} className="stat-tile password">
                  <div className="stat-tile-head"><span className="stat-icon">🔐</span><h3>Password Attacks</h3></div>
                  <strong>{metrics.failedLogins}</strong>
                  <p>Blocked attempts in last 60s</p>
                </article>
                <article key={`ov-blocked-${metrics.blockedIps}`} className="stat-tile blocked">
                  <div className="stat-tile-head"><span className="stat-icon">🛡️</span><h3>Automatically Blocked</h3></div>
                  <strong>{metrics.blockedIps}</strong>
                  <p>No manual action needed</p>
                </article>
                <article key={`ov-events-${totalEventsAnalyzed}`} className="stat-tile analyzed">
                  <div className="stat-tile-head"><span className="stat-icon">👁️</span><h3>Events Analyzed</h3></div>
                  <strong>{totalEventsAnalyzed}</strong>
                  <p>This session</p>
                </article>
              </section>

              <section className="panel system-health-card">
                <h2>System Status</h2>
                <div className="health-grid">
                  {[
                    ["Anomaly detection", true],
                    ["Phishing classifier", true],
                    ["Risk scoring", true],
                    ["Auto-response", true],
                  ].map(([label, active]) => (
                    <div key={String(label)} className="health-row">
                      <div className="health-row-left">
                        <span className={`dot ${active ? "online" : "offline"}`} />
                        <strong>{label}</strong>
                      </div>
                      <div className="health-row-right">
                        <em>{active ? "Online" : "Offline"}</em>
                        <small>{compactTime(new Date().toISOString())}</small>
                      </div>
                    </div>
                  ))}
                </div>
                <p className="health-summary">
                  {metrics.critical === 0
                    ? "Everything looks normal. No action needed."
                    : metrics.critical <= 2
                    ? `Low activity. ${metrics.critical} threats being monitored.`
                    : `${metrics.critical} active threats. System is responding automatically.`}
                </p>
              </section>

              <section className="overview-bottom-row">
                <div className="panel recent-activity-card">
                  <h2>Recent Activity</h2>
                  {events.slice(0, 5).map((event, idx) => (
                    <div key={`recent-${idx}`} className="recent-row">
                      <span
                        className={`stream-dot ${
                          event.severity === "CRITICAL"
                            ? "critical"
                            : event.severity === "HIGH"
                            ? "high"
                            : event.severity === "MEDIUM"
                            ? "medium"
                            : "low"
                        }`}
                      />
                      <span>{eventDescription(event)}</span>
                      <em>{compactTime(event.timestamp)}</em>
                    </div>
                  ))}
                  <button type="button" className="inline-link" onClick={() => setCurrentView("live")}>View all →</button>
                </div>
                <div className="panel quick-actions-card">
                  <h2>Quick Actions</h2>
                  <div className="quick-actions-grid">
                    <button className="quick-action-btn" type="button" onClick={() => void generateBoardReport()}>📋 Generate Board Report</button>
                    <button className="quick-action-btn" type="button" onClick={() => void generateIncidentReport()}>📄 Generate IR Report</button>
                    <button className="quick-action-btn" type="button" onClick={jumpToLiveSearch}>🔍 Search Logs</button>
                    <button className="quick-action-btn" type="button" onClick={() => setCurrentView("ai")}>🤖 Ask AI Analyst</button>
                  </div>
                </div>
              </section>
            </div>
          ) : null}

          {currentView === "live" ? (
            <div className="view-fade panel live-feed-view">
              <div className="panel-head-inline"><h2>What's Happening Now</h2><span className="panel-mini-pill">1 event / sec</span></div>
              <div className="live-filter-row">
                {(["all", "high", "medium", "low"] as const).map((level) => (
                  <button key={level} type="button" className={`filter-pill ${liveSeverityFilter === level ? "active" : ""}`} onClick={() => setLiveSeverityFilter(level)}>{level[0].toUpperCase() + level.slice(1)}</button>
                ))}
              </div>
              <div className="feed-query-row big">
                <input ref={liveSearchRef} type="text" className="feed-query-input" placeholder="Filter by IP, country, attack type, severity, port..." value={queryInput} onChange={(event) => { setQueryInput(event.target.value); setFilteredEvents(null); setActiveQuery(null); }} onKeyDown={(event) => { if (event.key === "Enter") void submitFeedQuery(); }} />
                {queryInput.trim() ? <button type="button" className="feed-query-clear" onClick={clearFilteredView}>×</button> : null}
                <button type="button" className="feed-query-btn" onClick={() => void submitFeedQuery()} disabled={isQueryLoading} title="AI natural language search">{isQueryLoading ? <span className="feed-query-spinner" aria-hidden="true" /> : "AI Search"}</button>
              </div>
              {queryInput.trim() && liveFilteredEvents !== null && !filteredEvents ? (
                <div className="filtered-banner">
                  {liveFilteredEvents.length > 0
                    ? <><span>Showing <strong>{liveFilteredEvents.length}</strong> results for <em>'{queryInput.trim()}'</em></span><button type="button" className="filtered-banner-clear" onClick={clearFilteredView}>× Clear</button></>
                    : <><span>No matches for <em>'{queryInput.trim()}'</em> — press <strong>AI Search</strong> for natural language</span><button type="button" className="filtered-banner-clear" onClick={clearFilteredView}>× Clear</button></>}
                </div>
              ) : filteredEvents && activeQuery ? (
                <div className="filtered-banner"><span>AI Search: <strong>{filteredEvents.length}</strong> results for <em>'{activeQuery}'</em></span><button type="button" className="filtered-banner-clear" onClick={clearFilteredView}>× Clear</button></div>
              ) : null}
              {queryError ? <div className="feed-query-error">{queryError}</div> : null}
              <div className="stream-list tall" ref={streamRef}>
                {liveEvents.map((event, idx) => (
                  <div key={`live-${idx}`} className="stream-row large">
                    <span className={`stream-dot ${event.severity === "CRITICAL" ? "critical" : event.severity === "HIGH" ? "high" : event.severity === "MEDIUM" ? "medium" : "low"}`} />
                    <div>
                      <p className="stream-main-text">{eventDescription(event)}</p>
                      <p className="stream-sub-text">{`from ${event.source_ip} · ${countryLabel(String(event.country || "XX"))} · via ${event.event_type}`}</p>
                    </div>
                    <span className="stream-time">{compactTime(event.timestamp)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {currentView === "queue" ? (
            <div className="view-fade">
              <section className="panel threat-queue-view">
                <div className="panel-head-inline queue-head">
                  <h2>Active Threats {sortedQueue.length > 0 ? <span className="count-badge">{sortedQueue.length}</span> : null}</h2>
                  <div className="queue-sort-wrap">
                    <button type="button" className={`override-toggle ${overrideMode ? "active" : ""}`} onClick={() => void toggleOverrideMode()} title={overrideMode ? "Override ON — all auto-responses paused" : "Override OFF — auto-response active"}>{overrideMode ? "🔴 Override ON" : "🟢 Auto-Response"}</button>
                    <label htmlFor="queue-sort">Sort by</label>
                    <select
                      id="queue-sort"
                      className="queue-sort-select"
                      value={threatSort}
                      onChange={(e) => setThreatSort(e.target.value as "Highest Risk" | "Most Recent" | "Persistent")}
                    >
                      <option>Highest Risk</option>
                      <option>Most Recent</option>
                      <option>Persistent</option>
                    </select>
                  </div>
                </div>
                {overrideMode && sortedQueue.length > 0 ? (
                  <div className="pending-banner">⏳ <strong>{sortedQueue.length}</strong> threat{sortedQueue.length > 1 ? "s" : ""} awaiting your approval</div>
                ) : null}
                {sortedQueue.length === 0 ? (
                  <div className="queue-empty"><div className="shield-icon">🛡️</div><h3>No active threats</h3><p>All systems clear - SENTINEL is monitoring</p></div>
                ) : (
                  <div className="threat-grid">
                    {sortedQueue.map((threat, idx) => (
                      <article key={`tq-${idx}`} className={`threat-card big ${selectedThreat?.timestamp === threat.timestamp ? "selected" : ""}`}>
                        <div className="card-head"><strong>{plainThreatName(threat.attack_type)}</strong><span className={`score-pill ${threat.risk_score >= 75 ? "high" : threat.risk_score >= 40 ? "med" : "low"}`}>{Math.round(threat.risk_score)}/100</span></div>
                        <p className="threat-origin-line">{`${threat.source_ip} · ${countryLabel(String(threat.country || "XX"))}`}</p>
                        <div className="risk-breakdown">{scoreBreakdown(threat)}</div>
                        <div className="risk-bar"><span style={{ width: `${Math.min(100, threat.risk_score)}%`, background: riskFill(threat.risk_score) }} /></div>
                        <div className="card-foot"><span className="meta-badge">{threat.mitre?.technique ?? "N/A"}</span><span className="threat-dwell">{dwellSummary(Number(threat.dwell_seconds || 0), Number(threat.event_count || 1), Boolean(threat.is_persistent)).label}</span></div>
                        {threat.threat_actor ? <div className="actor-inline-badge threat-inline-row">🎯 Likely: {threat.threat_actor.name} ({threat.threat_actor.aka})</div> : null}
                        {threat.ip_intel ? <div className="ip-intel-row threat-inline-row">📡 Reported by {threat.ip_intel.total_reports} orgs · {threat.ip_intel.abuse_score}% malicious</div> : null}
                        <div className="hitl-actions">
                          <button type="button" className="analyze-link queue-action-btn" onClick={() => openThreatInAnalyst(threat)}>Analyze with AI →</button>
                          {overrideMode ? (
                            <>
                              <button type="button" className="hitl-approve-btn" disabled={hitlBusy === threat.source_ip} onClick={() => void approveThreat(threat.source_ip)}>✅ Approve</button>
                              <button type="button" className="hitl-reject-btn" disabled={hitlBusy === threat.source_ip} onClick={() => void rejectThreat(threat.source_ip)}>❌ Reject</button>
                            </>
                          ) : (
                            <span className="auto-blocked-badge">🛡️ Automatically blocked by SENTINEL</span>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                )}
                {hitlToast ? (
                  <div className={`hitl-toast ${hitlToast.type}`}>{hitlToast.message}</div>
                ) : null}
              </section>
            </div>
          ) : null}

          {currentView === "progress" ? (
            <div className="view-fade">
              <section className="panel progress-view">
                <div className="panel-head-inline"><h2>Attack Progress</h2><p className={`progress-status ${killChainActiveCount > 0 ? "hot" : "cool"}`}>{killChainActiveCount > 0 ? `Attack in progress · ${killChainActiveCount} stages active` : "No attack detected · All clear"}</p></div>
                <div className="kill-chain-track tall" role="list" aria-label="Attack progress timeline">
                  {killChainStageOrder.map((stage, idx) => {
                    const stageData = killChainStages[stage];
                    const isActive = Boolean(stageData);
                    const isPulsing = isActive && clockMs - Number(stageData?.activatedAtMs || 0) <= 3000;
                    return (
                      <div key={stage} className="kill-stage-wrap" role="listitem">
                        <div className={`kill-stage giant ${isActive ? "active" : "inactive"} ${isPulsing ? "pulse" : ""}`}>
                          <div className="kill-stage-name">{stageDisplayName(stage)}</div>
                          <div className="kill-stage-detail">{isActive ? `${stageTriggerText(String(stageData?.eventType || ""))} · ${stageData?.timestamp}` : ""}</div>
                        </div>
                        {idx < killChainStageOrder.length - 1 ? <span className="kill-stage-arrow">→</span> : null}
                      </div>
                    );
                  })}
                </div>
                <div className={`kill-chain-counter large ${killChainActiveCount <= 2 ? "low" : killChainActiveCount <= 5 ? "medium" : "high"}`}>{killChainActiveCount} of 8 stages active</div>
                {killChainActiveCount >= 3 ? <div className="coordinated-banner static"><strong>🔴 Coordinated campaign detected - {coordinatedCampaign?.vector_count ?? 3} simultaneous attack vectors</strong><span>{(coordinatedCampaign?.attack_types || []).join(", ")} · {(coordinatedCampaign?.source_countries || []).join(", ")}</span><button type="button" onClick={() => setCurrentView("ai")}>Ask AI about this →</button></div> : null}
                <div className="panel stage-history-table">
                  <h3>Stage Activity History</h3>
                  <table><thead><tr><th>Stage</th><th>Event</th><th>Source IP</th><th>Time</th></tr></thead><tbody>{stageHistory.map((entry, i) => <tr key={`stage-${i}`}><td>{entry.stage}</td><td>{entry.event}</td><td>{entry.source_ip}</td><td>{entry.time}</td></tr>)}</tbody></table>
                </div>
              </section>
            </div>
          ) : null}

          {currentView === "ai" ? (
            <div className="view-fade ai-view-grid">
              <section className="panel ai-chat-column">
                <div className="analyst-head"><div className="ai-head-left"><span className="ai-avatar">AI</span><div><h2>Security AI Assistant</h2><p>Online</p></div></div><button type="button" className="ir-report-btn" onClick={() => void generateIncidentReport()} disabled={isReportLoading}>{isReportLoading ? "Generating..." : "📄 IR Report"}</button></div>
                <div className="analyst-message-area giant">
                  {counterfactualPanels.map((panel) => (
                    <div key={panel.id} className="analyst-counterfactual-card" onMouseEnter={() => setCounterfactualHover(panel.id, true)} onMouseLeave={() => setCounterfactualHover(panel.id, false)}>
                      <div className="analyst-counterfactual-head"><strong>⚡ If we hadn't blocked this...</strong><span className="analyst-counterfactual-badge">SIMULATED</span></div>
                      <div className="analyst-counterfactual-grid"><div><h4>NEXT MOVE</h4><p>{panel.next_move}</p></div><div><h4>AT RISK</h4><p>{panel.at_risk}</p></div><div><h4>TIME TO BREACH</h4><p>{panel.time_to_breach}</p></div><div><h4>BLAST RADIUS</h4><p>{panel.blast_radius}</p></div></div>
                    </div>
                  ))}
                  {lastSubmittedQuestion ? <div className="user-bubble">{lastSubmittedQuestion}</div> : null}
                  <div className="ai-message-wrap">{selectedThreat?.auto_detected ? <div className="auto-detected-label">Auto-detected threat</div> : null}<span className="ai-tag">AI</span><div className={`ai-bubble ${isStreaming ? "warm streaming" : analystPrimaryText.startsWith("AI is analyzing") ? "warm" : ""}`}>{coordinatedCampaign?.analysis ? `${coordinatedCampaign.analysis}\n\n` : ""}{analystPrimaryText}{isStreaming ? <span className="typing-cursor">▍</span> : null}</div></div>
                </div>
                <div className="quick-chip-row">{["🚨 What's the biggest threat?", "🛡️ What should I do now?", "📋 Summarize everything", "🔗 Is this coordinated?", "⚡ What if we hadn't blocked it?"].map((chip) => <button key={chip} type="button" className="quick-chip" onClick={() => runQuickAnalystPrompt(chip)}>{chip}</button>)}</div>
                <div className="analyst-query-row"><input type="text" className="analyst-query-input" placeholder="Ask anything about current threats..." value={analystQuestion} onChange={(event) => setAnalystQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") askAnalyst(); }} /><button type="button" className="analyst-query-btn" onClick={() => askAnalyst()} disabled={isAnalystQueryLoading || isStreaming}>{isStreaming ? "Streaming..." : isAnalystQueryLoading ? "Asking..." : "Ask →"}</button></div>
                {analystQueryError ? <div className="report-error">{analystQueryError}</div> : null}
              </section>
              <aside className="panel ai-context-column">
                <h3>Current Threat Context</h3>
                <div className="context-card"><strong>Active Threats</strong><p>{queue.length} active · top: {plainThreatName(queue[0]?.attack_type || "NORMAL")}</p></div>
                <div className="context-card"><strong>Attack Origins</strong><p>{originHotspots.slice(0, 3).map((o) => `${countryLabel(o.country)} (${o.count})`).join(" · ") || "No active origins"}</p></div>
                <div className="context-card"><strong>Session Summary</strong><p>{totalEventsAnalyzed} events analyzed · {metrics.blockedIps} blocked</p></div>
                <div className="context-card"><strong>AI Capabilities</strong><ul><li>Explain any threat in plain English</li><li>Get step-by-step mitigation plan</li><li>Identify coordinated campaigns</li><li>Generate executive summary</li><li>Map attacks to MITRE techniques</li></ul></div>
              </aside>
            </div>
          ) : null}

          {currentView === "traffic" ? (
            <div className="view-fade">
              <section className="panel traffic-view"><h2>Network Traffic Analysis</h2><p className="panel-subtitle">Real-time traffic monitoring with anomaly detection</p><div className="legend-inline"><span><i className="blue" /> Normal traffic</span><span><i className="red" /> Anomalies detected</span></div><ResponsiveContainer width="100%" height={400}><AreaChart data={traffic} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}><defs><linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} /><stop offset="95%" stopColor="#3b82f6" stopOpacity={0.03} /></linearGradient><linearGradient id="gradAnomaly" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} /><stop offset="95%" stopColor="#ef4444" stopOpacity={0.03} /></linearGradient></defs><XAxis dataKey="second" stroke="rgba(255,255,255,0.1)" tick={{ fill: "#4b5d6e", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={{ stroke: "rgba(255,255,255,0.06)" }} tickLine={false} /><YAxis stroke="rgba(255,255,255,0.1)" tick={{ fill: "#4b5d6e", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={{ stroke: "rgba(255,255,255,0.06)" }} tickLine={false} width={30} /><Tooltip contentStyle={{ background: "#060f1e", border: "1px solid rgba(255,255,255,0.12)", borderRadius: "8px", color: "#e2e8f0", fontSize: "12px", boxShadow: "0 8px 24px rgba(0,0,0,0.6)" }} labelStyle={{ color: "#94a3b8", fontWeight: 600, marginBottom: 4 }} itemStyle={{ color: "#e2e8f0" }} /><Area type="monotone" dataKey="normal" stroke="#3b82f6" strokeWidth={2} fill="url(#gradNormal)" dot={false} activeDot={{ r: 4, fill: "#3b82f6", strokeWidth: 0 }} /><Area type="monotone" dataKey="anomaly" stroke="#ef4444" strokeWidth={2} fill="url(#gradAnomaly)" dot={false} activeDot={{ r: 4, fill: "#ef4444", strokeWidth: 0 }} /></AreaChart></ResponsiveContainer><div className="traffic-stats"><div className="context-card"><strong>Current traffic rate</strong><p>~1 event/sec</p></div><div className="context-card"><strong>Anomalies in last 10 min</strong><p>{queue.length}</p></div><div className="context-card"><strong>Peak anomaly time</strong><p>{queue[0] ? compactTime(queue[0].timestamp) : "N/A"}</p></div></div></section>
            </div>
          ) : null}

          {currentView === "origins" ? (
            <div className="view-fade origins-only-view">
              <section className="panel origins-hero-card full">
                <div className="origins-hero-head">
                  <div>
                    <p className="origins-kicker">Geo Correlation Monitor</p>
                    <h2>Where Are Attacks Coming From?</h2>
                  </div>
                  <div className="origins-hero-pill">● Live geolocation analysis</div>
                </div>

                <div className="origins-stat-strip">
                  <div>
                    <strong>{originHotspots.length}</strong>
                    <span>Active regions</span>
                  </div>
                  <div>
                    <strong>{originTotalSources}</strong>
                    <span>Tracked sources</span>
                  </div>
                  <div>
                    <strong>{metrics.blockedIps}</strong>
                    <span>IPs blocked</span>
                  </div>
                  <div>
                    <strong style={{ color: topOriginSpot ? "#ff6b6b" : "#64748b" }}>
                      {topOriginSpot ? countryLabel(topOriginSpot.country) : "—"}
                    </strong>
                    <span>Top threat origin</span>
                  </div>
                </div>

                <div className="world-map-canvas enhanced">
                  <div className="world-map-layer" aria-hidden="true">
                    <ComposableMap projection="geoNaturalEarth1" projectionConfig={{ scale: 170 }}>
                      <Geographies geography={WORLD_MAP_GEO_URL}>
                        {({ geographies }) =>
                          geographies.map((geo) => (
                            <Geography key={geo.rsmKey} geography={geo} className="map-geography" />
                          ))
                        }
                      </Geographies>
                    </ComposableMap>
                  </div>
                  {originHotspots.length === 0 ? (
                    <div className="map-empty-state">No threat origin hotspots yet — waiting for attack activity.</div>
                  ) : null}
                  {originHotspots.map((spot, idx) => (
                    <div key={spot.country} className="origin-dot" style={{ left: `${spot.x}%`, top: `${spot.y}%` }}>
                      <span className="origin-ping" style={{ background: idx === 0 ? "#ff334f" : idx === 1 ? "#ff8b2c" : "#f4ad38" }} />
                      <small>{countryLabel(spot.country)} · {spot.count}</small>
                    </div>
                  ))}
                </div>

                <div className="origin-map-legend">
                  <span><i className="high" /> High concentration</span>
                  <span><i className="med" /> Moderate</span>
                  <span><i className="low" /> Low</span>
                </div>

                <div className="origin-summary-list enhanced">
                  {originHotspots.length === 0 ? (
                    <div className="origin-summary-row empty">No regions ranked yet.</div>
                  ) : (
                    originHotspots.map((spot, idx) => {
                      const percent = originTotalSources > 0 ? Math.round((spot.count / originTotalSources) * 100) : 0;
                      const barColor = idx === 0 ? "linear-gradient(90deg,#ff334f,#ff6b2c)" : idx === 1 ? "linear-gradient(90deg,#ff8b2c,#f4c038)" : "linear-gradient(90deg,#2f7df6,#00c2a8)";
                      return (
                        <div key={`bar-${spot.country}`} className="origin-summary-row ranked">
                          <span>{countryLabel(spot.country)}</span>
                          <div className="origin-bar-wrap">
                            <div className="origin-bar-fill" style={{ width: `${Math.max(8, percent)}%`, background: barColor }} />
                          </div>
                          <strong>{spot.count} <em style={{ fontWeight: 400, color: "#64748b", fontStyle: "normal" }}>({percent}%)</em></strong>
                        </div>
                      );
                    })
                  )}
                </div>
              </section>

              <section className="panel user-anomaly-panel full enhanced">
                <div className="anomaly-head-row">
                  <div>
                    <h2>Behavioral Baseline Analysis</h2>
                    <p className="panel-subtitle" style={{ margin: "2px 0 0" }}>Is this login time suspicious for this user?</p>
                  </div>
                  <span className="anomaly-chip">Behavioral Baseline</span>
                </div>
                {anomalyPanelData ? (
                  <div className={`anomaly-headline ${anomalyPanelData.interpretation.tone}`} style={{ marginBottom: 12 }}>
                    {anomalyPanelData.interpretation.tone === "high"
                      ? "🚨 Highly suspicious login time"
                      : anomalyPanelData.interpretation.tone === "medium"
                      ? "⚠ Unusual login timing detected"
                      : "✓ Login time looks normal"}
                    <span style={{ marginLeft: 12, fontSize: "0.75rem", fontWeight: 400, opacity: 0.7 }}>
                      User: {latestAuthAnomaly?.username ?? "unknown"} · {latestAuthAnomaly?.source_ip ?? ""}
                    </span>
                  </div>
                ) : null}
                <div className="user-anomaly-chart-wrap">
                  {anomalyPanelData ? <Bar data={anomalyPanelData.chartData} options={anomalyChartOptions} /> : <div className="placeholder" style={{ color: "#475569", fontSize: "0.84rem", paddingTop: 40, textAlign: "center" }}>No suspicious login detected yet. Run a brute-force attack to see baseline analysis.</div>}
                </div>
                <p className="user-anomaly-deviation">
                  {anomalyPanelData
                    ? `At ${anomalyPanelData.eventHour}:00 — expected baseline activity: ${anomalyPanelData.expectedAtHour} · observed: ${anomalyPanelData.observedValue}. ${anomalyPanelData.interpretation.headline}.`
                    : ""}
                </p>
              </section>
            </div>
          ) : null}

          {currentView === "reports" ? (
            <div className="view-fade reports-view">
              <section className="reports-hero panel">
                <p className="reports-kicker">Executive Intelligence Workspace</p>
                <h2>Generate Reports</h2>
                <p className="panel-subtitle">Turn live SOC telemetry into clear executive and incident-ready narratives in one click.</p>
                <div className="reports-hero-metrics">
                  <div>
                    <strong>{queue.length}</strong>
                    <span>Active threats</span>
                  </div>
                  <div>
                    <strong>{totalEventsAnalyzed}</strong>
                    <span>Events analyzed</span>
                  </div>
                  <div>
                    <strong>{metrics.blockedIps}</strong>
                    <span>Auto-blocked</span>
                  </div>
                </div>
              </section>

              <div className="reports-grid">
                <article className="panel report-action-card board">
                  <div className="report-card-head">
                    <span className="report-icon">📊</span>
                    <span className="report-chip">Board Ready</span>
                  </div>
                  <h3>Board Report</h3>
                  <p>A 5-bullet non-technical summary suitable for executives and board members. No jargon.</p>
                  <button type="button" className="report-cta" onClick={() => void generateBoardReport()}>
                    Generate Board Report
                  </button>
                  <small>Last generated: {boardReportGeneratedAt ? boardGeneratedLabel : "Not yet generated"}</small>
                </article>

                <article className="panel report-action-card incident">
                  <div className="report-card-head">
                    <span className="report-icon">📄</span>
                    <span className="report-chip">SOC Deep Dive</span>
                  </div>
                  <h3>Incident Report</h3>
                  <p>A structured technical report with timeline, attack vectors, and recommended next steps.</p>
                  <button type="button" className="report-cta" onClick={() => void generateIncidentReport()}>
                    Generate IR Report
                  </button>
                  <small>Last generated: {incidentReportGeneratedAt ? incidentGeneratedLabel : "Not yet generated"}</small>
                </article>
              </div>

              {boardReport || incidentReport ? (
                <section className="panel report-preview">
                  <div className="report-preview-head">
                    <div>
                      <h3>Latest Generated Report</h3>
                      <p>{boardReport ? "Board Report" : "Incident Report"}</p>
                    </div>
                    <div className="report-preview-actions">
                      <button
                        type="button"
                        onClick={() => {
                          const text = boardReport || incidentReport || "";
                          void navigator.clipboard.writeText(text);
                        }}
                      >
                        Copy
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          saveReportAsFile(
                            boardReport ? "board-report" : "incident-report",
                            boardReport || incidentReport || ""
                          )
                        }
                      >
                        Download
                      </button>
                    </div>
                  </div>
                  <pre>{boardReport || incidentReport}</pre>
                </section>
              ) : null}
            </div>
          ) : null}

        </div>
      </section>

      {isIncidentModalOpen ? (
        <div
          className="report-modal-overlay"
          role="dialog"
          aria-modal="true"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              closeIncidentModal();
            }
          }}
        >
          <div className="report-modal">
            <div className="report-modal-head">
              <h3>Incident Report</h3>
              <button type="button" className="report-close" onClick={closeIncidentModal}>
                ×
              </button>
            </div>
            <p className="report-generated-note">{`Generated ${incidentGeneratedLabel}`}</p>
            {isReportLoading ? (
              <div className="report-loading">
                <span className="report-spinner" aria-hidden="true" />
                <p>Generating report...</p>
              </div>
            ) : null}
            {reportError ? (
              <div className="report-modal-error">
                <p>{reportError}</p>
                <button type="button" onClick={() => void generateIncidentReport()}>
                  Retry
                </button>
              </div>
            ) : null}
            {incidentReport ? (
              <div className="incident-report-content">
                {incidentReport.split(/\r?\n/).map((line, idx) => {
                  const normalized = line.trim();
                  if (!normalized) return <div key={`line-${idx}`} className="incident-line-gap" />;
                  if (INCIDENT_HEADERS.has(normalized.toUpperCase())) {
                    return (
                      <p key={`line-${idx}`} className="incident-report-header">
                        {normalized}
                      </p>
                    );
                  }
                  return (
                    <p key={`line-${idx}`} className="incident-report-line">
                      {line}
                    </p>
                  );
                })}
              </div>
            ) : null}
            {!isReportLoading && !reportError && incidentReport ? (
              <div className="report-modal-actions">
                <button type="button" onClick={() => void copyReportToClipboard()}>
                  📋 Copy
                </button>
                <button type="button" onClick={() => saveReportAsPdf("Incident Report", incidentReport, "incident-report")}>
                  ⬇ Download PDF
                </button>
                <button type="button" onClick={closeIncidentModal}>
                  Close
                </button>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {isBoardModalOpen ? (
        <div
          className="board-modal-overlay"
          role="dialog"
          aria-modal="true"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              closeBoardModal();
            }
          }}
        >
          <div className="board-modal">
            <div className="board-modal-head">
              <h3>Executive Security Summary</h3>
            </div>
            {isBoardReportLoading ? (
              <div className="report-loading">
                <span className="report-spinner" aria-hidden="true" />
                <p>Generating summary...</p>
              </div>
            ) : null}
            {boardReportError ? (
              <div className="report-modal-error">
                <p>{boardReportError}</p>
                <button type="button" onClick={() => void generateBoardReport()}>
                  Retry
                </button>
              </div>
            ) : null}
            {boardReport ? (
              <>
                <div className="board-summary-list">
                  {boardReportParsed.rows.map((row) => (
                    <div
                      key={row.key}
                      className="board-summary-row"
                      style={{ borderLeftColor: BOARD_BORDER_BY_KEY[row.key] ?? "#9fb3d6" }}
                    >
                      <strong>{row.key}</strong>
                      <p>{row.value}</p>
                    </div>
                  ))}
                </div>
                {boardReportParsed.bottomLine ? (
                  <div className="board-bottom-line">
                    <strong>BOTTOM LINE</strong>
                    <p>{boardReportParsed.bottomLine}</p>
                  </div>
                ) : null}
                <div className="board-generated-note">
                  {`Generated by SENTINEL AI-SOC · ${boardGeneratedLabel}`}
                </div>
              </>
            ) : null}
            {!isBoardReportLoading && !boardReportError && boardReport ? (
              <div className="board-modal-actions">
                <button type="button" onClick={() => void copyBoardReport()}>
                  📋 Copy
                </button>
                <button type="button" onClick={() => saveReportAsPdf("Executive Security Summary", boardReport, "board-report")}>
                  ⬇ Download PDF
                </button>
                <button type="button" onClick={closeBoardModal}>
                  Close
                </button>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      <div className="toast-stack">
        {responseToasts.map((toast) => (
          <div
            key={toast.id}
            className={`toast response-toast ${toast.exiting ? "is-exiting" : ""}`}
          >
            <div className="response-toast-head">
              <strong>{toast.title}</strong>
              <button
                type="button"
                className="response-toast-dismiss"
                onClick={() => dismissResponseToast(toast.id)}
                aria-label="Dismiss response toast"
              >
                ×
              </button>
            </div>
            <div className="response-toast-body">
              {toast.lines.map((line) => (
                <p key={`${toast.id}-${line}`}>• {line}</p>
              ))}
            </div>
            <div className="response-toast-progress" />
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
