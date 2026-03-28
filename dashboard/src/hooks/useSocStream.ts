import { useEffect, useMemo, useRef, useState } from "react";
import {
  ClassificationState,
  CoordinatedCampaignEvent,
  CounterfactualPanel,
  DwellEntry,
  MetricState,
  ResponseFiredEvent,
  ResponseToast,
  ThreatEvent,
  TrafficPoint,
  UserBehaviorAnomalyEvent,
} from "../types";

const MAX_EVENT_LOG = 120;
const MAX_QUEUE = 12;
const MAX_RESPONSE_TOASTS = 6;
const MAX_TRAFFIC_SECONDS = 60;
const UI_FLUSH_INTERVAL_MS = 500;
const CLASSIFICATION_WINDOW = 160;
const RESPONSE_TOAST_LIFETIME_MS = 6000;
const RESPONSE_TOAST_EXIT_MS = 300;
const COUNTERFACTUAL_LIFETIME_MS = 25000;

const preloadEvents = (): ThreatEvent[] => [];

const INITIAL_METRICS: MetricState = {
  critical: 0,
  high: 0,
  blockedIps: 0,
  failedLogins: 0,
};

const INITIAL_CLASSIFICATION: ClassificationState = {
  BRUTE_FORCE: 0,
  PORT_SCAN: 0,
  PHISHING: 0,
  OTHERS: 0,
};

const isResponseFiredEvent = (payload: unknown): payload is ResponseFiredEvent => {
  if (!payload || typeof payload !== "object") return false;
  const event = payload as Partial<ResponseFiredEvent>;
  return event.type === "response_fired" && Array.isArray(event.actions);
};

const isCoordinatedCampaignEvent = (payload: unknown): payload is CoordinatedCampaignEvent => {
  if (!payload || typeof payload !== "object") return false;
  const event = payload as Partial<CoordinatedCampaignEvent>;
  return event.type === "campaign_detected" && Array.isArray(event.attack_types);
};

const CLASSIFICATION_EXCLUDE_TYPES = new Set([
  "NORMAL",
  "SYSTEM",
  "BLOCKED_SOURCE",
  "COORDINATED_CAMPAIGN",
  "CAMPAIGN_DETECTED",
]);

const normalizeAttackType = (attackType: string): string => {
  const normalized = String(attackType || "").trim().toUpperCase().replace(/\s+/g, "_");
  if (normalized === "BRUTEFORCE") return "BRUTE_FORCE";
  if (normalized === "PORTSCAN") return "PORT_SCAN";
  return normalized;
};

const getClassificationAttackType = (event: ThreatEvent): string => {
  const primary = normalizeAttackType(event.attack_type);
  if (primary === "BLOCKED_SOURCE") {
    return normalizeAttackType(event.attempted_attack_type || "");
  }
  return primary;
};

const classificationKey = (attackType: string): keyof ClassificationState => {
  const normalized = normalizeAttackType(attackType);
  if (normalized === "BRUTE_FORCE") return "BRUTE_FORCE";
  if (normalized === "PORT_SCAN") return "PORT_SCAN";
  if (normalized === "PHISHING") return "PHISHING";
  return "OTHERS";
};

const secondBucket = (isoTimestamp: string): string => {
  const d = new Date(isoTimestamp);
  return `${d.getHours().toString().padStart(2, "0")}:${d
    .getMinutes()
    .toString()
    .padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
};

export const useSocStream = (url: string) => {
  const apiBase = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8001";
  const [isConnected, setIsConnected] = useState(false);
  const [events, setEvents] = useState<ThreatEvent[]>(preloadEvents());
  const [queue, setQueue] = useState<ThreatEvent[]>([]);
  const [metrics, setMetrics] = useState<MetricState>(INITIAL_METRICS);
  const [classification, setClassification] =
    useState<ClassificationState>(INITIAL_CLASSIFICATION);
  const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
  const [responseToasts, setResponseToasts] = useState<ResponseToast[]>([]);
  const [counterfactualPanels, setCounterfactualPanels] = useState<CounterfactualPanel[]>([]);
  const [dwellByIp, setDwellByIp] = useState<Record<string, DwellEntry>>({});
  const [coordinatedCampaign, setCoordinatedCampaign] = useState<CoordinatedCampaignEvent | null>(null);
  const [isCampaignBannerDismissed, setIsCampaignBannerDismissed] = useState(false);
  const [latestAuthAnomaly, setLatestAuthAnomaly] = useState<UserBehaviorAnomalyEvent | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const blockedIpSet = useRef<Set<string>>(new Set());
  const responseToastTimers = useRef<number[]>([]);
  const responseToastExitTimers = useRef<number[]>([]);
  const counterfactualTimers = useRef<number[]>([]);
  const counterfactualTimerById = useRef<Record<string, number>>({});
  const counterfactualRemainingById = useRef<Record<string, number>>({});
  const counterfactualStartById = useRef<Record<string, number>>({});
  const bufferedEvents = useRef<ThreatEvent[]>([]);
  const recentAttackTypes = useRef<string[]>([]);
  const dwellStateRef = useRef<Record<string, DwellEntry>>({});
  const persistenceInsightTriggered = useRef<Set<string>>(new Set());

  const parseCounterfactualText = (
    text: string,
    context?: { source_ip?: string; attack_type?: string }
  ): {
    next_move: string;
    at_risk: string;
    time_to_breach: string;
    blast_radius: string;
  } => {
    const lines = String(text || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    const cleanedText = lines
      .join("\n")
      .replace(/\*\*/g, "")
      .replace(/`/g, "")
      .trim();

    const attackType = String(context?.attack_type || "UNKNOWN")
      .toLowerCase()
      .replace(/_/g, " ")
      .trim();
    const sourceIp = String(context?.source_ip || "unknown").trim();
    const contextualAttack = attackType && attackType !== "unknown" ? attackType : "detected activity";
    const contextualSource = sourceIp && sourceIp !== "unknown" ? sourceIp : "the source";

    const pick = (prefix: string, fallback: string): string => {
      const line = lines.find((entry) => entry.toUpperCase().startsWith(prefix));
      if (!line) return fallback;
      const value = line.slice(prefix.length).trim();
      if (!value) return fallback;
      if (value.toLowerCase().includes("unknown from available telemetry")) return fallback;
      return value;
    };

    const pickRegex = (regex: RegExp, fallback: string): string => {
      const match = cleanedText.match(regex);
      if (!match) return fallback;
      const value = String(match[1] || "").trim();
      if (!value) return fallback;
      if (value.toLowerCase().includes("unknown from available telemetry")) return fallback;
      return value;
    };

    const nextMoveFallback = `Likely continuation of ${contextualAttack} attempts from ${contextualSource}.`;
    const atRiskFallback = "Internet-facing authentication and application services remain the primary exposure.";
    const timeFallback = "15-45 minutes if not contained.";
    const blastFallback = "Risk of account compromise and follow-on lateral movement in connected systems.";

    const nextMove =
      pick("NEXT MOVE:", "") ||
      pickRegex(/next\s*move\s*[:\-]\s*(.+?)(?:\n|$)/i, "") ||
      nextMoveFallback;
    const atRisk =
      pick("AT RISK:", "") ||
      pickRegex(/at\s*risk\s*[:\-]\s*(.+?)(?:\n|$)/i, "") ||
      atRiskFallback;
    const timeToBreach =
      pick("TIME TO BREACH:", "") ||
      pickRegex(/time\s*to\s*breach\s*[:\-]\s*(.+?)(?:\n|$)/i, "") ||
      timeFallback;
    const blastRadius =
      pick("BLAST RADIUS:", "") ||
      pickRegex(/blast\s*radius\s*[:\-]\s*(.+?)(?:\n|$)/i, "") ||
      blastFallback;

    return {
      next_move: nextMove,
      at_risk: atRisk,
      time_to_breach: timeToBreach,
      blast_radius: blastRadius,
    };
  };

  const scheduleCounterfactualDismiss = (id: string, ms: number) => {
    if (counterfactualTimerById.current[id]) {
      window.clearTimeout(counterfactualTimerById.current[id]);
      delete counterfactualTimerById.current[id];
    }
    counterfactualStartById.current[id] = Date.now();
    counterfactualRemainingById.current[id] = ms;

    const timer = window.setTimeout(() => {
      setCounterfactualPanels((prev) => prev.filter((item) => item.id !== id));
      delete counterfactualTimerById.current[id];
      delete counterfactualStartById.current[id];
      delete counterfactualRemainingById.current[id];
    }, Math.max(0, ms));

    counterfactualTimerById.current[id] = timer;
    counterfactualTimers.current.push(timer);
  };

  const setCounterfactualHover = (id: string, hovered: boolean) => {
    setCounterfactualPanels((prev) => prev.map((panel) => (panel.id === id ? { ...panel, hovered } : panel)));

    if (hovered) {
      const activeTimer = counterfactualTimerById.current[id];
      if (!activeTimer) return;
      window.clearTimeout(activeTimer);
      delete counterfactualTimerById.current[id];

      const startedAt = counterfactualStartById.current[id] ?? Date.now();
      const previousRemaining = counterfactualRemainingById.current[id] ?? COUNTERFACTUAL_LIFETIME_MS;
      const elapsed = Date.now() - startedAt;
      counterfactualRemainingById.current[id] = Math.max(0, previousRemaining - elapsed);
      return;
    }

    const remaining = counterfactualRemainingById.current[id] ?? COUNTERFACTUAL_LIFETIME_MS;
    scheduleCounterfactualDismiss(id, remaining);
  };

  const dismissResponseToast = (id: string) => {
    setResponseToasts((prev) => prev.map((toast) => (toast.id === id ? { ...toast, exiting: true } : toast)));
    const timer = window.setTimeout(() => {
      setResponseToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, RESPONSE_TOAST_EXIT_MS);
    responseToastExitTimers.current.push(timer);
  };

  const pushResponseToast = (event: ResponseFiredEvent) => {
    const lines = (event.actions ?? [])
      .map((line) => String(line || "").trim())
      .filter(Boolean);
    if (lines.length === 0) {
      return;
    }

    const toastId = `${event.timestamp}-${Math.random().toString(36).slice(2, 8)}`;
    setResponseToasts((prev) => {
      const next = [{ id: toastId, title: "🛡️ SENTINEL Responded", lines, exiting: false }, ...prev];
      return next.slice(0, MAX_RESPONSE_TOASTS);
    });

    const timer = window.setTimeout(() => {
      dismissResponseToast(toastId);
    }, RESPONSE_TOAST_LIFETIME_MS);
    responseToastTimers.current.push(timer);
  };

  const pushCounterfactualPanel = (event: ResponseFiredEvent) => {
    if (!event.counterfactual) return;
    const sourceIp = String(event.source_ip || "unknown");
    const attackType = String(event.attack_type || "UNKNOWN");
    const panelId = `${sourceIp}:${attackType}:${event.timestamp}`;
    const parsed = parseCounterfactualText(event.counterfactual?.text || "Projection unavailable", {
      source_ip: sourceIp,
      attack_type: attackType,
    });
    setCounterfactualPanels((prev) => {
      const next = [
        {
          id: panelId,
          source_ip: sourceIp,
          attack_type: attackType,
          title: event.counterfactual?.title || "⚡ If SENTINEL hadn't responded...",
          text: event.counterfactual?.text || "Projection unavailable",
          badge: event.counterfactual?.badge || "simulated",
          timestamp: String(event.timestamp || new Date().toISOString()),
          next_move: parsed.next_move,
          at_risk: parsed.at_risk,
          time_to_breach: parsed.time_to_breach,
          blast_radius: parsed.blast_radius,
          hovered: false,
        },
        ...prev.filter((item) => `${item.source_ip}:${item.attack_type}` !== `${sourceIp}:${attackType}`),
      ];
      return next.slice(0, 8);
    });

    scheduleCounterfactualDismiss(panelId, COUNTERFACTUAL_LIFETIME_MS);
  };

  const dismissCounterfactualPanel = (id: string) => {
    const activeTimer = counterfactualTimerById.current[id];
    if (activeTimer) {
      window.clearTimeout(activeTimer);
      delete counterfactualTimerById.current[id];
    }
    delete counterfactualStartById.current[id];
    delete counterfactualRemainingById.current[id];
    setCounterfactualPanels((prev) => prev.filter((panel) => panel.id !== id));
  };

  useEffect(() => {
    const ws = new WebSocket(url);
    const flushTimer = window.setInterval(() => {
      const pending = bufferedEvents.current;
      if (pending.length === 0) return;

      bufferedEvents.current = [];

      setEvents((prev) => [...pending.reverse(), ...prev].slice(0, MAX_EVENT_LOG));

      const nextDwell = { ...dwellStateRef.current };
      for (const event of pending) {
        const ip = String(event.source_ip || "").trim();
        if (!ip) continue;

        const eventTimestamp = String(event.timestamp || new Date().toISOString());
        const backendDwellSeconds = Math.max(0, Number(event.dwell_seconds || 0));
        const backendEventCount = Math.max(1, Number(event.event_count || 1));
        const backendPersistent = Boolean(event.is_persistent);
        const firstSeenFromBackend = new Date(
          new Date(eventTimestamp).getTime() - backendDwellSeconds * 1000
        ).toISOString();

        const existing = nextDwell[ip];
        if (!existing) {
          nextDwell[ip] = {
            first_seen: firstSeenFromBackend,
            last_seen: eventTimestamp,
            count: backendEventCount,
            dwell_seconds: backendDwellSeconds,
            is_persistent: backendPersistent,
          };
          continue;
        }

        existing.last_seen = eventTimestamp;
        existing.first_seen = firstSeenFromBackend;
        existing.count = backendEventCount;
        existing.dwell_seconds = backendDwellSeconds;
        existing.is_persistent = backendPersistent;
      }
      dwellStateRef.current = nextDwell;
      setDwellByIp(nextDwell);

      const highRisk = pending.filter(
        (event) => event.severity === "HIGH" || event.severity === "CRITICAL"
      );
      if (highRisk.length > 0) {
        setQueue((prev) => {
          const byKey = new Map<string, ThreatEvent>();
          for (const item of prev) {
            byKey.set(`${item.source_ip}:${item.attack_type}`, item);
          }
          for (const item of highRisk) {
            byKey.set(`${item.source_ip}:${item.attack_type}`, item);
          }
          const merged = Array.from(byKey.values());
          merged.sort((a, b) => b.risk_score - a.risk_score);
          return merged.slice(0, MAX_QUEUE);
        });
      }

      setMetrics((prev) => {
        const next = { ...prev };
        for (const event of pending) {
          if (event.severity === "CRITICAL") next.critical += 1;
          if (event.severity === "HIGH") next.high += 1;
          if (event.event_type === "login" && event.status === "failure") {
            next.failedLogins += 1;
          }

          for (const action of event.actions ?? []) {
            if (action.action === "block_ip" && action.target) {
              if (!blockedIpSet.current.has(action.target)) {
                blockedIpSet.current.add(action.target);
              }
            }
          }
        }
        next.blockedIps = blockedIpSet.current.size;
        return next;
      });

      setClassification(() => {
        const next: ClassificationState = {
          BRUTE_FORCE: 0,
          PORT_SCAN: 0,
          PHISHING: 0,
          OTHERS: 0,
        };
        for (const event of pending) {
          const attackType = getClassificationAttackType(event);
          if (!attackType || CLASSIFICATION_EXCLUDE_TYPES.has(attackType)) {
            continue;
          }
          recentAttackTypes.current.push(attackType);
        }

        if (recentAttackTypes.current.length > CLASSIFICATION_WINDOW) {
          recentAttackTypes.current = recentAttackTypes.current.slice(-CLASSIFICATION_WINDOW);
        }

        for (const attackType of recentAttackTypes.current) {
          const key = classificationKey(attackType || "OTHERS");
          next[key] += 1;
        }
        return next;
      });

      setTraffic((prev) => {
        const nextMap = new Map(prev.map((item) => [item.second, item]));
        for (const event of pending) {
          const bucket = secondBucket(event.timestamp);
          const current = nextMap.get(bucket) ?? { second: bucket, normal: 0, anomaly: 0 };
          if (event.is_attack || event.attack_type !== "NORMAL") {
            current.anomaly += 1;
          } else {
            current.normal += 1;
          }
          nextMap.set(bucket, current);
        }
        return Array.from(nextMap.values()).slice(-MAX_TRAFFIC_SECONDS);
      });

      let latestAuthEvent: ThreatEvent | null = null;
      for (const event of pending) {
        const isAuthRelated =
          String(event.event_type || "").toLowerCase() === "login" ||
          Boolean(event.username && String(event.username).toLowerCase() !== "unknown");
        const highOrMed = event.severity === "HIGH" || event.severity === "MEDIUM";
        if (!isAuthRelated || !highOrMed) {
          continue;
        }

        if (!latestAuthEvent) {
          latestAuthEvent = event;
          continue;
        }

        const candidateTs = new Date(event.timestamp).getTime();
        const currentTs = new Date(latestAuthEvent.timestamp).getTime();
        if (!Number.isNaN(candidateTs) && (Number.isNaN(currentTs) || candidateTs > currentTs)) {
          latestAuthEvent = event;
        }
      }

      if (latestAuthEvent) {
        setLatestAuthAnomaly({
          username: String(latestAuthEvent.username || "unknown"),
          timestamp: latestAuthEvent.timestamp,
          severity: latestAuthEvent.severity,
          source_ip: latestAuthEvent.source_ip,
          attack_type: latestAuthEvent.attack_type,
          anomaly_score: Number(latestAuthEvent.anomaly_score || 0),
        });
      }

    }, UI_FLUSH_INTERVAL_MS);

    ws.onopen = () => {
      setIsConnected(true);
      setStreamError(null);

      fetch(`${apiBase}/api/operator/blocked`)
        .then(res => res.json())
        .then(data => {
          if (data?.status === "success" && Array.isArray(data.data)) {
            let changed = false;
            for (const ip of data.data) {
              if (typeof ip === 'string' && !blockedIpSet.current.has(ip)) {
                blockedIpSet.current.add(ip);
                changed = true;
              }
            }
            if (changed) {
              setMetrics(prev => ({ ...prev, blockedIps: blockedIpSet.current.size }));
            }
          }
        })
        .catch(() => {});

      // Load real historical events from the database
      fetch(`${apiBase}/api/events/history?limit=120`)
        .then(res => res.json())
        .then(data => {
          if (data?.status === "success" && Array.isArray(data.data) && data.data.length > 0) {
            const dbEvents: ThreatEvent[] = data.data.map((e: Record<string, unknown>) => ({
              timestamp: String(e.timestamp || ""),
              source_ip: String(e.source_ip || "unknown"),
              destination_ip: String(e.destination_ip || "unknown"),
              destination_port: Number(e.destination_port || 0),
              event_type: String(e.event_type || "request"),
              protocol: String(e.protocol || "TCP"),
              status: String(e.status || "unknown"),
              country: String(e.country || "XX"),
              is_attack: Boolean(e.is_attack),
              attack_type: String(e.attack_type || "NORMAL"),
              anomaly_score: Number(e.anomaly_score || 0),
              risk_score: Number(e.risk_score || 0),
              severity: String(e.severity || "LOW"),
              reason: String(e.description || ""),
              actions: [],
            }));
            setEvents(dbEvents);
          }
        })
        .catch(() => {});
    };
    ws.onclose = () => {
      setIsConnected(false);
      setStreamError("Data temporarily unavailable");
    };
    ws.onerror = () => {
      setIsConnected(false);
      setStreamError("Data temporarily unavailable");
    };

    ws.onmessage = (msg) => {
      let payload: unknown;
      try {
        payload = JSON.parse(msg.data);
      } catch {
        setStreamError("Data temporarily unavailable");
        return;
      }

      const incoming = Array.isArray(payload) ? payload : [payload];
      for (const event of incoming) {
        if (isResponseFiredEvent(event)) {
          pushResponseToast(event);
          pushCounterfactualPanel(event);

          const blockedIp = event.source_ip?.trim();
          if (blockedIp) {
            if (!blockedIpSet.current.has(blockedIp)) {
              blockedIpSet.current.add(blockedIp);
            }
            setMetrics((prev) => ({
              ...prev,
              blockedIps: blockedIpSet.current.size,
            }));
            setQueue((prev) => prev.filter((t) => t.source_ip !== blockedIp));
          }
          continue;
        }

        if (isCoordinatedCampaignEvent(event)) {
          setCoordinatedCampaign(event);
          setIsCampaignBannerDismissed(false);
          continue;
        }

        const threat = event as ThreatEvent;
        if (!threat || !threat.timestamp || !threat.source_ip) {
          continue;
        }
        bufferedEvents.current.push(threat);
      }
    };

    return () => {
      window.clearInterval(flushTimer);
      for (const timer of responseToastTimers.current) {
        window.clearTimeout(timer);
      }
      for (const timer of responseToastExitTimers.current) {
        window.clearTimeout(timer);
      }
      for (const timer of counterfactualTimers.current) {
        window.clearTimeout(timer);
      }
      responseToastTimers.current = [];
      responseToastExitTimers.current = [];
      counterfactualTimers.current = [];
      counterfactualTimerById.current = {};
      counterfactualStartById.current = {};
      counterfactualRemainingById.current = {};
      ws.close();
    };
  }, [url]);

  const latestHighRisk = useMemo(() => queue[0] ?? null, [queue]);
  const persistentThreatCount = useMemo(() => {
    return Object.values(dwellByIp).filter((entry) => Boolean(entry.is_persistent)).length;
  }, [dwellByIp]);
  const isCoordinatedCritical = Boolean(coordinatedCampaign);
  const dismissCampaignBanner = () => setIsCampaignBannerDismissed(true);

  useEffect(() => {
    const now = Date.now();
    for (const threat of queue) {
      const ip = String(threat.source_ip || "").trim();
      if (!ip) continue;
      if (persistenceInsightTriggered.current.has(ip)) continue;

      const dwell = dwellByIp[ip];
      if (!dwell) continue;

      const firstSeenMs = new Date(dwell.first_seen).getTime();
      if (Number.isNaN(firstSeenMs)) continue;
      const dwellMs = now - firstSeenMs;
      if (dwellMs <= 2 * 60 * 60 * 1000) continue;

      const dwellHours = Math.floor(dwellMs / (60 * 60 * 1000));
      const dwellMinutes = Math.floor((dwellMs % (60 * 60 * 1000)) / (60 * 1000));
      const dwellText = `${dwellHours}h ${dwellMinutes}m`;

      persistenceInsightTriggered.current.add(ip);
      void fetch(`${apiBase}/api/analyst/persistence-insight`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_ip: ip,
          dwell_time: dwellText,
          threat,
        }),
      }).catch(() => {
        // Keep silent for demo stability.
      });
    }
  }, [apiBase, dwellByIp, queue]);

  return {
    isConnected,
    events,
    queue,
    metrics,
    classification,
    traffic,
    responseToasts,
    dismissResponseToast,
    counterfactualPanels,
    dismissCounterfactualPanel,
    setCounterfactualHover,
    dwellByIp,
    persistentThreatCount,
    coordinatedCampaign,
    isCampaignBannerDismissed,
    dismissCampaignBanner,
    isCoordinatedCritical,
    latestAuthAnomaly,
    latestHighRisk,
    streamError,
    blockedIpsArray: Array.from(blockedIpSet.current),
  };
};
