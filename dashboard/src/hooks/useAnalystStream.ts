import { useCallback, useEffect, useRef, useState } from "react";
import type { ThreatEvent } from "../types";

type StreamState = "idle" | "connecting" | "streaming" | "done" | "error";

export type AnalystStreamResult = {
  /** The progressively revealed text — grows word by word while streaming. */
  streamedText: string;
  state: StreamState;
  /** True while the stream is actively receiving words. */
  isStreaming: boolean;
  /** Start streaming for a given query + optional threat context. */
  startStream: (query: string, threat?: ThreatEvent | null) => void;
  /** Abort in-flight stream and reset to idle. */
  reset: () => void;
};

const WS_BASE =
  (import.meta.env.VITE_WS_BASE as string | undefined) ??
  "ws://localhost:8001";

export const useAnalystStream = (): AnalystStreamResult => {
  const [streamedText, setStreamedText] = useState("");
  const [state, setState] = useState<StreamState>("idle");
  const wsRef = useRef<WebSocket | null>(null);

  // Close any open socket cleanly.
  const closeSocket = useCallback(() => {
    const ws = wsRef.current;
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      ws.close();
    }
    wsRef.current = null;
  }, []);

  const reset = useCallback(() => {
    closeSocket();
    setStreamedText("");
    setState("idle");
  }, [closeSocket]);

  const startStream = useCallback(
    (query: string, threat?: ThreatEvent | null) => {
      closeSocket();
      setStreamedText("");
      setState("connecting");

      const ws = new WebSocket(`${WS_BASE}/api/analyst/stream`);
      wsRef.current = ws;

      ws.onopen = () => {
        setState("streaming");
        ws.send(JSON.stringify({ query, threat: threat ?? null }));
      };

      ws.onmessage = (msg: MessageEvent) => {
        let payload: unknown;
        try {
          payload = JSON.parse(msg.data as string);
        } catch {
          return;
        }

        if (!payload || typeof payload !== "object") return;
        const event = payload as Record<string, unknown>;

        if (event.type === "analysis_stream") {
          const chunk = String(event.chunk ?? "");
          setStreamedText((prev) => prev + chunk);
        } else if (event.type === "analysis_stream_end") {
          setState("done");
          closeSocket();
        } else if (event.type === "analysis_stream_error") {
          setState("error");
          closeSocket();
        }
      };

      ws.onerror = () => {
        setState("error");
        closeSocket();
      };

      ws.onclose = () => {
        // If we close without receiving stream_end, mark done so UI doesn't hang.
        setState((prev) => (prev === "streaming" || prev === "connecting" ? "done" : prev));
        wsRef.current = null;
      };
    },
    [closeSocket]
  );

  // Cleanup on unmount.
  useEffect(() => {
    return () => {
      closeSocket();
    };
  }, [closeSocket]);

  return {
    streamedText,
    state,
    isStreaming: state === "streaming" || state === "connecting",
    startStream,
    reset,
  };
};
