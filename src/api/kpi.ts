import { readFileSync, existsSync } from "fs";

const EVENTS_PATH = "./data/events.jsonl";

interface ParsedEvent {
  eventType?: string;
  decision?: "ALLOW" | "DENY";
  decisionCode?: string;
  latencyMs?: number;
}

function readEvents(): ParsedEvent[] {
  if (!existsSync(EVENTS_PATH)) return [];
  const raw = readFileSync(EVENTS_PATH, "utf8").trim();
  if (!raw) return [];
  return raw
    .split("\n")
    .map((line) => {
      try {
        return JSON.parse(line) as ParsedEvent;
      } catch {
        return {} as ParsedEvent;
      }
    })
    .filter((e) => Object.keys(e).length > 0);
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

export function getKpiSnapshot(): Record<string, number> {
  const events = readEvents();
  const decisions = events.filter((e) => e.eventType === "decision_made");
  const allows = decisions.filter((e) => e.decision === "ALLOW").length;
  const denies = decisions.filter((e) => e.decision === "DENY").length;
  const total = decisions.length;

  const falseDenyProxy = decisions.filter((e) => e.decisionCode === "DENY_INTERNAL_SAFE_FAILURE").length;
  const overrideProxy = 0; // placeholder until explicit override events exist
  const replayDenies = decisions.filter((e) => e.decisionCode === "DENY_BINDING_NONCE_REPLAY").length;
  const replayAttempts = replayDenies;

  const latencies = decisions
    .map((e) => e.latencyMs)
    .filter((v): v is number => typeof v === "number" && v >= 0);

  return {
    decisions_total: total,
    allow_total: allows,
    deny_total: denies,
    verification_success_rate: total > 0 ? allows / total : 0,
    replay_block_rate: replayAttempts > 0 ? replayDenies / replayAttempts : 1,
    false_deny_proxy_rate: total > 0 ? falseDenyProxy / total : 0,
    policy_override_rate: overrideProxy,
    latency_p50_ms: percentile(latencies, 50),
    latency_p95_ms: percentile(latencies, 95),
  };
}
