import { loadMetrics, saveMetrics } from "./metricsStore";

export interface ServiceMetrics {
  startedAt: string;
  totals: {
    requests: number;
    allow: number;
    deny: number;
  };
  denyByCode: Record<string, number>;
}

const metrics: ServiceMetrics =
  loadMetrics() ?? {
    startedAt: new Date().toISOString(),
    totals: {
      requests: 0,
      allow: 0,
      deny: 0,
    },
    denyByCode: {},
  };

export function recordDecision(decision: "ALLOW" | "DENY", decisionCode: string): void {
  metrics.totals.requests += 1;
  if (decision === "ALLOW") {
    metrics.totals.allow += 1;
    saveMetrics(metrics);
    return;
  }

  metrics.totals.deny += 1;
  metrics.denyByCode[decisionCode] = (metrics.denyByCode[decisionCode] ?? 0) + 1;
  saveMetrics(metrics);
}

export function getMetricsSnapshot(): ServiceMetrics {
  return {
    startedAt: metrics.startedAt,
    totals: { ...metrics.totals },
    denyByCode: { ...metrics.denyByCode },
  };
}
