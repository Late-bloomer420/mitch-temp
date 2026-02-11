export interface ServiceMetrics {
  startedAt: string;
  totals: {
    requests: number;
    allow: number;
    deny: number;
  };
  denyByCode: Record<string, number>;
}

const metrics: ServiceMetrics = {
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
    return;
  }

  metrics.totals.deny += 1;
  metrics.denyByCode[decisionCode] = (metrics.denyByCode[decisionCode] ?? 0) + 1;
}

export function getMetricsSnapshot(): ServiceMetrics {
  return {
    startedAt: metrics.startedAt,
    totals: { ...metrics.totals },
    denyByCode: { ...metrics.denyByCode },
  };
}
