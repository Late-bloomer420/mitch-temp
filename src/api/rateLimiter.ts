const hits = new Map<string, number[]>();

export interface RateLimitConfig {
  windowSeconds: number;
  maxRequestsPerRequester: number;
}

export function checkRateLimit(requesterId: string, cfg: RateLimitConfig): boolean {
  const now = Date.now();
  const windowMs = cfg.windowSeconds * 1000;
  const arr = hits.get(requesterId) ?? [];
  const kept = arr.filter((t) => now - t <= windowMs);
  if (kept.length >= cfg.maxRequestsPerRequester) {
    hits.set(requesterId, kept);
    return false;
  }
  kept.push(now);
  hits.set(requesterId, kept);
  return true;
}
