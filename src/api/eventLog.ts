import { appendFileSync, existsSync, mkdirSync } from "fs";
import { dirname } from "path";

export type EventType =
  | "request_received"
  | "decision_made"
  | "request_rejected_auth"
  | "request_rejected_schema";

export interface AuditEvent {
  at: string;
  eventType: EventType;
  correlationId: string;
  requestId?: string;
  rpId?: string;
  decision?: "ALLOW" | "DENY";
  decisionCode?: string;
  latencyMs?: number;
}

const EVENTS_PATH = "./data/events.jsonl";

function ensureDir(): void {
  const dir = dirname(EVENTS_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

export function appendEvent(event: AuditEvent): void {
  ensureDir();
  appendFileSync(EVENTS_PATH, JSON.stringify(event) + "\n", "utf8");
}
