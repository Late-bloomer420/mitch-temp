import { createServer, IncomingMessage, ServerResponse } from "http";
import { verifyRequest } from "./api/verifierRoutes";
import { PolicyManifestV0 } from "./types/policy";
import { ResolveKey } from "./proof/keyResolver";
import { createSignedLocalRequest, localResolveKey } from "./api/testRequestFactory";
import { getMetricsSnapshot, recordDecision, resetMetrics } from "./api/metrics";
import { isAuthorized } from "./config/auth";
import { envResolveKey } from "./proof/envKeyResolver";

const PORT = Number(process.env.PORT ?? 8080);
const RUNTIME_AUDIENCE = process.env.RUNTIME_AUDIENCE ?? "rp.example";
const IS_PROD = process.env.NODE_ENV === "production";
const ALLOW_DEV_RESET = !IS_PROD && process.env.ALLOW_DEV_RESET === "1";
const ALLOW_TEST_KEYS = !IS_PROD && process.env.LOCAL_TEST_KEYS === "1";
const ALLOW_METRICS = !IS_PROD || process.env.ALLOW_METRICS === "1";
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES ?? 262144);

const defaultPolicy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

// TODO: replace with real key resolver + issuer status integration
const resolveKey: ResolveKey = ALLOW_TEST_KEYS ? localResolveKey : envResolveKey;

function sendJson(res: ServerResponse, statusCode: number, body: unknown, correlationId?: string): void {
  const json = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json),
    ...(correlationId ? { "x-correlation-id": correlationId } : {}),
  });
  res.end(json);
}

function sendCsv(res: ServerResponse, statusCode: number, csv: string, correlationId?: string): void {
  res.writeHead(statusCode, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Length": Buffer.byteLength(csv),
    ...(correlationId ? { "x-correlation-id": correlationId } : {}),
  });
  res.end(csv);
}

function sendHtml(res: ServerResponse, statusCode: number, html: string, correlationId?: string): void {
  res.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    ...(correlationId ? { "x-correlation-id": correlationId } : {}),
  });
  res.end(html);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk) => {
      const buf = Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_BODY_BYTES) {
        req.destroy(new Error("payload_too_large"));
        return;
      }
      chunks.push(buf);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  const correlationId = req.headers["x-correlation-id"]?.toString() ?? `corr-${Date.now()}`;

  if (!req.url || !req.method) {
    return sendJson(res, 400, { error: "bad_request" }, correlationId);
  }

  if (req.method === "GET" && req.url === "/") {
    return sendJson(
      res,
      200,
      {
        service: "miTch verifier",
        endpoints: ["GET /", "GET /health", "GET /dashboard", "GET /metrics", "GET /metrics.csv", "GET /metrics/reset (ALLOW_DEV_RESET=1)", "GET /test-request (LOCAL_TEST_KEYS=1)", "POST /verify"],
      },
      correlationId
    );
  }

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { status: "ok" }, correlationId);
  }

  if (req.method === "GET" && req.url === "/dashboard") {
    if (IS_PROD) return sendJson(res, 404, { error: "not_found" }, correlationId);
    const m = getMetricsSnapshot();
    const recentRows = m.recentDecisions
      .map(
        (d) => `<tr><td>${d.at}</td><td>${d.requestId}</td><td>${d.decision}</td><td>${d.decisionCode}</td></tr>`
      )
      .join("");

    const html = `<!doctype html><html><head><meta charset="utf-8"><title>miTch Dashboard</title></head><body style="font-family:Arial;max-width:920px;margin:2rem auto;line-height:1.4">
<h1>miTch Local Dashboard</h1>
<p><b>Started:</b> ${m.startedAt}</p>
<ul>
<li><b>Requests:</b> ${m.totals.requests}</li>
<li><b>ALLOW:</b> ${m.totals.allow}</li>
<li><b>DENY:</b> ${m.totals.deny}</li>
</ul>
<h3>Deny by Code</h3>
<pre>${JSON.stringify(m.denyByCode, null, 2)}</pre>
<h3>Recent Decisions (last 10)</h3>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">
<thead><tr><th>Time</th><th>Request ID</th><th>Decision</th><th>Code</th></tr></thead>
<tbody>${recentRows || "<tr><td colspan='4'><i>No decisions yet</i></td></tr>"}</tbody>
</table>
<p><a href="/metrics">/metrics (JSON)</a> | <a href="/metrics.csv">/metrics.csv</a></p>
</body></html>`;
    return sendHtml(res, 200, html, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics") {
    if (!ALLOW_METRICS) return sendJson(res, 404, { error: "not_found" }, correlationId);
    return sendJson(res, 200, getMetricsSnapshot(), correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics/reset") {
    if (!ALLOW_DEV_RESET) return sendJson(res, 403, { error: "dev_reset_disabled" }, correlationId);
    const reset = resetMetrics();
    return sendJson(res, 200, reset, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics.csv") {
    if (!ALLOW_METRICS) return sendJson(res, 404, { error: "not_found" }, correlationId);
    const m = getMetricsSnapshot();
    const rows = [
      "metric,value",
      `startedAt,${m.startedAt}`,
      `requests_total,${m.totals.requests}`,
      `allow_total,${m.totals.allow}`,
      `deny_total,${m.totals.deny}`,
      ...Object.entries(m.denyByCode).map(([k, v]) => `deny_code_${k},${v}`),
    ];
    return sendCsv(res, 200, rows.join("\n"), correlationId);
  }

  if (req.method === "GET" && req.url === "/test-request") {
    if (!ALLOW_TEST_KEYS) {
      return sendJson(res, 403, { error: "test_keys_disabled" }, correlationId);
    }
    const sample = createSignedLocalRequest(RUNTIME_AUDIENCE);
    return sendJson(res, 200, sample, correlationId);
  }

  if (req.method === "POST" && req.url === "/verify") {
    if (!isAuthorized(req.headers.authorization?.toString())) {
      return sendJson(res, 401, { error: "unauthorized" }, correlationId);
    }

    try {
      const raw = await readBody(req);
      const parsed: unknown = raw ? JSON.parse(raw) : {};

      const result = await verifyRequest(parsed, defaultPolicy, RUNTIME_AUDIENCE, resolveKey);
      recordDecision(result.decision, result.decisionCode, result.requestId);
      const status = result.decision === "ALLOW" ? 200 : 403;
      return sendJson(res, status, result, correlationId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "";
      const code = msg.includes("payload_too_large")
        ? "DENY_SCHEMA_TYPE_MISMATCH"
        : "DENY_INTERNAL_SAFE_FAILURE";
      const status = msg.includes("payload_too_large") ? 413 : 400;

      return sendJson(res, status, {
        version: "v0",
        requestId: "unknown",
        decision: "DENY",
        decisionCode: code,
        claimsSatisfied: [],
        receiptRef: "aqdr:pending",
        verifiedAt: new Date().toISOString(),
      }, correlationId);
    }
  }

  return sendJson(res, 404, { error: "not_found" }, correlationId);
});

server.listen(PORT, () => {
  console.log(`miTch verifier listening on http://localhost:${PORT}`);
});
