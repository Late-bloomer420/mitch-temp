import { createServer, IncomingMessage, ServerResponse } from "http";
import { verifyRequest } from "./api/verifierRoutes";
import { PolicyManifestV0 } from "./types/policy";
import { ResolveKey } from "./proof/keyResolver";
import { createSignedLocalRequest, localResolveKey } from "./api/testRequestFactory";
import { getMetricsSnapshot, recordDecision, resetMetrics } from "./api/metrics";

const PORT = Number(process.env.PORT ?? 8080);
const RUNTIME_AUDIENCE = process.env.RUNTIME_AUDIENCE ?? "rp.example";
const ALLOW_DEV_RESET = process.env.ALLOW_DEV_RESET === "1";

const defaultPolicy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

// TODO: replace with real key resolver + issuer status integration
const resolveKey: ResolveKey = process.env.LOCAL_TEST_KEYS === "1"
  ? localResolveKey
  : async () => ({ status: "missing" });

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
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
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
    const m = getMetricsSnapshot();
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>miTch Dashboard</title></head><body style="font-family:Arial;max-width:760px;margin:2rem auto;line-height:1.4">
<h1>miTch Local Dashboard</h1>
<p><b>Started:</b> ${m.startedAt}</p>
<ul>
<li><b>Requests:</b> ${m.totals.requests}</li>
<li><b>ALLOW:</b> ${m.totals.allow}</li>
<li><b>DENY:</b> ${m.totals.deny}</li>
</ul>
<h3>Deny by Code</h3>
<pre>${JSON.stringify(m.denyByCode, null, 2)}</pre>
<p><a href="/metrics">/metrics (JSON)</a> | <a href="/metrics.csv">/metrics.csv</a></p>
</body></html>`;
    return sendHtml(res, 200, html, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics") {
    return sendJson(res, 200, getMetricsSnapshot(), correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics/reset") {
    if (!ALLOW_DEV_RESET) return sendJson(res, 403, { error: "dev_reset_disabled" }, correlationId);
    const reset = resetMetrics();
    return sendJson(res, 200, reset, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics.csv") {
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
    if (process.env.LOCAL_TEST_KEYS !== "1") {
      return sendJson(res, 403, { error: "test_keys_disabled" }, correlationId);
    }
    const sample = createSignedLocalRequest(RUNTIME_AUDIENCE);
    return sendJson(res, 200, sample, correlationId);
  }

  if (req.method === "POST" && req.url === "/verify") {
    try {
      const raw = await readBody(req);
      const parsed: unknown = raw ? JSON.parse(raw) : {};

      const result = await verifyRequest(parsed, defaultPolicy, RUNTIME_AUDIENCE, resolveKey);
      recordDecision(result.decision, result.decisionCode);
      const status = result.decision === "ALLOW" ? 200 : 403;
      return sendJson(res, status, result, correlationId);
    } catch {
      return sendJson(res, 400, {
        version: "v0",
        requestId: "unknown",
        decision: "DENY",
        decisionCode: "DENY_INTERNAL_SAFE_FAILURE",
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
