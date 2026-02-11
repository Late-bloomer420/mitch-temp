import { createServer, IncomingMessage, ServerResponse } from "http";
import { verifyRequest } from "./api/verifierRoutes";
import { PolicyManifestV0 } from "./types/policy";
import { ResolveKey } from "./proof/keyResolver";
import { createSignedLocalRequest, localResolveKey } from "./api/testRequestFactory";
import { getMetricsSnapshot, recordDecision } from "./api/metrics";

const PORT = Number(process.env.PORT ?? 8080);
const RUNTIME_AUDIENCE = process.env.RUNTIME_AUDIENCE ?? "rp.example";

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

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { status: "ok" }, correlationId);
  }

  if (req.method === "GET" && req.url === "/metrics") {
    return sendJson(res, 200, getMetricsSnapshot(), correlationId);
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
