import { createServer, IncomingMessage, ServerResponse } from "http";
import { verifyRequest } from "./api/verifierRoutes";
import { PolicyManifestV0 } from "./types/policy";
import { ResolveKey } from "./proof/keyResolver";

const PORT = Number(process.env.PORT ?? 8080);

const defaultPolicy: PolicyManifestV0 = {
  version: "v0",
  id: "policy-v0-age",
  purposes: ["age_gate_checkout"],
  predicates: [{ name: "age_gte", allowed: true }],
  failClosed: true,
};

// TODO: replace with real key resolver + issuer status integration
const resolveKey: ResolveKey = async () => ({ status: "missing" });

function sendJson(res: ServerResponse, statusCode: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json),
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
  if (!req.url || !req.method) {
    return sendJson(res, 400, { error: "bad_request" });
  }

  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { status: "ok" });
  }

  if (req.method === "POST" && req.url === "/verify") {
    try {
      const raw = await readBody(req);
      const parsed: unknown = raw ? JSON.parse(raw) : {};

      const result = await verifyRequest(parsed, defaultPolicy, "rp.example", resolveKey);
      const status = result.decision === "ALLOW" ? 200 : 403;
      return sendJson(res, status, result);
    } catch {
      return sendJson(res, 400, {
        version: "v0",
        requestId: "unknown",
        decision: "DENY",
        decisionCode: "DENY_INTERNAL_SAFE_FAILURE",
        claimsSatisfied: [],
        receiptRef: "aqdr:pending",
        verifiedAt: new Date().toISOString(),
      });
    }
  }

  return sendJson(res, 404, { error: "not_found" });
});

server.listen(PORT, () => {
  console.log(`miTch verifier listening on http://localhost:${PORT}`);
});
