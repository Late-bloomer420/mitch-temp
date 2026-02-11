import { request as httpRequest } from "http";
import { request as httpsRequest } from "https";
import { URL } from "url";
import { KeySource } from "./keySource";

function fetchJson(urlStr: string, timeoutMs: number): Promise<Record<string, string> | null> {
  return new Promise((resolve) => {
    try {
      const url = new URL(urlStr);
      const lib = url.protocol === "https:" ? httpsRequest : httpRequest;
      const req = lib(
        url,
        { method: "GET", timeout: timeoutMs },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(Buffer.from(c)));
          res.on("end", () => {
            try {
              const body = Buffer.concat(chunks).toString("utf8");
              const parsed = JSON.parse(body) as Record<string, string>;
              resolve(parsed);
            } catch {
              resolve(null);
            }
          });
        }
      );
      req.on("timeout", () => {
        req.destroy();
        resolve(null);
      });
      req.on("error", () => resolve(null));
      req.end();
    } catch {
      resolve(null);
    }
  });
}

export class HttpKeySource implements KeySource {
  constructor(
    private readonly urls: string[],
    private readonly timeoutMs = 1500,
    private readonly quorum = 1
  ) {}

  async getPublicKeyPem(keyId: string): Promise<string | null> {
    const maps = await Promise.all(this.urls.map((u) => fetchJson(u, this.timeoutMs)));

    const counts = new Map<string, number>();
    for (const map of maps) {
      if (!map) continue;
      const pem = map[keyId];
      if (typeof pem !== "string" || pem.length === 0) continue;
      counts.set(pem, (counts.get(pem) ?? 0) + 1);
    }

    let winner: string | null = null;
    let winnerCount = 0;
    for (const [pem, c] of counts.entries()) {
      if (c > winnerCount) {
        winner = pem;
        winnerCount = c;
      }
    }

    return winner && winnerCount >= this.quorum ? winner : null;
  }
}
