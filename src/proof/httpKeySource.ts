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
  constructor(private readonly url: string, private readonly timeoutMs = 1500) {}

  async getPublicKeyPem(keyId: string): Promise<string | null> {
    const map = await fetchJson(this.url, this.timeoutMs);
    if (!map) return null;
    const pem = map[keyId];
    return typeof pem === "string" && pem.length > 0 ? pem : null;
  }
}
