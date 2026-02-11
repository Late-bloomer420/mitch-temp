export interface KeySource {
  getPublicKeyPem(keyId: string): Promise<string | null>;
}

export class EnvKeySource implements KeySource {
  async getPublicKeyPem(keyId: string): Promise<string | null> {
    try {
      const raw = process.env.PUBLIC_KEYS_JSON ?? "{}";
      const parsed = JSON.parse(raw) as Record<string, string>;
      const pem = parsed[keyId];
      return typeof pem === "string" && pem.length > 0 ? pem : null;
    } catch {
      return null;
    }
  }
}
