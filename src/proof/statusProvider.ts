export type KeyStatus = "active" | "revoked" | "missing";

export interface KeyStatusProvider {
  getStatus(keyId?: string): Promise<KeyStatus>;
}

export class StaticStatusProvider implements KeyStatusProvider {
  async getStatus(keyId?: string): Promise<KeyStatus> {
    if (!keyId) return "missing";
    return process.env.REVOKED_KEY_IDS?.split(",").map((s) => s.trim()).includes(keyId)
      ? "revoked"
      : "active";
  }
}
