export type KeyStatus = "active" | "revoked" | "missing" | "unavailable";

export interface ResolvedKey {
  status: KeyStatus;
  publicKeyPem?: string;
}

export type ResolveKey = (keyId?: string) => Promise<ResolvedKey>;
