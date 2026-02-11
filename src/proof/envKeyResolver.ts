import { ResolveKey } from "./keyResolver";
import { StaticStatusProvider } from "./statusProvider";

const statusProvider = new StaticStatusProvider();

function parseKeyMap(): Record<string, string> {
  try {
    const raw = process.env.PUBLIC_KEYS_JSON ?? "{}";
    const parsed = JSON.parse(raw) as Record<string, string>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export const envResolveKey: ResolveKey = async (keyId?: string) => {
  const status = await statusProvider.getStatus(keyId);
  if (!keyId) return { status: "missing" };
  if (status === "revoked") return { status: "revoked" };

  const keys = parseKeyMap();
  const pem = keys[keyId];
  if (!pem) return { status: "missing" };
  return { status: "active", publicKeyPem: pem };
};
