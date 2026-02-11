import { ResolveKey } from "./keyResolver";
import { StaticStatusProvider } from "./statusProvider";
import { EnvKeySource } from "./keySource";

const statusProvider = new StaticStatusProvider();
const keySource = new EnvKeySource();

export const envResolveKey: ResolveKey = async (keyId?: string) => {
  const status = await statusProvider.getStatus(keyId);
  if (!keyId) return { status: "missing" };
  if (status === "revoked") return { status: "revoked" };
  if (status === "unavailable") return { status: "unavailable" };

  const pem = await keySource.getPublicKeyPem(keyId);
  if (!pem) return { status: "missing" };
  return { status: "active", publicKeyPem: pem };
};
