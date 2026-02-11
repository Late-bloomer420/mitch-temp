export type CredentialStatusCheck =
  | { ok: true; revoked: boolean }
  | { ok: false; reason: "credential_status_unavailable" };

function parseRevokedIds(value?: string): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

async function checkHttpStatus(credentialId: string): Promise<CredentialStatusCheck> {
  const url = (process.env.CREDENTIAL_STATUS_URL ?? "").trim();
  if (!url) return { ok: false, reason: "credential_status_unavailable" };

  const timeoutMs = Number(process.env.CREDENTIAL_STATUS_TIMEOUT_MS ?? 1500);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return { ok: false, reason: "credential_status_unavailable" };
    const data = (await res.json()) as { revokedCredentialIds?: string[] };
    const revoked = Array.isArray(data.revokedCredentialIds)
      ? new Set(data.revokedCredentialIds.map((s) => String(s).trim()).filter(Boolean))
      : new Set<string>();
    return { ok: true, revoked: revoked.has(credentialId) };
  } catch {
    return { ok: false, reason: "credential_status_unavailable" };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkCredentialRevocation(credentialId?: string): Promise<CredentialStatusCheck> {
  if (!credentialId) return { ok: true, revoked: false };

  const mode = (process.env.CREDENTIAL_STATUS_MODE ?? "env").trim().toLowerCase();

  // baseline env mode
  const envRevoked = parseRevokedIds(process.env.REVOKED_CREDENTIAL_IDS);
  if (mode === "env") {
    return { ok: true, revoked: envRevoked.has(credentialId) };
  }

  // optional http mode scaffold
  if (mode === "http") {
    // local list still applies as immediate deny list
    if (envRevoked.has(credentialId)) return { ok: true, revoked: true };
    return checkHttpStatus(credentialId);
  }

  return { ok: false, reason: "credential_status_unavailable" };
}
