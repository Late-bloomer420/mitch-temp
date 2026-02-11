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

export async function checkCredentialRevocation(
  credentialId?: string,
  credentialStatus?: { type?: string; statusListCredential?: string; statusListIndex?: string }
): Promise<CredentialStatusCheck> {
  if (!credentialId && !credentialStatus) return { ok: true, revoked: false };

  // StatusList2021 shape scaffold (validation/transport readiness)
  if (credentialStatus) {
    if (
      credentialStatus.type !== "StatusList2021Entry" ||
      !credentialStatus.statusListCredential ||
      !credentialStatus.statusListIndex
    ) {
      return { ok: false, reason: "credential_status_unavailable" };
    }
  }

  const mode = (process.env.CREDENTIAL_STATUS_MODE ?? "env").trim().toLowerCase();

  const effectiveCredentialId = credentialId ?? "";

  // baseline env mode
  const envRevoked = parseRevokedIds(process.env.REVOKED_CREDENTIAL_IDS);
  if (mode === "env") {
    if (!effectiveCredentialId) return { ok: true, revoked: false };
    return { ok: true, revoked: envRevoked.has(effectiveCredentialId) };
  }

  // optional http mode scaffold
  if (mode === "http") {
    if (!effectiveCredentialId) return { ok: false, reason: "credential_status_unavailable" };
    // local list still applies as immediate deny list
    if (envRevoked.has(effectiveCredentialId)) return { ok: true, revoked: true };
    return checkHttpStatus(effectiveCredentialId);
  }

  return { ok: false, reason: "credential_status_unavailable" };
}
