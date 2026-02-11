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

async function checkHttpStatus(
  credentialId: string,
  statusListIndex?: string
): Promise<CredentialStatusCheck> {
  const url = (process.env.CREDENTIAL_STATUS_URL ?? "").trim();
  if (!url) return { ok: false, reason: "credential_status_unavailable" };

  const timeoutMs = Number(process.env.CREDENTIAL_STATUS_TIMEOUT_MS ?? 1500);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return { ok: false, reason: "credential_status_unavailable" };
    const data = (await res.json()) as { revokedCredentialIds?: unknown; revokedIndexes?: unknown };

    const hasRevokedIds = Object.prototype.hasOwnProperty.call(data, "revokedCredentialIds");
    const hasRevokedIndexes = Object.prototype.hasOwnProperty.call(data, "revokedIndexes");
    if (!hasRevokedIds && !hasRevokedIndexes) return { ok: false, reason: "credential_status_unavailable" };

    if (hasRevokedIds && !Array.isArray(data.revokedCredentialIds)) {
      return { ok: false, reason: "credential_status_unavailable" };
    }
    if (hasRevokedIndexes && !Array.isArray(data.revokedIndexes)) {
      return { ok: false, reason: "credential_status_unavailable" };
    }

    const revokedIds = Array.isArray(data.revokedCredentialIds)
      ? new Set(data.revokedCredentialIds.map((s) => String(s).trim()).filter(Boolean))
      : new Set<string>();
    const revokedIndexes = Array.isArray(data.revokedIndexes)
      ? new Set(data.revokedIndexes.map((s) => String(s).trim()).filter(Boolean))
      : new Set<string>();
    const isRevokedById = revokedIds.has(credentialId);
    const isRevokedByIndex = !!statusListIndex && revokedIndexes.has(statusListIndex);
    return { ok: true, revoked: isRevokedById || isRevokedByIndex };
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
  const effectiveStatusIndex = credentialStatus?.statusListIndex?.trim() ?? "";

  // baseline env mode
  const envRevoked = parseRevokedIds(process.env.REVOKED_CREDENTIAL_IDS);
  const envRevokedIndexes = parseRevokedIds(process.env.REVOKED_STATUS_LIST_INDEXES);
  if (mode === "env") {
    const revokedById = effectiveCredentialId ? envRevoked.has(effectiveCredentialId) : false;
    const revokedByIndex = effectiveStatusIndex ? envRevokedIndexes.has(effectiveStatusIndex) : false;
    return { ok: true, revoked: revokedById || revokedByIndex };
  }

  // optional http mode scaffold
  if (mode === "http") {
    if (!effectiveCredentialId) return { ok: false, reason: "credential_status_unavailable" };
    // local list still applies as immediate deny list
    if (envRevoked.has(effectiveCredentialId)) return { ok: true, revoked: true };
    if (effectiveStatusIndex && envRevokedIndexes.has(effectiveStatusIndex)) return { ok: true, revoked: true };
    return checkHttpStatus(effectiveCredentialId, effectiveStatusIndex || undefined);
  }

  return { ok: false, reason: "credential_status_unavailable" };
}
