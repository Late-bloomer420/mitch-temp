export function hasStrongRecentReAuth(meta?: {
  reAuthRecent?: boolean;
  reAuthMethod?: string;
  reAuthAssertion?: string;
}): { ok: boolean; invalidEvidence: boolean } {
  if (!meta) return { ok: false, invalidEvidence: false };

  if (process.env.REQUIRE_STRONG_REAUTH !== "1") {
    return { ok: meta.reAuthRecent === true, invalidEvidence: false };
  }

  if (!meta.reAuthMethod && !meta.reAuthAssertion) {
    return { ok: false, invalidEvidence: meta.reAuthRecent === true };
  }

  if (meta.reAuthMethod !== "webauthn" || !meta.reAuthAssertion || meta.reAuthAssertion.trim().length === 0) {
    return { ok: false, invalidEvidence: true };
  }

  const allow = (process.env.WEBAUTHN_ASSERTION_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return { ok: allow.includes(meta.reAuthAssertion), invalidEvidence: true };
}
