export function hasStrongRecentReAuth(meta?: {
  reAuthRecent?: boolean;
  reAuthMethod?: string;
  reAuthAssertion?: string;
  reAuthChallenge?: string;
  reAuthIssuedAt?: string;
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

  if (!meta.reAuthChallenge || !meta.reAuthIssuedAt) {
    return { ok: false, invalidEvidence: true };
  }

  const issuedMs = Date.parse(meta.reAuthIssuedAt);
  if (!Number.isFinite(issuedMs)) {
    return { ok: false, invalidEvidence: true };
  }

  const maxAgeSeconds = Number(process.env.WEBAUTHN_MAX_AGE_SECONDS ?? 120);
  const ageMs = Date.now() - issuedMs;
  if (ageMs < 0 || ageMs > maxAgeSeconds * 1000) {
    return { ok: false, invalidEvidence: true };
  }

  const allowAssertions = (process.env.WEBAUTHN_ASSERTION_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const allowChallenges = (process.env.WEBAUTHN_CHALLENGE_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const assertionOk = allowAssertions.includes(meta.reAuthAssertion);
  const challengeOk = allowChallenges.includes(meta.reAuthChallenge);

  return { ok: assertionOk && challengeOk, invalidEvidence: true };
}
