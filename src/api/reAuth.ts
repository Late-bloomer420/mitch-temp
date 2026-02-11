import { createHmac, timingSafeEqual } from "crypto";

const usedWebauthnChallenges = new Map<string, number>();

function pruneUsedChallenges(now: number): void {
  for (const [k, exp] of usedWebauthnChallenges.entries()) {
    if (exp <= now) usedWebauthnChallenges.delete(k);
  }
}

function b64u(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function verifySignedAssertion(
  assertion: string,
  challenge: string,
  rpId: string,
  origin: string,
  issuedAt: string,
  secret: string
): boolean {
  const payload = `${challenge}|${rpId}|${origin}|${issuedAt}`;
  const expected = b64u(createHmac("sha256", secret).update(payload).digest());

  try {
    const a = Buffer.from(assertion, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export function hasStrongRecentReAuth(meta?: {
  reAuthRecent?: boolean;
  reAuthMethod?: string;
  reAuthAssertion?: string;
  reAuthChallenge?: string;
  reAuthIssuedAt?: string;
  reAuthRpId?: string;
  reAuthOrigin?: string;
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

  if (!meta.reAuthChallenge || !meta.reAuthIssuedAt || !meta.reAuthRpId || !meta.reAuthOrigin) {
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

  const allowChallenges = (process.env.WEBAUTHN_CHALLENGE_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const allowRpIds = (process.env.WEBAUTHN_RPID_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const allowOrigins = (process.env.WEBAUTHN_ORIGIN_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const verifyMode = (process.env.WEBAUTHN_VERIFY_MODE ?? "allowlist").toLowerCase();
  const challengeOk = allowChallenges.includes(meta.reAuthChallenge);
  const rpIdOk = allowRpIds.includes(meta.reAuthRpId);
  const originOk = allowOrigins.includes(meta.reAuthOrigin);

  let assertionOk = false;
  if (verifyMode === "signed") {
    const secret = process.env.WEBAUTHN_ASSERTION_HMAC_SECRET ?? "";
    if (secret.length > 0) {
      assertionOk = verifySignedAssertion(
        meta.reAuthAssertion,
        meta.reAuthChallenge,
        meta.reAuthRpId,
        meta.reAuthOrigin,
        meta.reAuthIssuedAt,
        secret
      );
    }
  } else {
    const allowAssertions = (process.env.WEBAUTHN_ASSERTION_ALLOWLIST ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    assertionOk = allowAssertions.includes(meta.reAuthAssertion);
  }

  const now = Date.now();
  pruneUsedChallenges(now);

  // one-time challenge use (replay protection)
  const challengeAlreadyUsed = usedWebauthnChallenges.has(meta.reAuthChallenge);
  if (challengeAlreadyUsed) {
    return { ok: false, invalidEvidence: true };
  }

  if (assertionOk && challengeOk && rpIdOk && originOk) {
    const challengeTtlMs = maxAgeSeconds * 1000;
    usedWebauthnChallenges.set(meta.reAuthChallenge, now + challengeTtlMs);
    return { ok: true, invalidEvidence: true };
  }

  return { ok: false, invalidEvidence: true };
}

export function resetReAuthState(): void {
  usedWebauthnChallenges.clear();
}
