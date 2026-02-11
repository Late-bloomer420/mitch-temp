import { createHmac, timingSafeEqual } from "crypto";

export interface WebAuthnEvidence {
  assertion: string;
  challenge: string;
  rpId: string;
  origin: string;
  issuedAt: string;
}

function b64u(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function verifySignedAssertion(e: WebAuthnEvidence, secret: string): boolean {
  const payload = `${e.challenge}|${e.rpId}|${e.origin}|${e.issuedAt}`;
  const expected = b64u(createHmac("sha256", secret).update(payload).digest());

  try {
    const a = Buffer.from(e.assertion, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export function verifyWebauthnEvidence(e: WebAuthnEvidence): boolean {
  const mode = (process.env.WEBAUTHN_VERIFY_MODE ?? "allowlist").toLowerCase();

  if (mode === "native") {
    // integration hook for future real WebAuthn authenticator verification.
    // For now, deny unless explicit adapter flag is provided by a trusted integration layer.
    return process.env.WEBAUTHN_NATIVE_ADAPTER_OK === "1";
  }

  if (mode === "signed") {
    const secret = process.env.WEBAUTHN_ASSERTION_HMAC_SECRET ?? "";
    if (!secret) return false;
    return verifySignedAssertion(e, secret);
  }

  const allowAssertions = (process.env.WEBAUTHN_ASSERTION_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return allowAssertions.includes(e.assertion);
}
