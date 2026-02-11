export interface AuthConfig {
  enabled: boolean;
  token: string;
}

export const authConfig: AuthConfig = {
  enabled: process.env.AUTH_TOKEN_REQUIRED === "1",
  token: process.env.AUTH_TOKEN ?? "",
};

export function isAuthorized(headerValue: string | undefined): boolean {
  if (!authConfig.enabled) return true;
  if (!authConfig.token) return false;
  if (!headerValue) return false;
  return headerValue === `Bearer ${authConfig.token}`;
}
