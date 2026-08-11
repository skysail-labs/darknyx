import type { CvmAccountCredentials, IsolatedTokenIssuer } from "./types.js";

export interface CvmTokenIssuerOptions {
  gatewayUrl: string;
  /** Must return a durable, session-isolated account. Never use one shared record. */
  resolveCredentials(
    sessionId: string,
    venueId: string,
  ): Promise<CvmAccountCredentials>;
  fetchImpl?: typeof fetch;
}

/** Exchange server-held, session-isolated CVM credentials for a short JWT. */
export function createCvmTokenIssuer(
  options: CvmTokenIssuerOptions,
): IsolatedTokenIssuer {
  const gateway = new URL(options.gatewayUrl);
  if (gateway.protocol !== "https:" || gateway.username || gateway.password) {
    throw new Error(
      "CVM token issuer requires a credential-free HTTPS gateway",
    );
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  return async ({ sessionId, venueId }) => {
    const credentials = await options.resolveCredentials(sessionId, venueId);
    if (
      !credentials.apiKey ||
      !credentials.apiSecret ||
      !credentials.passphrase
    ) {
      throw new Error("credential resolver returned an incomplete CVM account");
    }
    const response = await fetchImpl(new URL("/auth/token", gateway), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        api_key: credentials.apiKey,
        api_secret: credentials.apiSecret,
        passphrase: credentials.passphrase,
      }),
    });
    if (!response.ok)
      throw new Error(`CVM token exchange failed (${response.status})`);
    const body = (await response.json()) as Record<string, unknown>;
    if (
      typeof body.access_token !== "string" ||
      typeof body.expires_in !== "number" ||
      body.token_type !== "Bearer"
    ) {
      throw new Error("CVM token exchange returned a malformed response");
    }
    return {
      accountId: credentials.apiKey,
      accessToken: body.access_token,
      expiresIn: body.expires_in,
    };
  };
}
