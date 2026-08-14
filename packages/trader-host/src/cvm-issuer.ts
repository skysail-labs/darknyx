import type { CvmAccountCredentials, IsolatedTokenIssuer } from "./types.js";
import { fetchBounded, gatewayBase, readJsonBounded } from "./http.js";

export interface CvmTokenIssuerOptions {
  gatewayUrl: string;
  /** Must return a durable, session-isolated account. Never use one shared record. */
  resolveCredentials(
    sessionId: string,
    venueId: string,
  ): Promise<CvmAccountCredentials>;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
}

/** Exchange server-held, session-isolated CVM credentials for a short JWT. */
export function createCvmTokenIssuer(
  options: CvmTokenIssuerOptions,
): IsolatedTokenIssuer {
  const gateway = gatewayBase(options.gatewayUrl);
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
    const response = await fetchBounded(
      fetchImpl,
      new URL("auth/token", gateway),
      {
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
      },
      options.requestTimeoutMs,
    );
    if (!response.ok)
      throw new Error(`CVM token exchange failed (${response.status})`);
    const body = await readJsonBounded(
      response,
      32 * 1024,
      options.requestTimeoutMs,
    );
    if (
      typeof body.access_token !== "string" ||
      body.access_token.length < 32 ||
      body.access_token.length > 16_384 ||
      typeof body.expires_in !== "number" ||
      !Number.isSafeInteger(body.expires_in) ||
      body.expires_in < 30 ||
      body.expires_in > 3_600 ||
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
