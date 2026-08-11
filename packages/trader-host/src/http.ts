const DEFAULT_TIMEOUT_MS = 10_000;

export async function fetchBounded(
  fetchImpl: typeof fetch,
  input: string | URL | Request,
  init: RequestInit,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new Error("gateway timeout must be between 1 and 60000ms");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function readJsonBounded(
  response: Response,
  maxBytes = 32 * 1024,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<Record<string, unknown>> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error("response limit must be positive");
  }
  const contentLength = response.headers.get("content-length");
  if (
    contentLength !== null &&
    (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)
  ) {
    throw new Error("gateway response is too large");
  }
  if (!response.body) throw new Error("gateway response body is missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      void reader.cancel().catch(() => undefined);
      reject(new Error("gateway response body timed out"));
    }, timeoutMs);
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("gateway response is too large");
      }
      chunks.push(value);
    }
  } finally {
    if (timer) clearTimeout(timer);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("gateway response is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("gateway response must be an object");
  }
  return parsed as Record<string, unknown>;
}

export function gatewayBase(value: string): URL {
  const gateway = new URL(value);
  const local =
    gateway.protocol === "http:" && gateway.hostname === "localhost";
  if (
    (gateway.protocol !== "https:" && !local) ||
    gateway.username ||
    gateway.password ||
    gateway.search ||
    gateway.hash
  ) {
    throw new Error("gateway must be a credential-free HTTPS URL");
  }
  if (!gateway.pathname.endsWith("/")) gateway.pathname += "/";
  return gateway;
}
