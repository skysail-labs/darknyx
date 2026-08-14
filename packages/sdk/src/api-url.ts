/** Resolve a venue-relative API path without discarding a reverse-proxy prefix. */
export function apiUrl(baseUrl: string, path: string): URL {
  const base = new URL(baseUrl);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL(path.replace(/^\/+/, ""), base);
}
