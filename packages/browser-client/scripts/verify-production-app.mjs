import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(
  process.env.DARKNYX_TRADER_STATIC_ROOT ??
    resolve(import.meta.dirname, "../../../.devnet/trader-static"),
);
const manifest = JSON.parse(
  await readFile(resolve(root, "build-manifest.json"), "utf8"),
);
if (
  manifest.schema_version !== 1 ||
  !Array.isArray(manifest.files) ||
  manifest.files.length < 4
) {
  throw new Error("production application manifest is malformed");
}
for (const file of manifest.files) {
  if (
    !/^\/assets\/[A-Za-z0-9._-]+\.[A-Z0-9]{8}\.(js|css)(?:\.LEGAL\.txt)?$/.test(
      file.path,
    )
  ) {
    throw new Error(`production asset is not content-addressed: ${file.path}`);
  }
  const bytes = await readFile(resolve(root, file.path.slice(1)));
  const hash = createHash("sha256").update(bytes).digest("hex");
  if (bytes.length !== file.bytes || hash !== file.sha256) {
    throw new Error(`production asset does not match manifest: ${file.path}`);
  }
  const text = file.path.endsWith(".js") ? bytes.toString("utf8") : "";
  if (text.includes("sourceMappingURL") || text.includes("api-key=")) {
    throw new Error(
      `production JavaScript leaked debug or secret material: ${file.path}`,
    );
  }
}
const html = await readFile(resolve(root, "index.html"), "utf8");
if (
  !html.includes(`src="${manifest.entry}"`) ||
  !html.includes(`href="${manifest.stylesheet}"`) ||
  /<script(?![^>]*\bsrc=)/i.test(html)
) {
  throw new Error("production HTML does not pin external hashed assets");
}
console.log(`verified ${manifest.files.length} production assets`);
