import { createPrivateKey, sign } from "node:crypto";

const SIGNATURE_DOMAIN = Buffer.from("darknyx/client-artifact-manifest/v1\0");

export function signArtifactPayload(payload, keyBytes) {
  const privateKey = createPrivateKey({
    key: keyBytes,
    format: "der",
    type: "pkcs8",
  });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("artifact signing key must be Ed25519");
  }
  return sign(null, Buffer.concat([SIGNATURE_DOMAIN, payload]), privateKey);
}
