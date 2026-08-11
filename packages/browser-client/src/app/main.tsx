import { createRoot } from "react-dom/client";

import { BrowserVault } from "../custody/browser-vault.js";
import { BrowserProverSuite } from "../prover/browser-prover.js";
import { BrowserTraderController } from "../trader/controller.js";
import { TraderProduct } from "../ui/trader-product.js";
import "../ui/styles.css";
import {
  decodeReleasePublicKey,
  fetchBrowserApplicationRelease,
  releaseVenueConfig,
} from "./release.js";
import { createVenueRecovery } from "./recovery.js";

function rootElement(): HTMLElement {
  const root = document.getElementById("darknyx-trader-root");
  if (!root) throw new Error("Darknyx trader root is missing");
  return root;
}

function fail(error: unknown): void {
  const root = rootElement();
  root.replaceChildren();
  const section = document.createElement("section");
  section.className = "fatal-release-error";
  const eyebrow = document.createElement("span");
  eyebrow.className = "eyebrow";
  eyebrow.textContent = "Release unavailable";
  const heading = document.createElement("h1");
  heading.textContent = "Darknyx failed closed";
  const detail = document.createElement("p");
  detail.textContent =
    error instanceof Error
      ? error.message
      : "The trusted release could not start.";
  section.append(eyebrow, heading, detail);
  root.append(section);
}

async function start(): Promise<void> {
  if (!globalThis.isSecureContext) {
    throw new Error("A secure browser context is required for private custody");
  }
  const release = await fetchBrowserApplicationRelease();
  const venueRelease = releaseVenueConfig(release);
  const vault = new BrowserVault({
    workerUrl: new URL(__DARKNYX_VAULT_WORKER_PATH__, location.origin),
  });
  const prover = new BrowserProverSuite({
    manifestUrl: release.artifact_manifest_url,
    expectedArtifactSetId: release.artifact_set_id,
    expectedProtocolVersion: release.artifact_protocol_version,
    trustedKeyId: release.artifact_key_id,
    trustedPublicKey: decodeReleasePublicKey(release.artifact_public_key),
    workerUrl: new URL(__DARKNYX_PROVER_WORKER_PATH__, location.origin),
  });
  const controller = new BrowserTraderController({
    release: venueRelease,
    prover,
    vault,
    circuitVersion: release.circuit_version,
    provingKeyVersion: release.proving_key_version,
    recover: createVenueRecovery(venueRelease),
    venueLabel: `Darknyx · ${release.venue_id}`,
    onError: (error) => console.error("Darknyx client error", error),
  });
  addEventListener(
    "pagehide",
    () => {
      controller.destroy();
      prover.destroy();
    },
    { once: true },
  );
  createRoot(rootElement()).render(<TraderProduct controller={controller} />);
}

void start().catch(fail);
