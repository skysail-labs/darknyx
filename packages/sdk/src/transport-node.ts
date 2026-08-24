/**
 * Node-only transport entry point (T-03P).
 *
 * A separate subpath rather than part of the package index, because everything
 * re-exported here imports `node:https`, `node:tls`, or `node:crypto`. A
 * browser consumer that reaches for `@darknyx/sdk` must not pull these into
 * its bundle graph, and a subpath makes that a build error rather than a
 * runtime surprise.
 *
 * The verification core itself (`verifyTransportAttestation`) stays on the main
 * index: it is environment-neutral, and browser code needs it too.
 */

export {
  TransportAgent,
  createVerifiedFetch,
  parseObservedManifest,
  socketSpkiSha256,
  verifyTransportOnSocket,
  LIMITS,
  type TransportVerifierDeps,
  type VerifiedSocket,
  type VerifiedTransportOptions,
} from "./tee/transport-agent.node.js";

export {
  createVerifiedWebSocketFactory,
  upgradeSocketSpki,
  type NodeWebSocketLike,
  type VerifiedWebSocketOptions,
} from "./tee/transport-ws.node.js";

export {
  createVerifiedTransport,
  TransportVerificationError,
  type CreateVerifiedTransportOptions,
  type VerifiedTransport,
} from "./tee/transport.node.js";
