/** Browser-safe strict venue-attestation surface. */
export {
  EXPECTED_COMPOSE_HASH,
  verifyTeeAttestation,
  type TeeAttestation,
  type VerifyTeeAttestationOptions,
} from "./tee/attestation.js";
export {
  AttestationError,
  type AttestationFailure,
} from "./tee/verify-core.js";
export {
  NUM_TEE_KEYS_OFFSET,
  NUM_TREES_OFFSET,
  TEE_PUBKEYS_OFFSET,
  VAULT_CONFIG_ACCOUNT_LEN,
  assertTeePubkeysMatch,
  vaultConfigTeePubkeys,
  vaultConfigTradingParameters,
} from "./tee/vault-config.js";
export {
  decodeMarketConfig,
  type OnChainMarketConfig,
} from "./tee/market-config.js";
export { marketConfigPda, vaultConfigPda } from "./idl/vault-client.js";
export {
  fetchServerTime,
  fetchSystemStatus,
  type ServerTime,
  type SystemStatus,
} from "./system/system-client.js";
