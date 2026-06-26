export const NYX_DAPP_SESSION_KEY = "nyx_dapp_session_v1";

export interface DappSessionV1 {
  phantomSignatureBase58: string;
  ownerPubkeyBase58: string;
  tradingSecretKeyBase58: string;
  publicData: {
    userCommitmentHex: string;
    ownerCommitmentHex: string;
    ownerCommitmentDecimal: string;
    rootKeyPubkeyBase58: string;
  };
  proof: { piAHex: string; piBHex: string; piCHex: string };
}

export function readDappSession(): DappSessionV1 | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(NYX_DAPP_SESSION_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as DappSessionV1;
  } catch {
    return null;
  }
}

export function readDappSessionForOwner(
  ownerPubkeyBase58: string | null | undefined,
): DappSessionV1 | null {
  if (!ownerPubkeyBase58) return null;
  const session = readDappSession();
  if (!session) return null;
  return session.ownerPubkeyBase58 === ownerPubkeyBase58 ? session : null;
}
