export interface OnChainTransactionEvidence {
  id: string;
  label: string;
  layer: "L1" | "ER";
  description: string;
  signature?: string;
}

export interface SettlementEvidence {
  matchIdHex: string;
  clearingPrice: string;
  baseAmount: string;
  quoteAmount: string;
  buyerChangeAmount: string;
  sellerChangeAmount: string;
  buyerFeeAmount: string;
  sellerFeeAmount: string;
  noteCLeaf: string;
  noteDLeaf: string;
  noteELeaf: string;
  noteFLeaf: string;
  feeLeaf: string;
  buyerRelockActive: boolean;
  sellerRelockActive: boolean;
  newMerkleRootHex: string;
}

export interface DemoOnChainScenario {
  name: string;
  cluster: "devnet";
  asOf: string;
  transactions: OnChainTransactionEvidence[];
  settlement: SettlementEvidence;
  withdrawReplay: {
    firstWithdrawSignature?: string;
    nullifierHex: string;
    replayErrorCode: string;
    replayErrorMessage: string;
  };
}

export const DEMO_ONCHAIN_SCENARIO: DemoOnChainScenario = {
  name: "Alice vs Bob match-and-settle",
  cluster: "devnet",
  asOf: "2026-05-09",
  transactions: [
    {
      id: "deposit",
      label: "Deposit collateral",
      layer: "L1",
      description:
        "Vault deposit transaction that funds the notes used in the demo.",
      signature: process.env.NEXT_PUBLIC_DEMO_DEPOSIT_TX_SIG,
    },
    {
      id: "delegate",
      label: "Delegate pending-order slots",
      layer: "L1",
      description:
        "L1 setup for pending-order slot delegation into the ER validator.",
      signature: process.env.NEXT_PUBLIC_DEMO_DELEGATE_TX_SIG,
    },
    {
      id: "settle",
      label: "Lock + tee_forced_settle",
      layer: "L1",
      description:
        "Atomic settle path that consumes locked notes and emits settlement evidence.",
      signature: process.env.NEXT_PUBLIC_DEMO_SETTLE_TX_SIG,
    },
    {
      id: "withdraw",
      label: "Withdraw valid spend",
      layer: "L1",
      description:
        "Successful withdraw proving ownership and creating a nullifier entry.",
      signature: process.env.NEXT_PUBLIC_DEMO_WITHDRAW_TX_SIG,
    },
  ],
  settlement: {
    matchIdHex: "0x2f91010f944a1242096ce66a8c748f31",
    clearingPrice: "100 USDC / SOL",
    baseAmount: "0.5 SOL",
    quoteAmount: "50 USDC",
    buyerChangeAmount: "0 USDC",
    sellerChangeAmount: "0 SOL",
    buyerFeeAmount: "0.05 USDC",
    sellerFeeAmount: "0.0005 SOL",
    noteCLeaf: "48210",
    noteDLeaf: "48211",
    noteELeaf: "none",
    noteFLeaf: "none",
    feeLeaf: "48212",
    buyerRelockActive: false,
    sellerRelockActive: false,
    newMerkleRootHex:
      "0x8f42f7c3d7f90db80df4b03ec40f9ad1da0d0a9d8eef6c5e347f8f942621b4ad",
  },
  withdrawReplay: {
    firstWithdrawSignature: process.env.NEXT_PUBLIC_DEMO_WITHDRAW_TX_SIG,
    nullifierHex: "0x…(derived in VALID_SPEND public inputs)",
    replayErrorCode: "NullifierAlreadySpent",
    replayErrorMessage: "rejected before proof evaluation",
  },
};
