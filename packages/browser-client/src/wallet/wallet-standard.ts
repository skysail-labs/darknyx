import { getWallets, type Wallets } from "@wallet-standard/app";
import type {
  IdentifierString,
  Wallet,
  WalletAccount,
  WalletWithFeatures,
} from "@wallet-standard/base";
import {
  StandardConnect,
  StandardDisconnect,
  type StandardConnectFeature,
  type StandardDisconnectFeature,
} from "@wallet-standard/features";
import {
  SolanaSignAndSendTransaction,
  type SolanaSignAndSendTransactionFeature,
} from "@solana/wallet-standard-features";

type SolanaWalletFeatures = StandardConnectFeature &
  SolanaSignAndSendTransactionFeature &
  Partial<StandardDisconnectFeature>;
export type SolanaWallet = WalletWithFeatures<SolanaWalletFeatures>;

export interface ConnectedWalletView {
  walletName: string;
  address: string;
}

function compatible(
  wallet: Wallet,
  chain: IdentifierString,
): wallet is SolanaWallet {
  return (
    wallet.chains.includes(chain) &&
    StandardConnect in wallet.features &&
    SolanaSignAndSendTransaction in wallet.features
  );
}

/** Wallet Standard adapter used only for user-approved Solana transactions. */
export class ExternalWalletController {
  readonly #wallets: Wallets;
  readonly #chain: `solana:${string}`;
  #wallet: SolanaWallet | null = null;
  #account: WalletAccount | null = null;

  constructor(
    options: {
      chain?: `solana:${string}`;
      wallets?: Wallets;
    } = {},
  ) {
    this.#chain = options.chain ?? "solana:devnet";
    this.#wallets = options.wallets ?? getWallets();
  }

  available(): readonly { name: string; icon: string }[] {
    return this.#wallets
      .get()
      .filter((wallet) => compatible(wallet, this.#chain))
      .map((wallet) => ({ name: wallet.name, icon: wallet.icon }));
  }

  current(): ConnectedWalletView | null {
    if (!this.#wallet || !this.#account) return null;
    return { walletName: this.#wallet.name, address: this.#account.address };
  }

  async connect(walletName: string): Promise<ConnectedWalletView> {
    let wallet: SolanaWallet | undefined;
    for (const candidate of this.#wallets.get()) {
      if (candidate.name === walletName && compatible(candidate, this.#chain)) {
        wallet = candidate;
        break;
      }
    }
    if (!wallet)
      throw new Error("selected wallet is unavailable or incompatible");
    const { accounts } = await wallet.features[StandardConnect].connect();
    const account = accounts.find(
      (candidate) =>
        candidate.chains.includes(this.#chain) &&
        candidate.features.includes(SolanaSignAndSendTransaction),
    );
    if (!account)
      throw new Error(`wallet has no ${this.#chain} signing account`);
    this.#wallet = wallet;
    this.#account = account;
    return { walletName: wallet.name, address: account.address };
  }

  async disconnect(): Promise<void> {
    const wallet = this.#wallet;
    this.#wallet = null;
    this.#account = null;
    const disconnect = wallet?.features[StandardDisconnect];
    if (disconnect) {
      await disconnect.disconnect();
    }
  }

  async signAndSendTransaction(transaction: Uint8Array): Promise<Uint8Array> {
    if (!this.#wallet || !this.#account)
      throw new Error("wallet is not connected");
    if (transaction.length === 0 || transaction.length > 1_232) {
      throw new Error("serialized Solana transaction has an invalid size");
    }
    const [result] = await this.#wallet.features[
      SolanaSignAndSendTransaction
    ].signAndSendTransaction({
      account: this.#account,
      chain: this.#chain,
      transaction: Uint8Array.from(transaction),
      options: { commitment: "confirmed" },
    });
    if (!result?.signature || result.signature.length !== 64) {
      throw new Error("wallet returned an invalid Solana signature");
    }
    return Uint8Array.from(result.signature);
  }

  subscribe(listener: () => void): () => void {
    const offRegister = this.#wallets.on("register", listener);
    const offUnregister = this.#wallets.on("unregister", (...removed) => {
      if (this.#wallet && removed.includes(this.#wallet)) {
        this.#wallet = null;
        this.#account = null;
      }
      listener();
    });
    return () => {
      offRegister();
      offUnregister();
    };
  }
}
