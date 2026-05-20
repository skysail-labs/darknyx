import { Connection, PublicKey, Keypair, Transaction, TransactionInstruction, SystemProgram, sendAndConfirmTransaction } from "@solana/web3.js";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const RPC = process.env.L1_RPC_URL || "https://api.devnet.solana.com";
const VAULT_PROGRAM_ID = new PublicKey("C63vKvysCzX55PKraas4Wc22ijqjGJQdPC1mrzCFVWZx");

// Anchor global ix discriminator = sha256("global:<snake_case_name>")[..8]
const disc = (name) => createHash("sha256").update("global:" + name).digest().subarray(0, 8);

const admin = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(".devnet/keypairs/admin.json", "utf8"))));
const [vaultConfigPda] = PublicKey.findProgramAddressSync([Buffer.from("vault_config")], VAULT_PROGRAM_ID);

const conn = new Connection(RPC, "confirmed");
const beforeAcct = await conn.getAccountInfo(vaultConfigPda);
console.log(`Before: VaultConfig PDA ${vaultConfigPda.toBase58()} = ${beforeAcct?.data.length ?? "missing"} bytes`);

const ix = new TransactionInstruction({
  programId: VAULT_PROGRAM_ID,
  keys: [
    { pubkey: admin.publicKey, isSigner: true, isWritable: true },
    { pubkey: vaultConfigPda, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ],
  data: disc("realloc_vault_config"),
});

const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin], { commitment: "confirmed" });
console.log(`TX: ${sig}`);
const afterAcct = await conn.getAccountInfo(vaultConfigPda);
console.log(`After:  VaultConfig PDA = ${afterAcct.data.length} bytes`);
