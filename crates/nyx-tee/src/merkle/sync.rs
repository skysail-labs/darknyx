//! Cold-boot + live sync of the Merkle mirror against on-chain
//! VaultConfig. Cold boot paginates getSignaturesForAddress from
//! `vault_config.deployed_slot`; live sync polls + applies new
//! leaves as settles confirm.
