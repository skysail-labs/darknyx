---
description: "The current Merkle root and leaf count of the on-chain note commitment tree."
title: "Tree Root"
openapi: "/api-reference/openapi/darknyx-public.yaml GET /tree/root"
---

A proof is only valid against the root it was built for. Read the root, build the proof,
and submit before the tree advances, or the vault rejects the spend with
`StaleMerkleRoot (6004)`.
