---
description: "The current Merkle root and leaf count of the on-chain note commitment tree."
---

# Tree Root

A proof is only valid against the root it was built for. Read the root, build the proof,
and submit before the tree advances, or the vault rejects the spend with
`StaleMerkleRoot (6004)`.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/tree/root" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}
