---
description: "A Merkle inclusion proof for one note commitment, for spending or withdrawing."
---

# Inclusion Proof

The sibling path proving a commitment sits in the tree. The SDK feeds this straight into
the VALID_INPUT and VALID_SPEND circuits.

This is an authenticated read. Complete
[Transport & Attestation](../getting-started/transport-and-attestation.md)
before sending the bearer token.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/tree/inclusion" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}
