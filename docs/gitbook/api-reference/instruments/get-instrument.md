---
description: "Full detail for a single instrument, including mints, tick size, minimum size and current readiness."
---

# Get Instrument

Detail for one symbol. Prices and sizes are integers scaled by the instrument's
governed `price_scale`; never send a float. The REST object does not expose the
circuit-breaker bound or `price_scale`; read the finalized on-chain
`MarketConfig` when independently verifying those values.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/instruments/{symbol}" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

## See also

- [List Instruments](list-instruments.md)
