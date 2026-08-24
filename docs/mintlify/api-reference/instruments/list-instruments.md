---
description: "Every tradable instrument on this venue, with its tick size, minimum order size and price scale."
---

# List Instruments

Returns every market this engine is configured to trade. Use it at startup to discover
symbols and their integer scaling before submitting any order.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/instruments" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

## See also

- [Get Instrument](get-instrument.md)
- [Multi-Market Venue](/documentation/how-it-works/multi-market)
