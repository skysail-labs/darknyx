---
description: "Full detail for a single instrument, including tick size, minimum size and circuit-breaker bounds."
---

# Get Instrument

Detail for one symbol. Prices and sizes are integers scaled by the instrument's
`price_scale`; never send a float.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/instruments/{symbol}" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

## See also

- [List Instruments](list-instruments.md)
