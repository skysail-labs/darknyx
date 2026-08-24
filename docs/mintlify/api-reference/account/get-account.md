---
description: "The caller's currently open orders."
---

# Get Open Orders

The authoritative server-side view of what is resting. After a stream gap or a restart,
reconcile against this rather than trusting local state.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/account" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}
