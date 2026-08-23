---
description: "Process liveness and uptime. Public and unauthenticated."
---

# Health

A liveness probe only. It reports that the process is up, NOT that trading is enabled —
read System Status for that.

{% openapi src="https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml" path="/health" method="get" %}
https://raw.githubusercontent.com/skysail-labs/darknyx/main/docs/gitbook/api-reference/openapi/darknyx-public.yaml
{% endopenapi %}

## See also

- [System Status](system-status.md)
