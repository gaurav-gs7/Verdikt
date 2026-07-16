# Security Policy

## Supported boundary

MCP-Guard is a reference implementation, not a hosted security service. The
supported local boundary is:

- JSON-RPC MCP over stdio between the client, guard, and demo upstream servers.
- A loopback-only dashboard without authentication.
- A bearer-authenticated dashboard API when binding outside loopback.

Do not expose the dashboard on a non-loopback interface without setting a strong,
random `MCP_GUARD_API_TOKEN`. The built-in SQLite audit store, in-process rate
limits, and local approval key are single-node controls; production deployments
need external secrets, distributed state, and an append-only audit destination.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository.
Do not include live credentials, customer data, or exploit traffic against systems
you do not own. Include the affected revision, reproduction steps, impact, and any
suggested mitigation.
