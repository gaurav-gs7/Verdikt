# Security Evals And MCP-38 Coverage

GateTrace MCP maps its controls to the 38 threat categories in *MCP-38: A Comprehensive Threat Taxonomy for Model Context Protocol Systems (v1.0)*, arXiv:2603.18063.

The machine-readable source is [`config/mcp38_coverage.json`](../config/mcp38_coverage.json). `covered` means the primary mechanism has an implemented control and executable test. `partial` means a relevant control exists but material attack paths remain. `not_covered` is an explicit gap. Coverage is not a claim that a broad threat class has been eliminated.

Current generated totals:

| Status | Count |
| --- | ---: |
| Covered | 12 |
| Partial | 20 |
| Not covered | 6 |
| Total | 38 |

Run the policy regressions and matrix validation:

```bash
./scripts/run_evals.sh
```

Run every unit and integration proof:

```bash
PYTHONPATH=src ./scripts/python.sh -m unittest discover -s tests -v
```

High-value proofs include:

- `MCP-10` and `MCP-11`: poisoned descriptions and nested schema strings are rejected before pinning.
- `MCP-14`: duplicate cross-server tool names fail closed.
- `MCP-16`: a server that changes metadata after initial trust is blocked before execution.
- `MCP-20`: injected external tool output is quarantined without returning the malicious string.
- `MCP-22` and `MCP-23`: Slack callbacks are signed and allowlisted; duplicate requests are suppressed.
- `MCP-33`: local/Redis/DynamoDB limits, bounded scans, concurrency caps, and circuit breakers constrain abuse.
- `MCP-38`: audit mutation is detected and request decisions emit metrics and traces.

The six explicit gaps are multi-tenant isolation (`MCP-06`), general SSRF/XSS defense (`MCP-09`), privacy inference across aggregated data (`MCP-25`), DNS-rebinding defense (`MCP-31`), planning drift (`MCP-35`), and multi-agent context hijacking (`MCP-36`).

The independent attack fixture at [`tests/fixtures/external_mcp_server.py`](../tests/fixtures/external_mcp_server.py) is intentionally outside the `mcp_guard` package. It implements MCP JSON-RPC itself and supports `safe`, `result-injection`, and `rug-pull` modes. This proves the gateway boundary against a separate process; it is not represented as a third-party production server. The optional community filesystem configuration provides the real third-party interoperability path and requires Node/npm on first use.
