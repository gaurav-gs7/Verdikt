# Judikt 150-Second Hybrid Demo

The README recording deliberately uses two visual modes:

- Polished product slides explain the problem, purpose, control model, trust boundaries, production operability, and conceptual architecture.
- Terminal slides are mandatory whenever real input, processing, backend execution, output, metrics, or audit evidence is shown.

This keeps the story understandable without disguising runtime behavior as a product mockup.

![Judikt hybrid demo poster](assets/judikt-demo-poster.png)

## Timeline

The generated GIF is exactly 150 seconds and loops automatically.

1. Product introduction: what Judikt is and where it sits.
2. Production problem: overreach, confused-deputy risk, poisoned results, and weak evidence.
3. Request governance: identity, policy, risk, approval, rate limits, and blast-radius controls.
4. Response defense: definition pinning, injection scanning, quarantine, and redaction.
5. Trust boundaries: caller, gateway, MCP server, brokered credentials, and evidence systems.
6. Production operability: observability, persistence, deployment automation, and qualification.
7. Conceptual flowchart: agent to request gate, MCP server, response gate, and evidence fan-out.
8. Explicit handoff from explanation to captured terminal proof.
9. Live command and terminal flowcharts.
10. Actual code path and discovered MCP child-process tool counts.
11. Eight guarded runtime branches with input, processing, execution or skip behavior, and output.
12. Prometheus exposition and signed audit-chain verification.
13. Polished closing summary and reproducible build command.

Major outcomes remain visible for at least five seconds.

## Terminal proof

`scripts/record_demo.py` runs this command as a real subprocess:

```bash
./scripts/run_demo.sh --policy "$TMP/policy.json" --audit-db "$TMP/audit.db"
```

The recorder captures the command's stdout. It does not hand-author the values displayed in the terminal chapters. Generation fails unless that transcript proves:

1. A safe production read executed in an MCP child process.
2. A returned API key was redacted.
3. Unsafe arguments were denied before upstream execution.
4. A production rollback returned `REQUIRE_APPROVAL`.
5. An HMAC token authorized only the exact approved rollback.
6. Kubernetes remediation returned `DRY_RUN_ONLY` without mutation.
7. A controlled external MCP response was quarantined without unsafe-text exposure.
8. An operator kill switch skipped upstream execution.
9. Eight events passed signed hash-chain verification and appeared in Prometheus counters.

## Reproduce it

Run the terminal walkthrough directly:

```bash
./scripts/run_demo.sh --audit-db /tmp/judikt-demo.db
```

Regenerate the complete 150-second hybrid media artifact:

```bash
python3 -m pip install -e '.[media]'
make demo-recording
```

This writes:

- `docs/assets/judikt-demo.gif`: looping 1280 x 720 hybrid walkthrough.
- `docs/assets/judikt-demo-poster.png`: static 1280 x 720 product cover.

The renderer enforces an exact 150,000 ms duration and fails if the terminal sequence leaves insufficient room for the final five-second close.

## Safety and accuracy

The recorder creates a temporary policy, SQLite audit database, tool-definition pin store, deterministic correlation IDs, and controlled signing secrets. The poisoned response comes from `tests/fixtures/external_mcp_server.py`, which runs as a separate JSON-RPC stdio process. No cloud, LLM API, or production endpoint is contacted, and all temporary state is deleted after capture.

The local platform and Kubernetes operations are safe simulators unless Kubernetes is explicitly switched to `kubectl` mode. The gateway, subprocess MCP transport, policy outcomes, approval verification, response inspection, redaction, metrics, and signed audit path shown in the terminal are the real project implementation.

## Publishing caption

> Judikt in 150 seconds: product context and architecture first, followed by captured terminal proof of MCP inputs, deterministic controls, backend execution, poisoned-response quarantine, Prometheus output, and signed audit verification.
