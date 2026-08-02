# MCP-AttackBench Evaluation

Judikt includes a reproducible adapter for labeled MCP security datasets, including the input and metric shape needed to evaluate an acquired MCP-AttackBench corpus. The evaluator runs the same deterministic content and argument controls used in the gateway; it does not use an LLM judge.

The [MCP-AttackBench paper](https://arxiv.org/abs/2508.10991) reports 70,448 samples across jailbreak, prompt injection, cross-origin escalation, tool manipulation, command injection, data exfiltration, SQL injection, and related attacks. The [ACL Findings paper](https://aclanthology.org/2026.findings-acl.240/) defines accuracy, precision, recall, F1, and average latency as evaluation metrics.

## Honest Result Scope

The repository does not vendor or redistribute the paper's full corpus. The bundled `tests/fixtures/attackbench_smoke.jsonl` file contains eight project-authored adapter checks and must not be presented as an MCP-AttackBench score.

| Evidence | Samples | Precision | Recall | F1 | Claim |
| --- | ---: | ---: | ---: | ---: | --- |
| Tier 2 CI smoke profile | 8 | 1.0 | 1.0 | 1.0 | Parser, detector, metrics, threshold, and privacy regression only |
| Full MCP-AttackBench | 70,448 expected | Not published | Not published | Not published | Run after obtaining the independently maintained corpus |

CI stores the smoke JSON inside the `judikt-ci-evidence` artifact. A full result is publishable only when the report records `sample_count: 70448` and the input digest of the acquired corpus.

## Run It

JSON, JSONL, NDJSON, and CSV work without another dependency:

```bash
PYTHONPATH=src ./scripts/python.sh -m judikt.cli attackbench \
  /path/to/mcp-attackbench.jsonl \
  --dataset-id mcp-attackbench-2508.10991 \
  --expected-samples 70448 \
  --payload-field payload \
  --label-field label \
  --category-field category \
  --surface-field surface \
  --min-recall 0.90 \
  --output build/mcp-attackbench.json
```

Parquet streams records in 4,096-row batches and uses the optional benchmark profile:

```bash
python3 -m pip install -e '.[benchmark]'
```

Field arguments support dotted paths such as `sample.attack.payload`. Without explicit mappings, the adapter recognizes common names including `payload`, `text`, `label`, `is_attack`, `category`, and `surface`.

## Detection Path

For each record, the evaluator:

1. Canonicalizes the nested payload for a SHA-256 sample identifier.
2. Scans every string using the production `ContentGuard` rules.
3. On argument surfaces, also applies blocked argument patterns and recursive caller-credential detection.
4. Measures detector latency with a monotonic nanosecond timer.
5. Calculates TP, FP, TN, FN, accuracy, precision, recall, F1, FPR, and FNR.
6. Groups the metrics by attack category and MCP surface.
7. Writes only hashes and classification metadata for misses; raw prompts never enter the report.

`--expected-samples` prevents an incomplete subset from being mislabeled as a full result. `--min-precision`, `--min-recall`, and `--min-f1` turn the evaluator into a CI release gate.

## Interpretation

This adapter measures deterministic detection coverage, not the entire gateway. Some MCP-AttackBench scenarios require session context, caller identity, or a before/after tool definition. Those controls are tested separately by the OAuth, origin, metadata-pinning, and interoperability suites. A published report should therefore include both the benchmark output and the standard Judikt test evidence.
