input_data = {
  "service": "payments-api",
  "owner": "payments-team",
  "tier": "tier-1",
  "slo": {
    "availability": 99.9,
    "latency_p95_ms": 300
  },
  "runbook": "https://example.com/runbook"
}

REQUIRED_FIELDS = ["service", "owner", "tier", "slo", "runbook"]

for field in REQUIRED_FIELDS:
    if field not in input_data.keys():
        raise ValueError(f"Missing required field: {field}")
    
import argparse

def arg_parse(input_data: dict[str, any]) -> str:
    parser = argparse.ArgumentParser(description="Process some input data.")
    parser.add_argument("--service", required=True, help="The name of the service.")
    parser.add_argument("--owner", required=True, help="The owner of the service.")


from datetime import datetime, timedelta, timezone

def parse_ts(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def even_N(events, min, now=None):
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=min)
    count = 0
    for event in events:
        ts = parse_ts(event["timestamp"])
        if ts >= cutoff:
            count += 1
    return count % 2 == 0