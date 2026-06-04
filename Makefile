.PHONY: test demo eval dashboard trace docker-build

test:
	PYTHONPATH=src ./scripts/python.sh -m unittest discover -s tests -v

demo:
	./scripts/run_demo.sh --audit-db /tmp/mcp-guard-demo.db

eval:
	./scripts/run_evals.sh

dashboard:
	./scripts/run_dashboard.sh

trace:
	MCP_GUARD_TELEMETRY=console ./scripts/run_demo.sh --audit-db /tmp/mcp-guard-trace.db

docker-build:
	docker build -t mcp-guard:local .

