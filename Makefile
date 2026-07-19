.PHONY: test demo eval failure-test dashboard real-mcp trace docker-build observability-up observability-down helm-template aws-build-push aws-deploy aws-delete terraform-deploy terraform-destroy terraform-fmt serverless-package serverless-deploy serverless-destroy serverless-fmt

test:
	PYTHONPATH=src ./scripts/python.sh -m unittest discover -s tests -v

demo:
	./scripts/run_demo.sh --audit-db /tmp/mcp-guard-demo.db

eval:
	./scripts/run_evals.sh

failure-test:
	./scripts/run_failure_tests.sh

dashboard:
	./scripts/run_dashboard.sh

real-mcp:
	./scripts/run_real_mcp_http.sh

trace:
	MCP_GUARD_TELEMETRY=console ./scripts/run_demo.sh --audit-db /tmp/mcp-guard-trace.db

docker-build:
	docker build -t gatetrace-mcp:local .

observability-up:
	docker compose -f deploy/observability/docker-compose.yml up --build

observability-down:
	docker compose -f deploy/observability/docker-compose.yml down

helm-template:
	helm template gatetrace-mcp charts/mcp-guard

aws-build-push:
	./scripts/aws/build_push_ecr.sh

aws-deploy:
	@if [ -z "$$IMAGE_URI" ]; then echo "usage: make aws-deploy IMAGE_URI=<ecr-image-uri>"; exit 2; fi
	./scripts/aws/deploy_ec2.sh "$$IMAGE_URI"

aws-delete:
	./scripts/aws/delete_stack.sh

terraform-deploy:
	./scripts/aws/deploy_terraform.sh

terraform-destroy:
	./scripts/aws/destroy_terraform.sh

terraform-fmt:
	terraform fmt -recursive infra/aws/terraform

serverless-package:
	./scripts/aws/package_serverless.sh

serverless-deploy:
	./scripts/aws/deploy_serverless.sh

serverless-destroy:
	./scripts/aws/destroy_serverless.sh

serverless-fmt:
	terraform fmt -recursive infra/aws/serverless
