.PHONY: help test deploy scan dashboard dashboard-live tf-init tf-plan-dev tf-apply-dev tf-destroy-dev

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

test: ## Run scanner unit tests
	cd scanner && pip install pytest -q && pytest tests/ -v

deploy: ## Deploy scanner Lambda (zip)
	cd scanner && zip -j /tmp/scanner.zip handler.py && \
	aws lambda update-function-code --function-name logsentry-scanner-dev --zip-file fileb:///tmp/scanner.zip

scan: ## Run Trivy security scan
	trivy fs ./scanner

dashboard: ## Run dashboard (demo mode)
	cd dashboard && PORT=8080 python3 app.py

dashboard-live: ## Run dashboard (live DynamoDB mode)
	cd dashboard && LOGSENTRY_MODE=live FINDINGS_TABLE=logsentry-findings-dev AWS_REGION=us-east-1 PORT=8080 python3 app.py

tf-init: ## Terraform init
	cd terraform && terraform init

tf-plan-dev: ## Terraform plan (dev)
	cd terraform && terraform plan -var-file=terraform.tfvars.dev

tf-apply-dev: ## Terraform apply (dev)
	cd terraform && terraform apply -var-file=terraform.tfvars.dev -auto-approve

tf-destroy-dev: ## Terraform destroy (dev)
	cd terraform && terraform destroy -var-file=terraform.tfvars.dev -auto-approve
