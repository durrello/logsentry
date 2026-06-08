.PHONY: help test build scan deploy dashboard dashboard-live

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dashboard: ## Run dashboard (demo mode)
	cd dashboard && PORT=8080 python3 app.py

dashboard-live: ## Run dashboard (live DynamoDB mode)
	cd dashboard && LOGSENTRY_MODE=live PORT=8080 python3 app.py

test: ## Run scanner unit tests
	cd scanner && pip install -r requirements.txt pytest && pytest tests/ -v

build: ## Build scanner Docker image
	docker build -t logsentry-scanner:latest ./scanner

scan: ## Run Trivy security scan
	trivy fs ./scanner
	trivy image logsentry-scanner:latest

tf-init: ## Terraform init
	cd terraform && terraform init

tf-plan-dev: ## Terraform plan (dev)
	cd terraform && terraform plan -var-file=terraform.tfvars.dev

tf-apply-dev: ## Terraform apply (dev)
	cd terraform && terraform apply -var-file=terraform.tfvars.dev -auto-approve

tf-destroy-dev: ## Terraform destroy (dev)
	cd terraform && terraform destroy -var-file=terraform.tfvars.dev -auto-approve
