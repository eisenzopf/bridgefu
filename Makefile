# bridgefu — convenience wrappers around cargo, terraform, and deploy.sh.
# Nothing here is required; the underlying commands work standalone.
#
# Common flow:
#   make tf-apply                       # stand up the EC2 infra
#   make deploy CONFIG=./bridgefu.yaml  # build on instance + start service
#   make logs                           # follow the gateway logs

# --- overridable knobs -------------------------------------------------------
SSH_KEY ?= ~/.ssh/id_ed25519
CONFIG  ?= ./bridgefu.yaml
TF      := terraform -chdir=terraform

# Elastic IP is read from terraform outputs on demand (empty until tf-apply).
IP = $(shell $(TF) output -raw public_ip 2>/dev/null)

.DEFAULT_GOAL := help

# --- local dev ---------------------------------------------------------------
.PHONY: build
build: ## Release build against ../rvoip (path dep)
	cargo build --release

.PHONY: check
check: ## cargo check + terraform validate
	cargo check
	$(TF) validate

.PHONY: fmt
fmt: ## apply rustfmt + terraform fmt (opt-in; not run by check)
	cargo fmt
	$(TF) fmt

# --- terraform ---------------------------------------------------------------
.PHONY: tf-init
tf-init: ## terraform init
	$(TF) init

.PHONY: tf-plan
tf-plan: ## terraform plan
	$(TF) plan

.PHONY: tf-apply
tf-apply: ## terraform apply (stand up / update the instance)
	$(TF) apply

.PHONY: tf-output
tf-output: ## show terraform outputs (EIP, sip_uri, ...)
	$(TF) output

.PHONY: tf-destroy
tf-destroy: ## tear down all infra
	$(TF) destroy

# --- deploy / operate --------------------------------------------------------
.PHONY: deploy
deploy: ## Build image on the instance + (re)start the service. Vars: CONFIG=, SSH_KEY=
	@test -n "$(IP)" || { echo "no public_ip from terraform — run 'make tf-apply' first"; exit 1; }
	INSTANCE_IP=$(IP) SSH_KEY=$(SSH_KEY) CONFIG=$(CONFIG) ./deploy.sh

.PHONY: healthz
healthz: ## curl the gateway /healthz (from admin_cidr)
	@test -n "$(IP)" || { echo "no public_ip from terraform"; exit 1; }
	curl -fsS http://$(IP):9090/healthz && echo

.PHONY: logs
logs: ## follow the gateway journald logs over SSH
	@test -n "$(IP)" || { echo "no public_ip from terraform"; exit 1; }
	ssh -i $(SSH_KEY) ec2-user@$(IP) 'sudo journalctl -u bridgefu -f'

.PHONY: ssh
ssh: ## SSH into the instance
	@test -n "$(IP)" || { echo "no public_ip from terraform"; exit 1; }
	ssh -i $(SSH_KEY) ec2-user@$(IP)

# --- help --------------------------------------------------------------------
.PHONY: help
help: ## list targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
