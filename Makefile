# bridgefu — convenience wrappers around cargo. Nothing here is required; the
# underlying commands work standalone.
#
# Deployment lives elsewhere. The customer CloudFormation template, AMI build,
# Lambdas, and live qualification harness for the Vapi -> Amazon Connect recipe
# are maintained in eisenzopf/bridgefu-vapi-awsconnect, which pins an immutable
# Bridgefu commit and builds from it.

.DEFAULT_GOAL := help

.PHONY: build
build: ## Locked release build against crates.io rvoip 0.3.8
	cargo build --locked --release

.PHONY: check
check: ## cargo check against the locked graph
	cargo check --locked

.PHONY: fmt
fmt: ## apply rustfmt (opt-in; not run by check)
	cargo fmt

.PHONY: test
test: ## full locked test suite
	cargo test --locked --all-targets

.PHONY: recipes
recipes: ## list the embedded, credential-free recipe catalog
	cargo run --locked -- recipe available

.PHONY: recipe-matrix
recipe-matrix: ## conformance-test every built-in recipe
	cargo test --locked --test recipe_matrix -- --nocapture

.PHONY: help
help: ## list targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
