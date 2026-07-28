GO ?= go
PKG := ./...
# The library is the whole product surface; the examples are untested demos,
# so coverage is measured against the packages to keep the number meaningful.
COVERPKG := ./pkg/...
COVERPROFILE := coverage.out

.DEFAULT_GOAL := test

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all packages
	$(GO) build $(PKG)

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(PKG)

.PHONY: test
test: ## Run all tests with the race detector
	$(GO) test -race $(PKG)

.PHONY: coverage
coverage: ## Run tests and report coverage to the terminal
	$(GO) test -race -cover -coverprofile=$(COVERPROFILE) $(COVERPKG)
	$(GO) tool cover -func=$(COVERPROFILE)

.PHONY: coverage-html
coverage-html: coverage ## Generate and open an HTML coverage report
	$(GO) tool cover -html=$(COVERPROFILE)

.PHONY: example
example: ## Run the usage example
	$(GO) run ./examples/simple

.PHONY: example-structs
example-structs: ## Run the struct encryption example
	$(GO) run ./examples/structs

.PHONY: example-files
example-files: ## Run the file encryption example
	$(GO) run ./examples/files

.PHONY: clean
clean: ## Remove generated artifacts
	rm -f $(COVERPROFILE)
