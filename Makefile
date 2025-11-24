.PHONY: help build run test clean migrate-up migrate-down docker-build docker-run

# Variables
BINARY_NAME=better-wallet
BINARY_PATH=bin/$(BINARY_NAME)
MAIN_PATH=./cmd/server
DOCKER_IMAGE=better-wallet:latest

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	@go build -o $(BINARY_PATH) $(MAIN_PATH)
	@echo "Build complete: $(BINARY_PATH)"

run: ## Run the application
	@echo "Running $(BINARY_NAME)..."
	@go run $(MAIN_PATH)

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@go clean
	@echo "Clean complete"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

migrate-up: ## Run database migrations up
	@echo "Running migrations up..."
	@psql -d $$POSTGRES_DSN -f migrations/0001_initial_schema.up.sql
	@echo "Migrations complete"

migrate-down: ## Run database migrations down
	@echo "Running migrations down..."
	@psql -d $$POSTGRES_DSN -f migrations/0001_initial_schema.down.sql
	@echo "Rollback complete"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE) .
	@echo "Docker image built: $(DOCKER_IMAGE)"

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE)

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@echo "Format complete"

lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run ./...
	@echo "Lint complete"

dev: ## Run in development mode with hot reload (requires air)
	@echo "Starting development server..."
	@air

.DEFAULT_GOAL := help
