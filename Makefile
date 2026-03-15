BINARY_NAME=calvigil
BUILD_DIR=./bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/Calsoft-Pvt-Ltd/calvigil/cmd.version=$(VERSION)"

.PHONY: build test lint clean install run

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

## test: Run all tests
test:
	go test -v -race ./...

## lint: Run linter
lint:
	go vet ./...

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## install: Install the binary to $GOPATH/bin
install:
	go install $(LDFLAGS) .

## run: Build and run with default args
run: build
	$(BUILD_DIR)/$(BINARY_NAME) scan .

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /' | sort
