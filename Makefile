BINARY=hunter
VERSION?=0.1.0
LDFLAGS=-ldflags "-X github.com/buemura/hunter/internal/cli.version=$(VERSION)"

.PHONY: build test lint clean serve

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/hunter

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

serve:
	go run ./cmd/hunter serve

clean:
	rm -rf bin/
