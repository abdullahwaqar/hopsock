.PHONY: build test lint snapshot clean

build:
	go build -trimpath -o bin/hopsock ./cmd/hopsock

test:
	go test -race ./...

lint:
	golangci-lint run ./...

# Local dry run of the release: builds every platform into ./dist.
snapshot:
	goreleaser release --snapshot --clean --skip=publish

clean:
	rm -rf bin dist
