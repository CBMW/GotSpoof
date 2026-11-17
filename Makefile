.PHONY: build test check clean

build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/gotspoof ./cmd/gotspoof

test:
	go test ./...

check:
	gofmt -w cmd internal
	go vet ./...
	go test ./...

clean:
	go clean
