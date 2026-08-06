.PHONY: all build shims test vet fmt lint demo demo-target clean

BIN := bin/quarry

all: build test

build: shims
	go build -o $(BIN) ./cmd/quarry
	go build -o bin/quarry-vetd ./cmd/quarry-vetd

# quarry-shim: the in-container PID1 shim that records the target's true wait status
# (signal vs voluntary exit), defeating the docker exit(128+N) crash-signal forgery.
# Point DockerRunner at the arch matching the target image (via $QUARRY_SHIM).
shims:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/quarry-shim-linux-amd64 ./cmd/quarry-shim
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/quarry-shim-linux-arm64 ./cmd/quarry-shim

test:
	go test ./...

# Integration tests (real ASan target) run only when a C toolchain is present;
# they self-skip otherwise.
test-integration:
	go test -run Integration -v ./...

vet:
	go vet ./...

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

# lint fails on any gofmt drift or vet finding. Previously `lint` was declared in
# .PHONY with NO rule, so `make lint` silently passed — enforce it for real now.
lint:
	@echo "gofmt check…"
	@out=$$(gofmt -l cmd internal); if [ -n "$$out" ]; then echo "gofmt drift in:"; echo "$$out"; exit 1; fi
	go vet ./...
	@echo "go mod tidy check…"
	@go mod tidy -diff

# Build the demo target's sanitizer binary for a local (non-Docker) run.
demo-target:
	clang -fsanitize=address -g -O0 testdata/demo-stack-overflow/vuln.c -o testdata/demo-stack-overflow/vuln

# End-to-end demo against the real target. Requires a running litellm proxy
# (QUARRY_PROXY_URL) and a model alias (QUARRY_MODEL, default glm-5.2-ant).
demo: build demo-target
	./$(BIN) copilot --target testdata/demo-stack-overflow/quarry.yaml --verbose

clean:
	rm -rf bin .quarry-ws .quarry-home testdata/demo-stack-overflow/vuln testdata/demo-stack-overflow/vuln_fixed
