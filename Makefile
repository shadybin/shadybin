.PHONY: build check format test vectors sdk-test

build:
	go build -o bin/shadybin ./cmd/shadybin

test:
	go test ./...
	cd verify && go test ./...

format:
	gofmt -w .
	cd sdk/zig && zig fmt .
	cd sdk/rust && cargo fmt

# spec/vectors.json is the conformance suite every SDK runs; each SDK keeps a copy it can
# embed. vectors rewrites them all from the Go SDK, which generates the suite.
vectors:
	cd verify && SHADYBIN_WRITE_VECTORS=1 go test -run TestVectors ./...
	cp spec/vectors.json sdk/zig/src/testdata/vectors.json
	cp spec/vectors.json sdk/rust/tests/vectors.json

sdk-test:
	cd sdk/zig && zig build test
	cd sdk/rust && cargo test --quiet

check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run make format"; exit 1; }
	@cmp -s spec/vectors.json sdk/zig/src/testdata/vectors.json && cmp -s spec/vectors.json sdk/rust/tests/vectors.json || { echo "SDK vectors differ from spec/vectors.json: run make vectors"; exit 1; }
	go vet ./...
	cd verify && go vet ./...
	$(MAKE) test
	cd sdk/zig && zig fmt --check .
	cd sdk/rust && cargo fmt --check && cargo clippy --quiet --all-targets -- -D warnings
	$(MAKE) sdk-test
