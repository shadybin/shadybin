.PHONY: build check dist format test vectors sdk-test

build:
	go build -o bin/shadybin ./cmd/shadybin

# The release's binaries, which the release workflow publishes and certify rebuilds from
# the tag, so they must come out byte for byte the same on any machine: pure Go, no paths,
# no build IDs, no VCS stamp. TAG names the version.
dist:
	@test -n "$(TAG)" || { echo "make dist needs TAG"; exit 1; }
	rm -rf dist && mkdir dist
	for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go build -trimpath -buildvcs=false \
			-ldflags "-s -w -buildid= -X github.com/shadybin/shadybin/internal/cli.Version=$(TAG)" \
			-o dist/shadybin-$${p%/*}-$${p#*/} ./cmd/shadybin || exit 1; \
	done
	cd dist && shasum -a 256 shadybin-* > checksums.txt

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
	cp spec/vectors.json sdk/python/tests/vectors.json
	cp spec/vectors.json sdk/js/test/vectors.json

sdk-test:
	cd sdk/zig && zig build test
	cd sdk/rust && cargo test --quiet
	cd sdk/python && PYTHONPATH=src python3 -m unittest discover -s tests
	cd sdk/js && npm ci --silent --no-audit --no-fund && npx tsc -p . --noEmit && npm test --silent

check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run make format"; exit 1; }
	@for v in sdk/zig/src/testdata/vectors.json sdk/rust/tests/vectors.json sdk/python/tests/vectors.json sdk/js/test/vectors.json; do \
		cmp -s spec/vectors.json $$v || { echo "$$v differs from spec/vectors.json: run make vectors"; exit 1; }; done
	go vet ./...
	cd verify && go vet ./...
	$(MAKE) test
	cd sdk/zig && zig fmt --check .
	cd sdk/rust && cargo fmt --check && cargo clippy --quiet --all-targets -- -D warnings
	$(MAKE) sdk-test
