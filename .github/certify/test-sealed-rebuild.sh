#!/bin/bash
# Tests sealed-rebuild.sh on the runner it runs on (CI: macOS and Linux), with a fixture
# project, the way certify's rebuild job runs it:
#   - a clean project rebuilds sealed to the same bytes as unsealed;
#   - a build that ships a file the review left out makes something else;
#   - a build cannot reach the network, or sudo;
#   - the runner has its network back afterwards.
#
#   test-sealed-rebuild.sh <shadybin>
set -euo pipefail
sb=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
# Under the runner's temp directory, where certify works: macOS keeps other users out of
# a user's own temp directory (/var/folders/.../T) whatever its permissions say.
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/sealed-test.XXXXXX")
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_AUTHOR_DATE=2026-10-01T00:00:00Z GIT_COMMITTER_DATE=2026-10-01T00:00:00Z

repo="$work/repo"
mkdir -p "$repo/Sources/App" "$repo/docs"
cd "$repo"
if [ "$(uname -s)" = Darwin ]; then
  # A real Swift package with a dependency: resolved with the network, built without.
  cat > Package.swift <<'EOF'
// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "App",
  dependencies: [.package(url: "https://github.com/apple/swift-argument-parser", exact: "1.5.0")],
  targets: [.executableTarget(name: "App", dependencies: [.product(name: "ArgumentParser", package: "swift-argument-parser")])])
EOF
  printf 'import ArgumentParser\n@main struct App: ParsableCommand { func run() { print("hi") } }\n' > Sources/App/main.swift
  fetch='["swift package resolve"]'
  build='swift build -c release --force-resolved-versions -Xlinker -S && mkdir -p dist && cp .build/release/App dist/app'
else
  printf '// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: "App")\n' > Package.swift
  printf 'print("hi")\n' > Sources/App/main.swift
  fetch='[]'
  build='mkdir -p dist && cat Sources/App/main.swift > dist/app'
fi
printf 'print("hidden")\n' > docs/hidden.swift
git init -q -b main && git add . && git commit -q -m app
git tag v1.0.0
[ "$(uname -s)" = Darwin ] && swift package resolve >/dev/null 2>&1 && git add Package.resolved && git commit -q -m pin && git tag -f v1.0.0 >/dev/null

project() { # <run command>
  jq -n --arg run "$1" --argjson fetch "$fetch" '{repo: "github.com/acme/app", language: "swift", seal: true,
    checksums: "*.sha256", analyze: {exclude: ["docs/**"]},
    builds: [{runner: "any", fetch: $fetch, run: [$run], artifacts: ["dist/app"]}]}' > "$work/shadybin.json"
}
unsealed() { # <out>
  local src="$work/plain-$RANDOM"
  git clone -q --branch v1.0.0 "$repo" "$src"
  "$sb" rebuild -project "$work/shadybin.json" -build 0 -tag v1.0.0 -src "$src" -out "$1" >/dev/null
}
sealed() { # <out>: like certify's rebuild job, at the runner's workspace path
  local src="$work/sealed-$RANDOM" record="$work/seal-$RANDOM.txt" code=0
  git clone -q --branch v1.0.0 "$repo" "$src"
  # A watchdog, so a hang fails with what the builder was doing rather than a cancelled job.
  ( sleep 300; echo "WATCHDOG: still running after 5 minutes; the builder's processes:" >&2
    ps -axo user,pid,etime,command 2>/dev/null | grep -E '^shadybuild' >&2 || true
    sudo pkill -u shadybuild || true ) &
  local watchdog=$!
  echo "$(date -u +%T) sealed rebuild into $1" >&2
  bash "$here/sealed-rebuild.sh" "$sb" "$work/shadybin.json" 0 v1.0.0 "$src" "$1" "$record" || code=$?
  kill "$watchdog" 2>/dev/null || true
  echo "$(date -u +%T) sealed rebuild exited $code" >&2
  return "$code"
}
ok() { echo "ok: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

project "$build"
unsealed "$work/a"
sealed "$work/b" || fail "the sealed rebuild of a clean project failed"
cmp "$work/a/app" "$work/b/app" || fail "a clean project rebuilt sealed differs from unsealed"
ok "a clean project rebuilds sealed to the same bytes"

project "$build && cat docs/hidden.swift >> dist/app"
unsealed "$work/c"
grep -q hidden "$work/c/app" || fail "the fixture's hidden file was not shipped unsealed"
sealed "$work/d" || true
if [ -f "$work/d/app" ] && cmp -s "$work/c/app" "$work/d/app"; then fail "a build shipping an excluded file matched sealed"; fi
ok "a build shipping a file the review left out does not match"

project "$build && curl -fsS -m 10 -o /dev/null https://github.com"
if sealed "$work/e" 2>/dev/null; then fail "the sealed build reached the network"; fi
ok "the sealed build cannot reach the network"

project "$build && sudo -n true"
if sealed "$work/f" 2>/dev/null; then fail "the sealed build could sudo"; fi
ok "the sealed build cannot sudo"

# A toolchain installed into RUNNER_TEMP, as builds like marlin's do, at the runner's path.
if [ -n "${RUNNER_TEMP:-}" ]; then
  project "$build && echo tool > \"\$RUNNER_TEMP/tool-\$TAG\" && cat \"\$RUNNER_TEMP/tool-\$TAG\" >/dev/null"
  sealed "$work/g" || fail "the sealed build could not use RUNNER_TEMP"
  ok "the sealed build installs into RUNNER_TEMP"
  # And cannot touch the runner's own files there.
  echo mine > "$RUNNER_TEMP/runner-file-$$"
  project "$build && rm -f \"\$RUNNER_TEMP/runner-file-$$\""
  sealed "$work/h" 2>/dev/null || true
  [ -f "$RUNNER_TEMP/runner-file-$$" ] || fail "the sealed build removed a file of the runner's in RUNNER_TEMP"
  ok "the sealed build cannot remove the runner's files in RUNNER_TEMP"
fi

curl -fsS -m 20 -o /dev/null https://github.com || fail "the runner's network did not come back"
ok "the runner has its network back"
