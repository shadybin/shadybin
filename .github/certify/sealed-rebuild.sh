#!/bin/bash
# A sealed rebuild on a GitHub-hosted runner, for a project with "seal": true.
#
#   sealed-rebuild.sh <shadybin> <shadybin.json> <build index> <tag> <checkout> <out dir> <record>
#
# 1. shadybin seal empties every file of the checkout outside the review, removes .git and
#    writes the record. This runs before any of the vendor's code, as the runner's user.
# 2. The build runs as shadybuild, a user with no sudo, who can therefore never undo what
#    follows; its fetch commands with the network.
# 3. The firewall then drops every packet shadybuild sends, and all DNS from the machine:
#    on macOS a lookup goes through mDNSResponder, which no per-user rule sees, and a
#    lookup is enough to carry code in.
# 4. Its run commands, without the network; then the firewall opens again, whatever
#    happened.
#
# The record stays the runner user's: shadybuild can read it, never change it.
set -euo pipefail

sb=$1 project=$2 index=$3 tag=$4 src=$5 out=$6 record=$7
builder=shadybuild
uid=4815

"$sb" seal -project "$project" -tag "$tag" -src "$src" -o "$record"

case "$(uname -s)" in
Darwin)
  if ! id "$builder" >/dev/null 2>&1; then
    # sysadminctl makes a whole account, GeneratedUID included, which ACLs (the runner's
    # home has one) need to match a user; a bare dscl record is refused by them.
    sudo sysadminctl -addUser "$builder" -fullName "shadybin build" -UID "$uid" \
      -password "$(uuidgen)" -home "/Users/$builder" 2>&1 | grep -v -i -E 'secure ?token|^$' >&2 || true
    sudo createhomedir -c -u "$builder" >/dev/null
    id "$builder" >/dev/null
  fi
  ;;
Linux)
  id "$builder" >/dev/null 2>&1 || sudo useradd --create-home --uid "$uid" "$builder"
  ;;
*) echo "a sealed rebuild needs macOS or Linux" >&2; exit 1 ;;
esac

# The builder reaches shadybin, the toolchains, the project file and the checkout, writes
# the checkout and out, and reads the record; nothing of the runner's is its to write.
# Group bits too: on macOS the builder is in staff, the group of the runner's files, and a
# member of a file's group gets its group bits, never its other bits.
for p in "$sb" "$project" "$src" "$out" "$record"; do
  d=$(dirname "$p")
  while [ "$d" != / ]; do sudo chmod go+x "$d"; d=$(dirname "$d"); done
done
sudo chmod go+rx "$sb"
sudo chmod go+r "$project" "$record"
mkdir -p "$out"
sudo chown -R "$builder" "$src" "$out"
# Builds install toolchains where the vendor's release job does, often RUNNER_TEMP: Zig
# embeds the paths of what it compiles, so the rebuild must use the same ones. The builder
# may add to it, but the sticky bit keeps it from moving or replacing the runner's files
# there, shadybin and the seal record among them.
if [ -n "${RUNNER_TEMP:-}" ]; then
  sudo chmod 1777 "$RUNNER_TEMP"
fi
if ! (cd / && sudo -n -u "$builder" test -r "$project"); then
  echo "$builder cannot read $project:" >&2
  d=$project; while [ "$d" != / ]; do ls -lde "$d" >&2; d=$(dirname "$d"); done
  id "$builder" >&2 || true
  (cd / && sudo -n -u "$builder" cat "$project" >/dev/null) || true
  exit 1
fi

as_builder() {
  local env=(PATH="$PATH")
  [ -n "${DEVELOPER_DIR:-}" ] && env+=(DEVELOPER_DIR="$DEVELOPER_DIR")
  [ -n "${RUNNER_TEMP:-}" ] && env+=(RUNNER_TEMP="$RUNNER_TEMP")
  (cd / && sudo -n -u "$builder" -H env "${env[@]}" "$@")
}
rebuild() {
  as_builder "$sb" rebuild -project "$project" -build "$index" -tag "$tag" -src "$src" -sealed "$record" -out "$out" -phase "$1"
}

close_network() {
  case "$(uname -s)" in
  Darwin)
    printf '%s\n' \
      "block drop out quick proto { tcp udp } user $builder" \
      'block drop out quick proto { tcp udp } to port { 53 853 5353 } user _mdnsresponder' \
      'block drop out quick inet proto icmp icmp-type echoreq' \
      'block drop out quick inet6 proto icmp6 icmp6-type echoreq' | sudo pfctl -q -a com.apple/shadybin -f -
    sudo pfctl -q -E 2>/dev/null || true
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder || true
    ;;
  Linux)
    for t in iptables ip6tables; do
      sudo "$t" -I OUTPUT -m owner --uid-owner "$builder" -j REJECT
      for proto in udp tcp; do
        sudo "$t" -I OUTPUT -m owner --uid-owner systemd-resolve -p "$proto" --dport 53 -j REJECT
      done
    done
    sudo resolvectl flush-caches || true
    ;;
  esac
  # The proof the build has no network: the builder cannot reach anything.
  if as_builder curl -fsS -m 10 -o /dev/null https://github.com 2>/dev/null; then
    echo "the network is still open to $builder" >&2; return 1
  fi
}
open_network() {
  # macOS starts per-user services for the builder; none may outlive its build.
  sudo pkill -u "$builder" 2>/dev/null || true
  case "$(uname -s)" in
  Darwin) sudo pfctl -q -a com.apple/shadybin -F all 2>/dev/null || true ;;
  Linux)
    for t in iptables ip6tables; do
      sudo "$t" -D OUTPUT -m owner --uid-owner "$builder" -j REJECT 2>/dev/null || true
      for proto in udp tcp; do
        sudo "$t" -D OUTPUT -m owner --uid-owner systemd-resolve -p "$proto" --dport 53 -j REJECT 2>/dev/null || true
      done
    done
    ;;
  esac
}

step() { echo "$(date -u +%T) sealed-rebuild: $*" >&2; }
step fetch
rebuild fetch
trap open_network EXIT
step closing the network
close_network
step run
# A line every 30 seconds while the build runs offline, so its log shows it is alive.
( while sleep 30; do step "still building"; done ) &
heartbeat=$!
code=0
rebuild run || code=$?
pkill -P "$heartbeat" 2>/dev/null || true; kill "$heartbeat" 2>/dev/null || true
step "done ($code)"
exit "$code"
