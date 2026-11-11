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
    sudo dscl . -create "/Users/$builder"
    sudo dscl . -create "/Users/$builder" UserShell /bin/bash
    sudo dscl . -create "/Users/$builder" UniqueID "$uid"
    sudo dscl . -create "/Users/$builder" PrimaryGroupID 20
    sudo dscl . -create "/Users/$builder" NFSHomeDirectory "/Users/$builder"
    # An account with no GeneratedUID cannot be matched against an ACL, such as the one on
    # the runner's home, and is refused by it.
    sudo dscl . -create "/Users/$builder" GeneratedUID "$(uuidgen)"
    sudo dscl . -create "/Users/$builder" RealName "shadybin build"
    sudo mkdir -p "/Users/$builder"
    sudo chown "$builder:staff" "/Users/$builder"
  fi
  ;;
Linux)
  id "$builder" >/dev/null 2>&1 || sudo useradd --create-home --uid "$uid" "$builder"
  ;;
*) echo "a sealed rebuild needs macOS or Linux" >&2; exit 1 ;;
esac

# The builder reaches shadybin, the toolchains, the project file and the checkout, writes
# the checkout and out, and reads the record; nothing of the runner's is its to write.
for p in "$sb" "$project" "$src" "$out" "$record"; do
  d=$(dirname "$p")
  while [ "$d" != / ]; do sudo chmod o+x "$d"; d=$(dirname "$d"); done
done
sudo chmod o+rx "$sb"
sudo chmod o+r "$project" "$record"
mkdir -p "$out"
sudo chown -R "$builder" "$src" "$out"
if ! sudo -n -u "$builder" test -r "$project"; then
  echo "$builder cannot read $project:" >&2
  d=$project; while [ "$d" != / ]; do ls -lde "$d" >&2; d=$(dirname "$d"); done
  id "$builder" >&2 || true
  sudo -n -u "$builder" cat "$project" >/dev/null || true
  exit 1
fi

as_builder() {
  local env=(PATH="$PATH")
  [ -n "${DEVELOPER_DIR:-}" ] && env+=(DEVELOPER_DIR="$DEVELOPER_DIR")
  sudo -n -u "$builder" -H env "${env[@]}" "$@"
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
rebuild run
step done
