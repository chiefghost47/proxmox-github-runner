#!/usr/bin/env bash
# =============================================================================
# preflight.sh — run on the WORKSTATION (Git Bash) before the build. Read-only.
#   bash scripts/preflight.sh    # from the repo root; uses ./inputs.env
# Checks every prerequisite of the CI-VLAN runner build and prints PASS/FAIL/WARN.
# It changes nothing on the Proxmox host, the firewall, GitHub or this PC.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
[[ -f inputs.env ]] || { echo "inputs.env missing (copy inputs.env.example)"; exit 2; }
# shellcheck disable=SC1091
. ./inputs.env
F=0; W=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; F=$((F+1)); }
warn() { printf 'WARN  %s\n' "$*"; W=$((W+1)); }
q() { grep -v -i 'post-quantum\|store now\|openssh.com/pq\|^\*\*'; }
pfx() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$PFSENSE_SSH" "xmllint --xpath '$1' /cf/conf/config.xml 2>/dev/null" 2>&1 | q; }

echo "== workstation"
for t in ssh curl jq base64 shred; do command -v $t >/dev/null && pass "tool $t" || fail "tool $t missing"; done
if [[ -f "$VM_SSH_KEY" && -f "$VM_SSH_KEY.pub" ]]; then pass "VM key $VM_SSH_KEY present"; else fail "VM key missing: ssh-keygen -t ed25519 -N '' -C ci-runner-admin -f \"$VM_SSH_KEY\""; fi
pat_for() { echo "$GITHUB_PAT_FILE"; }  # one fine-grained PAT; add a per-owner case here if you need more
owners=$(for r in $REPOS; do echo "${r%%/*}"; done | sort -u)
for o in $owners; do
  repos=$(for r in $REPOS; do [[ "${r%%/*}" == "$o" ]] && echo "$r"; done | tr '\n' ' ')
  pf=$(pat_for "$o/x")
  if [[ ! -s "$pf" ]]; then fail "PAT for owner $o missing: $pf (fine-grained, owner $o, 2-day expiry, scopes in the run sheet)"; continue; fi
  pass "PAT for owner $o present"
  if who=$(GITHUB_PAT_FILE=$pf scripts/github-runner-api.sh whoami 2>/dev/null); then pass "PAT for $o valid (login $who)"; else fail "PAT for $o rejected by GitHub"; continue; fi
  out=$(GITHUB_PAT_FILE=$pf scripts/github-runner-api.sh check-repos $repos 2>&1)
  if [[ $? -eq 0 ]]; then pass "$o repos private, admin, not archived: $repos"; else fail "check-repos for $o failed:"; sed 's/^/      /' <<<"$out"; fi
done

echo "== Proxmox host (read-only)"
if ssh -o BatchMode=yes -o ConnectTimeout=10 "$PVE_SSH" pveversion >/dev/null 2>&1; then pass "ssh $PVE_SSH works"; else fail "ssh $PVE_SSH does not work"; fi
nc=$(ssh "$PVE_SSH" "STATE_DIR=/nonexistent VLAN_TAG=$VLAN_TAG IPCONFIG0=ip=$VM_IP/$CI_PREFIX,gw=$CI_GW bash -s netcheck" < scripts/proxmox-create-runner-vm.sh 2>&1); rc=$?
q <<<"$nc"; F=$(( F + $(grep -c '^FAIL' <<<"$nc") )); W=$(( W + $(grep -c '^WARN' <<<"$nc") ))
(( rc == 0 )) || grep -q '^FAIL' <<<"$nc" || fail "host netcheck exited $rc"
read -r avail <<<"$(ssh "$PVE_SSH" "awk '/^MemAvailable:/{print int(\$2/1024)}' /proc/meminfo")"
need=$(( MEMORY_MB + 2048 ))
(( avail >= need )) && pass "MemAvailable ${avail} MB >= ${need} MB" || fail "MemAvailable ${avail} MB < ${need} MB (free RAM first)"
read -r free_g cap <<<"$(ssh "$PVE_SSH" "zpool list -Hp -o free,cap $STORAGE 2>/dev/null | awk '{print int(\$1/1073741824), \$2}'")"
if [[ -n "${free_g:-}" ]]; then
  (( free_g >= DISK_GB + 10 )) && pass "$STORAGE free ${free_g} GiB" || fail "$STORAGE free ${free_g} GiB < $((DISK_GB+10))"
  (( ${cap%\%} < 80 )) && pass "$STORAGE at ${cap%\%}% (< 80%)" || fail "$STORAGE at ${cap%\%}% (ZFS degrades past 80%)"
else fail "cannot read zpool $STORAGE"; fi
if ssh "$PVE_SSH" "qm list | awk '{print \$2}' | grep -qx $VM_NAME"; then warn "a guest named $VM_NAME exists (build uses it only if vm.env points at it)"; else pass "no guest named $VM_NAME"; fi
ssh "$PVE_SSH" "sed -n '/^dir: local\$/,/^\$/p' /etc/pve/storage.cfg | grep -q 'content.*snippets'" && pass "snippets already enabled on 'local' (no storage change needed)" || warn "snippets not on 'local' (create would add it)"
ssh "$PVE_SSH" "timeout 10 curl -fsS -o /dev/null https://cloud-images.ubuntu.com/noble/current/SHA256SUMS" && pass "the host can fetch the Ubuntu cloud image" || fail "the host cannot reach cloud-images.ubuntu.com"

echo "== pfSense (read-only)"
opt=$(pfx "name(//interfaces/*[ipaddr=\"$CI_GW\"])")
if [[ "$opt" =~ ^opt[0-9]+$ ]]; then
  pass "pfSense interface $opt has $CI_GW ($(pfx "string(//interfaces/$opt/descr)"))"
  [[ "$(pfx "string(//interfaces/$opt/if)")" == *".$VLAN_TAG" ]] && pass "$opt sits on VLAN $VLAN_TAG" || fail "$opt is not on VLAN $VLAN_TAG"
  [[ "$(pfx "boolean(//interfaces/$opt/enable)")" == true ]] && pass "$opt enabled" || fail "$opt not enabled"
  [[ "$(pfx "boolean(//dhcpd/$opt/enable)")" == true ]] && warn "DHCP is on for $opt (convention: off, static IPs)" || pass "no DHCP on $opt"
  rules=$(pfx "//filter/rule[interface=\"$opt\"]" | tr -d '\n\t' | sed 's#</rule>#</rule>\n#g')
  rules=$(grep -v "<disabled" <<<"$rules")   # a disabled rule counts for nothing
  n=$(grep -c '<rule>' <<<"$rules")
  (( n > 0 )) && pass "$n firewall rules on $opt" || fail "no firewall rules on $opt"
  # A pass rule may sit above the private-range block only if it is a real DNS or NTP exception:
  # a pass whose DESTINATION names specific servers (not any) and port 53 or 123. Anything else
  # above the block (any->any, a source-port match, a rule with no destination port) is a FAIL.
  dns_ntp_exception() {  # $1 = one flattened <rule>...</rule>
    local d; d=$(sed -n 's#.*<destination>\(.*\)</destination>.*#\1#p' <<<"$1")
    [[ "$1" == *"<type>pass</type>"* && -n "$d" && "$d" != *"<any/>"* && ( "$d" == *"<port>53</port>"* || "$d" == *"<port>123</port>"* ) ]]
  }
  first=""
  while IFS= read -r r; do
    [[ -z "$r" ]] && continue
    dns_ntp_exception "$r" && continue
    first=$r; break
  done <<<"$rules"
  if [[ "$first" == *"<type>block</type>"* && ( "$first" == *PRIVATE* || "$first" == *192.168.0.0/16* ) ]]; then
    pass "first $opt rule after any DNS/NTP exceptions blocks private destinations"
  else
    fail "the first $opt rule after the DNS/NTP exceptions must block private destinations; found: $(sed -n 's#.*<descr>\(.*\)</descr>.*#\1#p' <<<"$first" | head -c 80)"
  fi
  last=$(tail -1 <<<"$rules")
  [[ "$last" == *"<type>block</type>"* && "$last" == *"<any/></destination>"* ]] && pass "$opt ends with a default deny" || warn "$opt has no explicit trailing default deny"
  grep -q '41641\|3478' <<<"$rules" && fail "$opt passes VPN (Tailscale) ports 41641/3478: not for a CI VLAN" || pass "$opt passes no VPN ports"
  nat=$(pfx "//nat/outbound/rule[source/network=\"$opt\" or source/network=\"$CI_SUBNET\"]/descr/text()")
  [[ -n "$nat" ]] && pass "outbound NAT rule for $opt: $nat" || fail "no outbound NAT rule for $opt/$CI_SUBNET (mode is manual: without it there is no egress)"
  lan=$(pfx "//filter/rule[interface=\"lan\"]" | tr -d '\n\t' | sed 's#</rule>#</rule>\n#g')
  lan=$(grep -v "<disabled" <<<"$lan")
  grep -E "<type>block</type>" <<<"$lan" | grep -qE "$CI_SUBNET|<network>$opt</network>|<network>${opt}ip</network>" \
    && pass "LAN has a block rule toward the CI VLAN" || fail "LAN has no block rule toward $CI_SUBNET (LAN any->any would reach the runner)"
  # Order matters (first match wins): the admin pass rule must sit above the block toward the CI
  # VLAN, and no OTHER pass rule above that block may reach the CI VLAN (any->any included).
  pi=$(grep -n "<type>pass</type>" <<<"$lan" | grep -F "$ADMIN_HOST" | grep "<port>22</port>" | grep -E "$VM_IP|$CI_SUBNET" | head -1 | cut -d: -f1)
  bi=$(grep -n "<type>block</type>" <<<"$lan" | grep -E "$CI_SUBNET|<network>$opt</network>|<network>${opt}ip</network>" | head -1 | cut -d: -f1)
  if [[ -z "$pi" ]]; then fail "no LAN pass rule $ADMIN_HOST -> $VM_IP tcp 22"
  elif [[ -n "$bi" && "$pi" -gt "$bi" ]]; then fail "LAN admin pass rule sits below the block toward the CI VLAN, so it never matches"
  else pass "LAN admin pass rule $ADMIN_HOST -> runner exists and precedes the CI VLAN block"; fi
  if [[ -n "$bi" ]]; then
    wide=$(grep -n "<type>pass</type>" <<<"$lan" | awk -F: -v b="$bi" -v p="$pi" '$1 < b && $1 != p' \
      | grep -E "<destination><any/>|$CI_SUBNET|<network>$opt</network>|<network>${opt}ip</network>" | cut -d: -f1 | tr '\n' ' ')
    [[ -z "${wide// /}" ]] && pass "no other LAN pass rule above the CI VLAN block reaches the CI VLAN" \
      || fail "LAN pass rule(s) at position(s) $wide sit above the CI VLAN block and reach the CI VLAN (an any->any pass bypasses the block)"
  fi
else
  fail "no pfSense interface with address $CI_GW (CI VLAN not built yet)"
fi

echo "----"
echo "preflight: $F fail(s), $W warning(s)"
(( F == 0 ))
