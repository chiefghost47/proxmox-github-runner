#!/usr/bin/env bash
# =============================================================================
# proxmox-create-runner-vm.sh  —  run ON THE PROXMOX VE HOST as root
#
# Builds the VM for a GitHub Actions self-hosted runner and writes its Proxmox
# VM firewall file.
#
# What it will NOT do, ever:
#   - enable the datacenter firewall, or edit cluster.fw / host.fw
#   - touch any other guest, host networking, bridges or routes
#   - stop, reset or destroy any VM
#
# Subcommands:
#   recon       read-only facts about this host (storage, bridges, memory, firewall)
#   netcheck    read-only: is the CI VLAN trunked to this host's bridge? (create runs it)
#   create      download + verify the Ubuntu cloud image, create and start the VM
#               on the CI VLAN, wait for the guest agent, print the VM's IPv4
#   ip          print the VM's IPv4 (needs qemu-guest-agent in the VM)
#   firewall    write /etc/pve/firewall/<VMID>.fw for the VM (see FIREWALL INPUTS)
#   fw-status   say whether the VM firewall rules are actually live, and why not
#
# State (VMID, key path, IP) is kept in $STATE_DIR/vm.env so later calls find
# the VM without being told again. Explicit environment variables win.
# =============================================================================
set -Eeuo pipefail
trap 'echo "ERROR: line $LINENO: $BASH_COMMAND" >&2' ERR

STATE_DIR="${STATE_DIR:-/root/gh-runner-setup}"
STATE_FILE="$STATE_DIR/vm.env"

# Load saved state for keys the caller did not set explicitly.
if [[ -f "$STATE_FILE" ]]; then
  while IFS='=' read -r _k _v; do
    case "$_k" in
      VMID|VM_NAME|SSH_KEY|CI_USER|VM_IP) [[ -z "${!_k:-}" ]] && printf -v "$_k" '%s' "$_v" ;;
    esac
  done < "$STATE_FILE"
fi

# ---------------------------------------------------------------- VM settings
VM_NAME="${VM_NAME:-ci-runner-01}"
VM_TAGS="${VM_TAGS:-github-runner;ci}"
VM_DESCRIPTION="${VM_DESCRIPTION:-GitHub Actions self-hosted runner. Untrusted CI code runs here.}"
VMID="${VMID:-}"                         # empty = next free id
NODE="${NODE:-$(hostname -s)}"
STORAGE="${STORAGE:-}"                   # empty = local-lvm if present, else first active 'images' storage
SNIPPET_STORAGE="${SNIPPET_STORAGE:-local}"
BRIDGE="${BRIDGE:-vmbr0}"
VLAN_TAG="${VLAN_TAG:-}"                 # REQUIRED for create: a VLAN dedicated to CI, never one that carries other systems
IPCONFIG0="${IPCONFIG0:-ip=dhcp}"        # e.g. "ip=10.90.0.10/24,gw=10.90.0.1" (an isolated VLAN usually has no DHCP)
NAMESERVER="${NAMESERVER:-}"             # e.g. 10.90.0.1 (the firewall resolver on the CI VLAN)
SEARCHDOMAIN="${SEARCHDOMAIN:-}"         # e.g. lab.example
CORES="${CORES:-4}"
MEMORY_MB="${MEMORY_MB:-8192}"
MEM_HEADROOM_MB="${MEM_HEADROOM_MB:-2048}"   # host MemAvailable must exceed MEMORY_MB by this much
BALLOON="${BALLOON:-0}"                      # 0 = fixed allocation; small ballooned guests thrash under CI load
DISK_GB="${DISK_GB:-50}"
UBUNTU_SERIES="${UBUNTU_SERIES:-noble}"      # 24.04 LTS
CI_USER="${CI_USER:-ciadmin}"
SSH_KEY="${SSH_KEY:-$STATE_DIR/keys/${VM_NAME}_ed25519}"
IMG_DIR="${IMG_DIR:-$STATE_DIR/images}"
VM_IP="${VM_IP:-}"

# ---------------------------------------------------------- FIREWALL INPUTS
ADMIN_CIDRS="${ADMIN_CIDRS:-}"     # extra SSH sources (space separated). All of this host's IPv4s are added automatically.
DNS_SERVERS="${DNS_SERVERS:-}"     # resolver IPs the VM uses (space separated) — required by 'firewall'
ALLOW_LAN_TCP="${ALLOW_LAN_TCP:-}" # LAN exceptions "ip:port[,port] ..." e.g. a SIEM agent "10.90.1.20:1514,1515"
BLOCK_CIDRS_V4="${BLOCK_CIDRS_V4:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16}"

# ------------------------------------------------------------------ helpers
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
# JSON helper using the host's own python3: no packages are ever installed on the hypervisor.
pyj() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

save_state() {
  mkdir -p "$STATE_DIR"
  {
    echo "VMID=$VMID"
    echo "VM_NAME=$VM_NAME"
    echo "SSH_KEY=$SSH_KEY"
    echo "CI_USER=$CI_USER"
    echo "VM_IP=${VM_IP:-}"
  } > "$STATE_FILE"
}

record_change() {  # exhaustive list of host changes, for the report and for rollback
  mkdir -p "$STATE_DIR"
  printf '%s  %s\n' "$(date -u +%FT%TZ)" "$*" >> "$STATE_DIR/host-changes.log"
}

dc_fw_enabled() {
  [[ -f /etc/pve/firewall/cluster.fw ]] || return 1
  awk '/^\[OPTIONS\]/{o=1;next} /^\[/{o=0} o && /^[[:space:]]*enable:[[:space:]]*1/{f=1} END{exit !f}' \
    /etc/pve/firewall/cluster.fw
}

find_vm_by_name() {  # prints VMID of a guest with that name, returns 1 if none
  pvesh get /cluster/resources --type vm --output-format json \
    | N="$1" pyj 'import os; [print(g["vmid"]) for g in d if g.get("name")==os.environ["N"]]' | head -1 | grep .
}

pick_storage() {  # explicit STORAGE wins; else the active 'images' storage with the most free space
  if [[ -n "$STORAGE" ]]; then echo "$STORAGE"; return; fi
  pvesm status --content images 2>/dev/null     | awk 'NR>1 && $3=="active" && $6 ~ /^[0-9]+$/ {print $6, $1}' | sort -rn | awk 'NR==1{print $2}'
}

uplinks() {  # physical/bond ports enslaved to $BRIDGE (not tap/veth/fw* guest ports)
  local p
  for p in /sys/class/net/"$BRIDGE"/brif/*; do
    p=${p##*/}
    if [[ -e /sys/class/net/$p/device || -d /sys/class/net/$p/bonding ]]; then echo "$p"; fi
  done
  return 0
}

host_ipv4s() {  # this host's IPv4s, minus Tailscale/CGNAT (the VM can never be reached from those)
  ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]}' \
    | grep -Ev '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.' | sort -u || true
}

# ------------------------------------------------------------------- recon
cmd_recon() {
  need pveversion; need pvesh; need qm; need python3
  echo "## pveversion";        pveversion
  echo "## node";              echo "$NODE"
  echo "## cpu";               lscpu | grep -E '^(Model name|Socket|Core|Thread|CPU\(s\))' || true
  echo "## memory (MB)";       awk '/^(MemTotal|MemAvailable):/{printf "%s %d\n", $1, $2/1024}' /proc/meminfo
  if [[ -r /proc/spl/kstat/zfs/arcstats ]]; then
    echo "## zfs arc (MB)";    awk '$1=="size"{print int($3/1048576)}' /proc/spl/kstat/zfs/arcstats
  fi
  echo "## storage";           pvesm status
  echo "## storage content";   pvesh get /storage --output-format json | pyj '[print(s["storage"], s["type"], s.get("content",""), sep="\t") for s in d]'
  echo "## bridges";           ip -br link show type bridge || true
  echo "## /etc/network/interfaces (bridge lines)"
  grep -E '^[[:space:]]*(auto|iface|bridge-|address|gateway)' /etc/network/interfaces || true
  echo "## host ipv4";         ip -4 -br addr
  echo "## default route";     ip route show default
  echo "## host resolvers";    grep -E '^nameserver' /etc/resolv.conf || true
  echo "## guests (qm)";       qm list
  echo "## guests (pct)";      pct list 2>/dev/null || true
  echo "## next vmid";         pvesh get /cluster/nextid
  echo "## guest named $VM_NAME"; find_vm_by_name "$VM_NAME" || echo "none"
  echo "## saved state";       cat "$STATE_FILE" 2>/dev/null || echo "none"
  echo "## datacenter firewall"; if dc_fw_enabled; then echo ENABLED; else echo disabled; fi
  echo "## pve-firewall status";   pve-firewall status 2>&1 || true
  echo "## pve-firewall localnet"; pve-firewall localnet 2>&1 || true
  echo "## tailscale on host";     if command -v tailscale >/dev/null; then tailscale ip -4 2>&1 || true; else echo "not installed"; fi
  echo "## tools"
  local c; for c in python3 curl ssh ssh-keygen sha256sum; do
    printf '%-10s %s\n' "$c" "$(command -v "$c" || echo MISSING)"
  done
}

# ----------------------------------------------------------------- netcheck
# Read-only. Fails unless the CI VLAN reaches this host's bridge. It cannot see the
# switch or pfSense; those are checked from inside the VM (runner-vm-setup.sh netcheck).
cmd_netcheck() {
  local fails=0 p
  [[ -n "$VLAN_TAG" ]] || { echo "FAIL  VLAN_TAG is empty: the runner must live on the dedicated CI VLAN"; return 1; }
  [[ "$VLAN_TAG" =~ ^[0-9]+$ ]] && (( VLAN_TAG >= 2 && VLAN_TAG <= 4094 )) || { echo "FAIL  bad VLAN_TAG '$VLAN_TAG'"; return 1; }
  if [[ "$(cat /sys/class/net/$BRIDGE/bridge/vlan_filtering 2>/dev/null)" == 1 ]]; then
    echo "PASS  $BRIDGE is VLAN-aware"
  else
    echo "FAIL  $BRIDGE is not VLAN-aware"; fails=1
  fi
  local ups; ups=$(uplinks)
  [[ -n "$ups" ]] || { echo "FAIL  no physical uplink found on $BRIDGE"; fails=1; }
  for p in $ups; do
    if bridge vlan show dev "$p" 2>/dev/null | awk '{for(i=1;i<=NF;i++) print $i}' | grep -qx "$VLAN_TAG"; then
      echo "PASS  VLAN $VLAN_TAG is allowed on uplink $p"
    else
      echo "FAIL  VLAN $VLAN_TAG is not allowed on uplink $p (add it to bridge-vids of $BRIDGE; a host-admin change)"; fails=1
    fi
  done
  if grep -qE "^[[:space:]]*bridge-vids.*(^|[[:space:]])${VLAN_TAG}([[:space:]]|$)" /etc/network/interfaces; then
    echo "PASS  VLAN $VLAN_TAG is persisted in /etc/network/interfaces (survives a host reboot)"
  else
    echo "FAIL  VLAN $VLAN_TAG is live-only or absent: not in bridge-vids in /etc/network/interfaces"; fails=1
  fi
  local used
  used=$(grep -l "^net[0-9]*:.*tag=${VLAN_TAG}\([,[:space:]]\|$\)" /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ' || true)
  if [[ -n "$used" ]]; then
    echo "WARN  other guests already use VLAN $VLAN_TAG: $used (a CI VLAN should be dedicated)"
  else
    echo "PASS  no other guest is on VLAN $VLAN_TAG"
  fi
  if [[ "$IPCONFIG0" == "ip=dhcp" ]]; then
    echo "WARN  IPCONFIG0 is DHCP; an isolated VLAN normally uses static addresses"
  else
    echo "INFO  IPCONFIG0=$IPCONFIG0 NAMESERVER=${NAMESERVER:-<unset>}"
  fi
  return "$fails"
}

# ------------------------------------------------------------------- create
check_resources() {
  local st=$1 avail_mb need_mb avail_kib
  avail_mb=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  need_mb=$(( MEMORY_MB + MEM_HEADROOM_MB ))
  (( avail_mb >= need_mb )) || die "host MemAvailable is ${avail_mb} MB; need ${MEMORY_MB} + ${MEM_HEADROOM_MB} headroom = ${need_mb} MB. Do not overcommit the host: retry with a smaller MEMORY_MB only if it fits."
  avail_kib=$(pvesm status --storage "$st" | awk 'NR==2{print $6}')
  [[ "$avail_kib" =~ ^[0-9]+$ ]] || die "could not read free space for storage $st"
  (( avail_kib / 1048576 >= DISK_GB + 10 )) || die "storage $st has $(( avail_kib / 1048576 )) GiB free; need $(( DISK_GB + 10 )) GiB"
  log "resources ok: MemAvailable ${avail_mb} MB, storage $st $(( avail_kib / 1048576 )) GiB free"
}

download_image() {
  local base="https://cloud-images.ubuntu.com/${UBUNTU_SERIES}/current"
  local name="${UBUNTU_SERIES}-server-cloudimg-amd64.img"
  local img="$IMG_DIR/$name" sums="$IMG_DIR/SHA256SUMS.${UBUNTU_SERIES}" want
  mkdir -p "$IMG_DIR"
  curl -fsSL --retry 3 "$base/SHA256SUMS" -o "$sums"
  want=$(awk -v n="$name" '$2=="*"n || $2==n {print $1}' "$sums")
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "no SHA-256 for $name in $base/SHA256SUMS"
  if [[ -f "$img" ]] && echo "$want  $img" | sha256sum -c --status; then
    log "cloud image already present and verified"
  else
    log "downloading $name"
    curl -fL --retry 3 -o "$img.part" "$base/$name"
    echo "$want  $img.part" | sha256sum -c --status || { rm -f "$img.part"; die "checksum mismatch for $name"; }
    mv "$img.part" "$img"
    log "cloud image verified ($want)"
  fi
  echo "$img"
}

ensure_key() {
  local d; d=$(dirname "$SSH_KEY")
  mkdir -p "$d"; chmod 700 "$d"
  if [[ -f "${SSH_KEY}.pub" && ! -f "$SSH_KEY" ]]; then
    log "using public key ${SSH_KEY}.pub (private key is held off-host)"
  elif [[ ! -f "$SSH_KEY" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C "${VM_NAME}-admin@$(hostname -s)" -f "$SSH_KEY"
    log "generated SSH key $SSH_KEY"
  fi
}

ensure_snippets() {
  local content
  content=$(pvesh get "/storage/$SNIPPET_STORAGE" --output-format json | pyj 'print(d.get("content",""))')
  if ! tr ',' '\n' <<<"$content" | grep -qx snippets; then
    log "adding 'snippets' content type to storage $SNIPPET_STORAGE (currently: $content)"
    pvesm set "$SNIPPET_STORAGE" --content "${content:+$content,}snippets"
    record_change "storage $SNIPPET_STORAGE: content '$content' -> '${content:+$content,}snippets' (rollback: pvesm set $SNIPPET_STORAGE --content '$content')"
  fi
}

write_vendor_snippet() {
  local vol="$SNIPPET_STORAGE:snippets/${VM_NAME}-vendor.yaml" path
  path=$(pvesm path "$vol")
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<'EOF'
#cloud-config
# gh-runner-setup: install the QEMU guest agent so the Proxmox host can find
# and recover this VM without network access (qm guest exec).
package_update: true
packages:
  - qemu-guest-agent
runcmd:
  - [systemctl, start, qemu-guest-agent]
EOF
  record_change "wrote cloud-init vendor snippet $path"
  echo "$vol"
}

wait_agent() {
  local t=${1:-900} s=$SECONDS
  while (( SECONDS - s < t )); do
    qm guest cmd "$VMID" ping >/dev/null 2>&1 && return 0
    sleep 10
  done
  return 1
}

vm_ip() {
  qm guest cmd "$VMID" network-get-interfaces 2>/dev/null | python3 -c '
import sys, json, re
try: d = json.load(sys.stdin)
except ValueError: sys.exit(0)   # agent not up yet
ips=[a["ip-address"] for i in d if i.get("name")!="lo" and not re.match(r"(docker|br-|veth)", i.get("name",""))
     for a in i.get("ip-addresses",[]) if a.get("ip-address-type")=="ipv4"]
print(ips[0] if ips else "")' | grep .
}

cmd_create() {
  need qm; need pvesh; need pvesm; need python3; need curl; need sha256sum; need ssh-keygen
  local existing st img vendor net ip
  if existing=$(find_vm_by_name "$VM_NAME"); then
    die "a guest named $VM_NAME already exists (VMID $existing). Not touching it. Pick another VM_NAME, or use 'ip' if this build created it."
  fi
  [[ -n "$VMID" ]] || VMID=$(pvesh get /cluster/nextid)
  if qm status "$VMID" >/dev/null 2>&1; then die "VMID $VMID is already in use"; fi
  cmd_netcheck || die "network prerequisites for VLAN ${VLAN_TAG:-<unset>} are not in place; not creating the VM"
  st=$(pick_storage); [[ -n "$st" ]] || die "no active storage with 'images' content"
  check_resources "$st"
  img=$(download_image)
  ensure_key
  ensure_snippets
  vendor=$(write_vendor_snippet)

  net="virtio,bridge=${BRIDGE},firewall=1"
  [[ -n "$VLAN_TAG" ]] && net+=",tag=${VLAN_TAG}"

  log "creating VM $VMID ($VM_NAME) on storage $st, bridge $BRIDGE${VLAN_TAG:+ vlan $VLAN_TAG}"
  qm create "$VMID" --name "$VM_NAME" --tags "$VM_TAGS" --onboot 1 \
    --description "$VM_DESCRIPTION Built by gh-runner-setup $(date -u +%F)." \
    --ostype l26 --cpu host --sockets 1 --cores "$CORES" --memory "$MEMORY_MB" --balloon "$BALLOON" \
    --scsihw virtio-scsi-single --net0 "$net" --agent enabled=1 \
    --serial0 socket --vga serial0
  record_change "created VM $VMID ($VM_NAME)"
  save_state   # saved immediately so a later failure still leaves a findable VM

  qm set "$VMID" --scsi0 "${st}:0,import-from=${img},discard=on,iothread=1,ssd=1"
  qm disk resize "$VMID" scsi0 "${DISK_GB}G" 2>/dev/null || qm resize "$VMID" scsi0 "${DISK_GB}G"
  qm set "$VMID" --ide2 "${st}:cloudinit" --boot order=scsi0
  qm set "$VMID" --ciuser "$CI_USER" --sshkeys "${SSH_KEY}.pub" --ipconfig0 "$IPCONFIG0" --cicustom "vendor=${vendor}"
  if [[ -n "$NAMESERVER" ]]; then qm set "$VMID" --nameserver "$NAMESERVER"; fi
  if [[ -n "$SEARCHDOMAIN" ]]; then qm set "$VMID" --searchdomain "$SEARCHDOMAIN"; fi
  qm start "$VMID"
  record_change "started VM $VMID"

  log "waiting for the guest agent (first boot installs it; can take several minutes)"
  wait_agent 900 || die "guest agent not responding after 15 min. The CI VLAN may lack internet/DNS (the agent is installed from apt on first boot). Check 'qm terminal $VMID' and the pfSense CI rules"
  local tries=0
  until ip=$(vm_ip); do
    (( ++tries > 30 )) && die "guest agent is up but reports no IPv4 (DHCP?)"
    sleep 5
  done
  VM_IP="$ip"; save_state
  log "VM $VMID ($VM_NAME) is up at $VM_IP"
  echo "$VM_IP"
}

cmd_ip() {
  [[ -n "$VMID" ]] || die "VMID unknown (run create first or set VMID)"
  local ip; ip=$(vm_ip) || die "no IPv4 from the guest agent for VM $VMID"
  VM_IP="$ip"; save_state
  echo "$ip"
}

# ----------------------------------------------------------------- firewall
cmd_firewall() {
  [[ -n "$VMID" ]] || die "VMID unknown (run create first or set VMID)"
  qm config "$VMID" >/dev/null 2>&1 || die "VM $VMID not found"
  [[ -n "$DNS_SERVERS" ]] || die "set DNS_SERVERS to the resolver IP(s) the VM uses"
  local admin=() c f tmp r ip ports
  for c in $(host_ipv4s) $ADMIN_CIDRS; do admin+=("$c"); done
  (( ${#admin[@]} )) || die "no admin sources — refusing to write rules that block all SSH"

  f="/etc/pve/firewall/${VMID}.fw"
  tmp=$(mktemp)
  {
    echo "# gh-runner-setup: firewall for the GitHub runner VM (untrusted CI code)."
    echo "# Generated $(date -u +%FT%TZ). Live only when the datacenter firewall is enabled."
    echo "# The outer control is the firewall on the CI VLAN; this file is defence in depth."
    echo "[OPTIONS]"
    echo "enable: 1"
    echo "policy_in: DROP"
    echo "policy_out: ACCEPT"
    echo "dhcp: 1"
    echo "ndp: 0"
    echo "radv: 0"
    echo "macfilter: 1"
    echo "log_level_in: nolog"
    echo "log_level_out: nolog"
    echo
    echo "[RULES]"
    for c in "${admin[@]}"; do
      echo "IN ACCEPT -source $c -p tcp -dport 22 -log nolog # admin ssh"
      echo "IN ACCEPT -source $c -p icmp -log nolog # admin ping"
    done
    echo "OUT ACCEPT -p udp -sport 68 -dport 67 -log nolog # dhcp"
    for c in $DNS_SERVERS; do
      echo "OUT ACCEPT -dest $c -p udp -dport 53 -log nolog # dns"
      echo "OUT ACCEPT -dest $c -p tcp -dport 53 -log nolog # dns"
    done
    for r in $ALLOW_LAN_TCP; do
      ip=${r%%:*}; ports=${r#*:}
      echo "OUT ACCEPT -dest $ip -p tcp -dport $ports -log nolog # lan exception"
    done
    for c in $BLOCK_CIDRS_V4; do
      echo "OUT REJECT -dest $c -log info # no LAN / private ranges"
    done
    echo "OUT DROP -dest ::/0 -log nolog # no IPv6 at all"
  } > "$tmp"

  if [[ -f "$f" ]]; then
    cp -a "$f" "$STATE_DIR/backup-${VMID}.fw.$(date +%s)"
    log "backed up existing $f"
  fi
  cp "$tmp" "$f"; rm -f "$tmp"
  record_change "wrote $f (VM firewall for $VMID only)"
  log "wrote $f"
  cmd_fw_status
}

cmd_fw_status() {
  local hf="/etc/pve/nodes/$NODE/host.fw" vf
  echo "datacenter firewall : $(dc_fw_enabled && echo ENABLED || echo disabled)"
  if [[ -f "$hf" ]]; then
    echo "host.fw ($NODE)      : $(grep -E '^[[:space:]]*enable:' "$hf" || echo 'no enable line (defaults to on)')"
  else
    echo "host.fw ($NODE)      : no file (host rules default to on once the datacenter firewall is enabled)"
  fi
  if [[ -n "$VMID" ]]; then
    vf="/etc/pve/firewall/$VMID.fw"
    echo "VM $VMID .fw file    : $([[ -f $vf ]] && echo present || echo MISSING)"
    echo "VM $VMID net0        : $(qm config "$VMID" | awk -F': ' '/^net0:/{print $2}')"
    if dc_fw_enabled && [[ -f "$vf" ]] && qm config "$VMID" | grep -q '^net0:.*firewall=1'; then
      echo "VM rules            : LIVE"
      echo "## compile warnings/errors (if any)"
      pve-firewall compile 2>&1 | grep -iE 'error|warn' | head -20 || echo "none"
    else
      echo "VM rules            : written but NOT live (datacenter firewall is off)"
    fi
  fi
  echo "## other guests with their own firewall enabled (they would start filtering if the datacenter firewall is turned on)"
  local other
  other=$(grep -l '^[[:space:]]*enable:[[:space:]]*1' /etc/pve/firewall/*.fw 2>/dev/null \
          | grep -v '/cluster\.fw$' | grep -v "/${VMID:-none}\.fw$" || true)
  echo "${other:-none}"
}

# --------------------------------------------------------------------- main
[[ $EUID -eq 0 ]] || die "run as root on the Proxmox host"
command -v pveversion >/dev/null 2>&1 || die "this is not a Proxmox VE host"

case "${1:-}" in
  recon)     cmd_recon ;;
  netcheck)  cmd_netcheck || exit 1 ;;
  create)    cmd_create ;;
  ip)        cmd_ip ;;
  firewall)  cmd_firewall ;;
  fw-status) cmd_fw_status ;;
  *) awk 'NR>1 && /^# shellcheck/{exit} NR>1 && /^#/{print; next} NR>1{exit}' "$0"; exit 2 ;;
esac
