#!/usr/bin/env bash
# =============================================================================
# runner-vm-setup.sh  —  run INSIDE the runner VM as root:
#     sudo /root/runner-vm-setup.sh <phase>
#
# Phases (idempotent, safe to re-run):
#   base              updates, toolchain, gh CLI, unattended security upgrades,
#                     IPv6 off, SSH key-only + admin-only, 'runner' user
#   docker            Docker Engine (docker.com repo), fixed address pools,
#                     runner user in the docker group (root-equivalent, see notes)
#   netcheck          BEFORE 'firewall': check that the outer (CI VLAN firewall) layer blocks the
#                     LAN on its own and still allows DNS + internet. Writes a marker that
#                     'runners' requires. Read-only apart from that marker.
#   firewall          in-VM egress/ingress filter, with a 5-minute dead-man switch
#   firewall-confirm  cancel the dead-man switch (only after a NEW ssh login works)
#   runners           install + verify actions/runner, one systemd service per repo
#   wazuh             optional Wazuh agent pinned to the manager's version
#   prune             weekly docker prune timer
#   hygiene           per-runner private /tmp + job-start hook that empties it (persistent-runner leftovers)
#   verify            local checks; exits non-zero on any FAIL
#
# Config: /root/runner-setup.env (KEY="value" lines). That file is the source of
# truth; values in it override the environment.
#
# Security model, in one paragraph: CI jobs run as 'runner'. That user is in the
# docker group, which is root-equivalent inside this VM, so the in-VM firewall
# stops accidents and lazy malware but not a determined job. The real boundary is
# the VM itself plus the Proxmox VM firewall on the hypervisor.
# =============================================================================
# shellcheck disable=SC2015  # "check && pass || fail": pass/fail always return 0
set -Eeuo pipefail
trap 'echo "ERROR: line $LINENO: $BASH_COMMAND" >&2' ERR

CONF=/root/runner-setup.env
# shellcheck disable=SC1090
if [[ -f "$CONF" ]]; then set -a; . "$CONF"; set +a; fi

ADMIN_USER="${ADMIN_USER:-${SUDO_USER:-ciadmin}}"
RUNNER_USER="${RUNNER_USER:-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-proxmox}"
RUNNER_BASE="${RUNNER_BASE:-/opt/actions-runner}"
RUNNER_NAME_PREFIX="${RUNNER_NAME_PREFIX:-$(hostname -s)}"
RUNNER_VERSION="${RUNNER_VERSION:-}"    # empty = latest release
RUNNER_SHA256="${RUNNER_SHA256:-}"      # empty = taken from the release notes
RUNNER_SUDO="${RUNNER_SUDO:-none}"      # none | apt | all
REGISTRATIONS_FILE="${REGISTRATIONS_FILE:-/root/.runner-registrations}"   # "owner/repo TOKEN" per line; shredded after use
ADMIN_CIDRS="${ADMIN_CIDRS:-}"          # SSH allowed from these; current SSH peers are added automatically
DNS_SERVERS="${DNS_SERVERS:-}"          # empty = upstream resolvers from systemd-resolved
ALLOW_LAN_TCP="${ALLOW_LAN_TCP:-}"      # "ip:port[,port] ..." LAN exceptions
BLOCK_CIDRS="${BLOCK_CIDRS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16}"
DOCKER_BIP="${DOCKER_BIP:-172.31.255.1/24}"
DOCKER_POOL_BASE="${DOCKER_POOL_BASE:-172.30.0.0/16}"
DOCKER_POOL_SIZE="${DOCKER_POOL_SIZE:-24}"
WAZUH_MANAGER="${WAZUH_MANAGER:-}"
WAZUH_VERSION="${WAZUH_VERSION:-}"      # exact manager version, e.g. 4.12.0
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-}"
VERIFY_LAN_TARGET="${VERIFY_LAN_TARGET:-}"  # ip:port on the LAN that must be blocked; default = gateway:80
OUTER_PROBES="${OUTER_PROBES:-}"        # "ip:port ..." LAN services pfSense must block (netcheck); must be set
NTP_SERVERS="${NTP_SERVERS:-}"          # e.g. the NTP servers the CI VLAN firewall allows; an isolated VLAN allows NTP only to these
GH_ENDPOINTS="${GH_ENDPOINTS:-https://api.github.com https://github.com https://codeload.github.com https://objects.githubusercontent.com https://pipelines.actions.githubusercontent.com https://results-receiver.actions.githubusercontent.com https://ghcr.io https://pkg-containers.githubusercontent.com https://registry-1.docker.io https://pypi.org https://files.pythonhosted.org}"
OUTER_MARKER=/var/lib/gh-runner-setup/outer-layer-ok

# The Wazuh agent must reach its manager even though the LAN is blocked.
if [[ -n "$WAZUH_MANAGER" && " $ALLOW_LAN_TCP " != *" $WAZUH_MANAGER:"* ]]; then
  ALLOW_LAN_TCP="${ALLOW_LAN_TCP:+$ALLOW_LAN_TCP }$WAZUH_MANAGER:1514,1515"
fi

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
apt_install() {
  apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

# --------------------------------------------------------------------- base
configure_runner_sudo() {
  local f=/etc/sudoers.d/90-gh-runner
  case "$RUNNER_SUDO" in
    none) rm -f "$f" ;;
    apt)  printf '%s ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt\n' "$RUNNER_USER" > "$f" ;;
    all)  printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$RUNNER_USER" > "$f" ;;
    *)    die "RUNNER_SUDO must be none, apt or all" ;;
  esac
  if [[ -f "$f" ]]; then
    chmod 0440 "$f"
    visudo -cf "$f" >/dev/null || { rm -f "$f"; die "sudoers validation failed"; }
    log "runner user sudo: $RUNNER_SUDO (root-equivalent, same as the docker group)"
  fi
}

phase_base() {
  log "waiting for cloud-init to finish"
  cloud-init status --wait >/dev/null 2>&1 || true
  apt-get update
  apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
  apt_install ca-certificates curl wget gnupg jq git zip unzip xz-utils tar build-essential \
    python3 python3-pip python3-venv iptables conntrack rsyslog unattended-upgrades \
    qemu-guest-agent acl nodejs fontconfig fonts-liberation fonts-liberation-sans-narrow

  # Time: isolated VLANs only pass NTP to approved IPs, so point timesyncd at them.
  if [[ -n "${NTP_SERVERS// /}" ]]; then
    install -d /etc/systemd/timesyncd.conf.d
    printf '[Time]\nNTP=%s\nFallbackNTP=\n' "$NTP_SERVERS" > /etc/systemd/timesyncd.conf.d/10-runner.conf
    systemctl restart systemd-timesyncd || true
  fi

  # GitHub CLI (official apt repo)
  install -d -m 0755 /etc/apt/keyrings
  if [[ ! -f /etc/apt/sources.list.d/github-cli.list ]]; then
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list
    apt-get update
  fi
  apt_install gh

  # Security updates install themselves. No automatic reboots: a reboot kills running jobs.
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
  systemctl enable --now qemu-guest-agent >/dev/null 2>&1 || systemctl start qemu-guest-agent || true

  # IPv6 off: a LAN host's IPv6 address would otherwise bypass the IPv4 LAN block.
  cat > /etc/sysctl.d/60-runner-no-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0
EOF
  sysctl --system >/dev/null

  # SSH: keys only, admin user only. sshd uses the FIRST value it sees, and
  # sshd_config.d is read in order, so this must sort before 60-cloudimg-settings.conf.
  id "$ADMIN_USER" >/dev/null 2>&1 || die "admin user $ADMIN_USER does not exist"
  cat > /etc/ssh/sshd_config.d/10-runner-hardening.conf <<EOF
# gh-runner-setup
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowUsers ${ADMIN_USER}
EOF
  mkdir -p /run/sshd
  if ! sshd -t; then
    rm -f /etc/ssh/sshd_config.d/10-runner-hardening.conf
    die "sshd config test failed; hardening file removed"
  fi
  systemctl reload ssh 2>/dev/null || systemctl restart ssh

  # The user CI jobs run as. No sudo unless RUNNER_SUDO says otherwise.
  id "$RUNNER_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$RUNNER_USER"
  configure_runner_sudo

  if [[ -f /var/run/reboot-required ]]; then
    log "REBOOT REQUIRED (kernel/libc update). Reboot the VM before the next phase."
  fi
  log "base: done"
}

# ------------------------------------------------------------------- docker
phase_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    local codename
    codename=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi

  [[ "$DOCKER_BIP" == */24 ]] || die "DOCKER_BIP must be a /24 (got $DOCKER_BIP)"
  install -d /etc/docker
  local want
  want=$(jq -n --arg bip "$DOCKER_BIP" --arg base "$DOCKER_POOL_BASE" --argjson size "$DOCKER_POOL_SIZE" \
    '{"bip": $bip,
      "default-address-pools": [{"base": $base, "size": $size}],
      "log-driver": "json-file",
      "log-opts": {"max-size": "20m", "max-file": "3"}}')
  if [[ ! -f /etc/docker/daemon.json ]] || ! jq -e --argjson w "$want" '. == $w' /etc/docker/daemon.json >/dev/null 2>&1; then
    [[ -f /etc/docker/daemon.json ]] && cp -a /etc/docker/daemon.json "/etc/docker/daemon.json.bak.$(date +%s)"
    printf '%s\n' "$want" > /etc/docker/daemon.json
    systemctl restart docker
  fi
  systemctl enable --now docker containerd >/dev/null 2>&1
  usermod -aG docker "$RUNNER_USER"
  log "docker: done. NOTE: the docker group is root-equivalent inside this VM."
}

# ----------------------------------------------------------------- netcheck
tcp_open() { timeout "${2:-6}" bash -c "exec 3<>/dev/tcp/${1%%:*}/${1##*:}" 2>/dev/null; }

phase_netcheck() {
  local fails=0 p gw dns
  if iptables -C OUTPUT -j RUNNER-EGRESS 2>/dev/null; then
    die "the in-VM firewall is active, so this test cannot see the pfSense layer. Run netcheck before 'firewall' (or after 'runner-firewall flush', then re-apply)"
  fi
  [[ -n "${OUTER_PROBES// /}" ]] || die "set OUTER_PROBES to LAN ip:port services that pfSense must block"
  gw=$(ip -4 route show default | awk '{print $3; exit}')
  dns=$(resolve_dns)
  echo "INFO  address $(ip -4 -o addr show scope global | awk '{print $4}' | paste -sd' ') gw $gw dns ${dns% }"
  if getent hosts github.com >/dev/null; then echo "PASS  DNS resolves github.com"; else echo "FAIL  DNS does not resolve"; fails=1; fi
  local u code
  for u in $GH_ENDPOINTS; do
    # any HTTP status proves the TLS path works; 000 means no connection
    code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null || true)
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then echo "PASS  egress $u (HTTP $code)"
    else echo "FAIL  no egress to $u"; fails=1; fi
  done
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then echo "PASS  clock is NTP-synchronised"
  else echo "WARN  clock not NTP-synchronised yet (check NTP_SERVERS against the CI VLAN firewall's NTP rule)"; fi
  if curl -fsS -m 15 -o /dev/null http://archive.ubuntu.com/ubuntu/; then echo "PASS  HTTP to archive.ubuntu.com"; else echo "WARN  no HTTP to archive.ubuntu.com (apt over http)"; fi
  for p in $OUTER_PROBES; do
    if tcp_open "$p"; then echo "FAIL  $p is REACHABLE through pfSense"; fails=1
    else echo "PASS  $p unreachable (the outer layer blocks it, or nothing listens there: probe hosts known to be up)"; fi
  done
  if [[ -n "$WAZUH_MANAGER" ]]; then
    if tcp_open "$WAZUH_MANAGER:1514"; then echo "PASS  Wazuh manager $WAZUH_MANAGER:1514 reachable (expected exception)"
    else echo "WARN  Wazuh manager $WAZUH_MANAGER:1514 not reachable (pfSense exception missing?)"; fi
  fi
  if (( fails )); then rm -f "$OUTER_MARKER"; die "outer layer check failed: do not register runners"; fi
  install -d -m 0700 "$(dirname "$OUTER_MARKER")"
  date -u +%FT%TZ > "$OUTER_MARKER"
  log "outer-layer checks passed (sampled connectivity, not proof); marker written to $OUTER_MARKER"
}

# ----------------------------------------------------------------- firewall
docker_cidrs() {  # the bridge network from DOCKER_BIP plus the address pool
  local ip=${DOCKER_BIP%/*}
  echo "${ip%.*}.0/24 $DOCKER_POOL_BASE"
}

resolve_dns() {
  if [[ -n "$DNS_SERVERS" ]]; then echo "$DNS_SERVERS"; return; fi
  awk '/^nameserver/{print $2}' /run/systemd/resolve/resolv.conf 2>/dev/null \
    | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u | tr '\n' ' ' || true
}

ssh_peers() {  # IPv4 addresses of current SSH clients
  ss -Htn state established '( sport = :22 )' 2>/dev/null \
    | awk '{print $4}' | sed -E 's/^\[//; s/\]?:[0-9]+$//; s/^::ffff://' \
    | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u | tr '\n' ' ' || true
}

write_firewall_tool() {
  cat > /usr/local/sbin/runner-firewall <<'TOOL'
#!/usr/bin/env bash
# runner-firewall — host firewall for the GitHub runner VM (gh-runner-setup)
#   runner-firewall apply   (re)build RUNNER-EGRESS / RUNNER-INPUT and hook them in
#   runner-firewall flush   remove hooks and chains (recovery)
#   runner-firewall show    print active rules with counters
# Config: /etc/runner-firewall.conf
set -euo pipefail
. /etc/runner-firewall.conf
IPT=iptables

mkchain() { $IPT -N "$1" 2>/dev/null || $IPT -F "$1"; }
unhook()  { while $IPT -C "$1" -j "$2" 2>/dev/null; do $IPT -D "$1" -j "$2"; done; }

apply() {
  # ---- egress: host processes (OUTPUT) and containers (DOCKER-USER) ----
  mkchain RUNNER-EGRESS
  $IPT -A RUNNER-EGRESS -o lo -j RETURN
  $IPT -A RUNNER-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  for c in $DOCKER_CIDRS; do $IPT -A RUNNER-EGRESS -d "$c" -j RETURN; done
  for d in $DNS_SERVERS; do
    $IPT -A RUNNER-EGRESS -d "$d" -p udp --dport 53 -j RETURN
    $IPT -A RUNNER-EGRESS -d "$d" -p tcp --dport 53 -j RETURN
  done
  for n in ${NTP_SERVERS:-}; do $IPT -A RUNNER-EGRESS -d "$n" -p udp --dport 123 -j RETURN; done   # NTP before the private-range reject; empty = none
  $IPT -A RUNNER-EGRESS -p udp --sport 68 --dport 67 -j RETURN
  for r in $ALLOW_LAN_TCP; do
    $IPT -A RUNNER-EGRESS -d "${r%%:*}" -p tcp -m multiport --dports "${r#*:}" -j RETURN
  done
  for c in $BLOCK_CIDRS; do
    $IPT -A RUNNER-EGRESS -d "$c" -m limit --limit 6/min --limit-burst 10 \
      -j LOG --log-prefix "RUNNER-EGRESS-BLOCK: " --log-level 4
    $IPT -A RUNNER-EGRESS -d "$c" -j REJECT --reject-with icmp-admin-prohibited
  done

  # ---- ingress: SSH only from admin sources ----
  mkchain RUNNER-INPUT
  $IPT -A RUNNER-INPUT -i lo -j RETURN
  $IPT -A RUNNER-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  $IPT -A RUNNER-INPUT -p udp --sport 67 --dport 68 -j RETURN
  for s in $ADMIN_SOURCES; do
    $IPT -A RUNNER-INPUT -s "$s" -p tcp --dport 22 -j RETURN
    $IPT -A RUNNER-INPUT -s "$s" -p icmp -j RETURN
  done
  $IPT -A RUNNER-INPUT -i docker0 -j RETURN
  $IPT -A RUNNER-INPUT -i br-+ -j RETURN
  $IPT -A RUNNER-INPUT -m limit --limit 6/min --limit-burst 10 \
    -j LOG --log-prefix "RUNNER-INPUT-DROP: " --log-level 4
  $IPT -A RUNNER-INPUT -j DROP

  # ---- hooks (idempotent) ----
  $IPT -C OUTPUT -j RUNNER-EGRESS 2>/dev/null || $IPT -I OUTPUT 1 -j RUNNER-EGRESS
  $IPT -N DOCKER-USER 2>/dev/null || true
  $IPT -C DOCKER-USER -j RUNNER-EGRESS 2>/dev/null || $IPT -I DOCKER-USER 1 -j RUNNER-EGRESS
  $IPT -C INPUT -j RUNNER-INPUT 2>/dev/null || $IPT -I INPUT 1 -j RUNNER-INPUT
}

flush() {
  unhook OUTPUT RUNNER-EGRESS
  unhook DOCKER-USER RUNNER-EGRESS
  unhook INPUT RUNNER-INPUT
  for ch in RUNNER-EGRESS RUNNER-INPUT; do
    $IPT -F "$ch" 2>/dev/null || true
    $IPT -X "$ch" 2>/dev/null || true
  done
}

case "${1:-}" in
  apply) apply ;;
  flush) flush ;;
  show)  for ch in RUNNER-EGRESS RUNNER-INPUT; do $IPT -L "$ch" -v -n --line-numbers 2>/dev/null || echo "$ch: absent"; done ;;
  *) echo "usage: $0 apply|flush|show" >&2; exit 2 ;;
esac
TOOL
  chmod 0755 /usr/local/sbin/runner-firewall

  cat > /etc/systemd/system/runner-firewall.service <<'UNIT'
[Unit]
Description=gh-runner-setup: runner VM firewall (egress + ingress)
Wants=network-online.target
After=network-online.target docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/runner-firewall apply

[Install]
WantedBy=multi-user.target docker.service
UNIT
}

phase_firewall() {
  command -v iptables >/dev/null || die "iptables missing (run 'base' first)"
  local dns admin
  dns=$(resolve_dns)
  # shellcheck disable=SC2046,SC2086  # word splitting is intended here
  admin=$(printf '%s\n' $ADMIN_CIDRS $(ssh_peers) | grep -v '^$' | sort -u | tr '\n' ' ' || true)
  [[ -n "${dns// /}" ]] || die "could not determine DNS servers; set DNS_SERVERS"
  if [[ -z "${admin// /}" && "${ALLOW_NO_ADMIN:-0}" != 1 ]]; then
    die "no admin SSH sources (ADMIN_CIDRS empty and no current SSH session) — refusing to lock SSH"
  fi

  cat > /etc/runner-firewall.conf <<EOF
# gh-runner-setup — generated $(date -u +%FT%TZ)
DOCKER_CIDRS="$(docker_cidrs)"
DNS_SERVERS="${dns% }"
NTP_SERVERS="${NTP_SERVERS:-}"
ALLOW_LAN_TCP="$ALLOW_LAN_TCP"
BLOCK_CIDRS="$BLOCK_CIDRS"
ADMIN_SOURCES="${admin% }"
EOF
  chmod 0644 /etc/runner-firewall.conf
  write_firewall_tool
  systemctl daemon-reload

  # Dead-man switch: if nobody confirms within 5 minutes, the rules are flushed.
  systemctl stop runner-fw-deadman.timer runner-fw-deadman.service >/dev/null 2>&1 || true
  systemctl reset-failed runner-fw-deadman.timer runner-fw-deadman.service >/dev/null 2>&1 || true
  systemd-run --quiet --unit=runner-fw-deadman --on-active=300 /usr/local/sbin/runner-firewall flush

  systemctl enable runner-firewall.service >/dev/null 2>&1
  systemctl restart runner-firewall.service
  log "firewall applied: dns=[${dns% }] admin=[${admin% }] lan-exceptions=[${ALLOW_LAN_TCP}]"
  log "DEAD-MAN SWITCH ARMED: rules flush in 5 min. From a NEW ssh session run: sudo $0 firewall-confirm"
}

phase_firewall_confirm() {
  systemctl stop runner-fw-deadman.timer >/dev/null 2>&1 || true
  systemctl reset-failed runner-fw-deadman.timer runner-fw-deadman.service >/dev/null 2>&1 || true
  if iptables -C INPUT -j RUNNER-INPUT 2>/dev/null; then
    log "dead-man switch cancelled; firewall stays active"
  else
    die "firewall is NOT active (dead-man already fired?). Re-run 'firewall', then confirm within 5 minutes."
  fi
}

# ------------------------------------------------------------------ runners
fetch_runner() {
  export LC_ALL=C.UTF-8   # grep -P needs a UTF-8 locale; under sudo it may be C
  local ver="$RUNNER_VERSION" sha="$RUNNER_SHA256" rel url f
  if [[ -z "$ver" ]]; then
    url=https://api.github.com/repos/actions/runner/releases/latest
  else
    url="https://api.github.com/repos/actions/runner/releases/tags/v${ver#v}"
  fi
  if [[ -z "$ver" || -z "$sha" ]]; then
    rel=$(curl -fsSL -H 'Accept: application/vnd.github+json' "$url") || die "cannot read $url"
    [[ -n "$ver" ]] || ver=$(jq -r '.tag_name' <<<"$rel")
    if [[ -z "$sha" ]]; then
      sha=$(jq -r '.body' <<<"$rel" \
        | grep -oP '(?<=<!-- BEGIN SHA linux-x64 -->)[0-9a-f]{64}(?=<!-- END SHA linux-x64 -->)' \
        | head -1 || true)
    fi
  fi
  ver=${ver#v}
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not determine the runner version (got '$ver')"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no SHA-256 for runner $ver in the release notes. Set RUNNER_SHA256 from https://github.com/actions/runner/releases — do not skip verification."
  install -d "$RUNNER_BASE/_cache"
  f="$RUNNER_BASE/_cache/actions-runner-linux-x64-$ver.tar.gz"
  if ! echo "$sha  $f" | sha256sum -c --status 2>/dev/null; then
    curl -fsSL --retry 3 -o "$f.part" \
      "https://github.com/actions/runner/releases/download/v$ver/actions-runner-linux-x64-$ver.tar.gz"
    echo "$sha  $f.part" | sha256sum -c --status || { rm -f "$f.part"; die "runner tarball checksum mismatch"; }
    mv "$f.part" "$f"
  fi
  log "actions/runner $ver verified (sha256 $sha)"
  echo "$f"
}

phase_runners() {
  id "$RUNNER_USER" >/dev/null 2>&1 || die "runner user missing (run 'base' first)"
  if [[ "${REQUIRE_FIREWALL:-1}" == 1 ]] && ! iptables -C OUTPUT -j RUNNER-EGRESS 2>/dev/null; then
    die "the runner firewall is not active — refusing to register runners on an unfiltered VM (set REQUIRE_FIREWALL=0 to override)"
  fi
  if [[ "${REQUIRE_FIREWALL:-1}" == 1 && ! -s "$OUTER_MARKER" ]]; then
    die "the outer (pfSense) layer was never verified — run 'netcheck' before 'firewall' first"
  fi
  configure_runner_sudo
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_BASE"

  if [[ -s "$REGISTRATIONS_FILE" ]]; then
    chmod 600 "$REGISTRATIONS_FILE"
    local tarball deps_done=0 regs=() line repo token slug dir name
    tarball=$(fetch_runner)
    mapfile -t regs < <(grep -Ev '^[[:space:]]*(#|$)' "$REGISTRATIONS_FILE")
    for line in "${regs[@]}"; do
      read -r repo token _ <<<"$line"
      [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "bad repo name '$repo' in $REGISTRATIONS_FILE"
      [[ -n "$token" ]] || die "missing token for $repo"
      slug=${repo//\//-}
      dir="$RUNNER_BASE/$slug"
      name="${RUNNER_NAME_PREFIX}-${repo#*/}"; name=${name:0:64}
      if [[ -f "$dir/.runner" ]]; then
        log "$repo: already configured in $dir — skipping registration"
        continue
      fi
      install -d -o "$RUNNER_USER" -g "$RUNNER_USER" "$dir"
      tar -xzf "$tarball" -C "$dir"
      chown -R "$RUNNER_USER:$RUNNER_USER" "$dir"
      if (( ! deps_done )); then
        "$dir/bin/installdependencies.sh" </dev/null >/dev/null
        deps_done=1
      fi
      log "$repo: registering runner '$name' (labels: $RUNNER_LABELS)"
      sudo -u "$RUNNER_USER" -H -- bash -c \
        'cd "$1" && ./config.sh --unattended --url "https://github.com/$2" --token "$3" --name "$4" --labels "$5" --work _work --replace' \
        _ "$dir" "$repo" "$token" "$name" "$RUNNER_LABELS" </dev/null >/dev/null
      ( cd "$dir" && ./svc.sh install "$RUNNER_USER" </dev/null >/dev/null && ./svc.sh start </dev/null >/dev/null )
    done
    shred -u "$REGISTRATIONS_FILE" 2>/dev/null || rm -f "$REGISTRATIONS_FILE"
    log "registration tokens file shredded"
  else
    log "no registrations file at $REGISTRATIONS_FILE — only checking existing runners"
  fi

  local d svc
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.runner" ]] || continue
    svc=$(cat "$d/.service" 2>/dev/null || true)
    if [[ -n "$svc" ]]; then
      systemctl enable --now "$svc" >/dev/null 2>&1 || log "WARN: could not start $svc"
    else
      log "WARN: $d is configured but has no .service file (svc.sh install failed?)"
    fi
  done
  log "runners: done"
}

# -------------------------------------------------------------------- wazuh
phase_wazuh() {
  if [[ -z "$WAZUH_MANAGER" ]]; then log "WAZUH_MANAGER not set — skipping the Wazuh agent"; return 0; fi
  [[ "$WAZUH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "set WAZUH_VERSION to the manager's exact version (an agent newer than the manager will not connect)"
  if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
    local major=${WAZUH_VERSION%%.*}
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${major}.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update
    local envs=(WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$(hostname -s)")
    [[ -n "$WAZUH_AGENT_GROUP" ]] && envs+=(WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP")
    env "${envs[@]}" apt-get install -y "wazuh-agent=${WAZUH_VERSION}-1"
    apt-mark hold wazuh-agent >/dev/null
  fi

  # Collect firewall drops (kernel log) and every runner's diagnostic logs.
  local conf=/var/ossec/etc/ossec.conf block d
  block="<!-- gh-runner-setup:begin -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>"
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.runner" ]] || continue
    block+="
  <localfile>
    <log_format>syslog</log_format>
    <location>${d%/}/_diag/*.log</location>
  </localfile>"
  done
  block+="
</ossec_config>
<!-- gh-runner-setup:end -->"
  sed -i '/<!-- gh-runner-setup:begin -->/,/<!-- gh-runner-setup:end -->/d' "$conf"
  printf '%s\n' "$block" >> "$conf"
  systemctl daemon-reload
  systemctl enable wazuh-agent >/dev/null 2>&1
  systemctl restart wazuh-agent
  log "wazuh: agent ${WAZUH_VERSION} installed (held), manager $WAZUH_MANAGER"
}

# ------------------------------------------------------------------ hygiene
# Persistent runners share state between jobs. Give every runner service its own /tmp
# (systemd PrivateTmp) and empty it at the start of each job via the runner's
# ACTIONS_RUNNER_HOOK_JOB_STARTED hook. Restarts only idle runners.
phase_hygiene() {
  local hook=/usr/local/bin/runner-job-started.sh d svc envf   # the runner only accepts .sh/.ps1/.js hooks
  rm -f /usr/local/bin/runner-job-started                     # pre-fix name
  cat > "$hook" <<'HOOK'
#!/bin/sh
# gh-runner-setup: runs as the runner user before every job, inside the service's private /tmp.
find /tmp -mindepth 1 -maxdepth 1 -user "$(id -un)" -exec rm -rf {} + 2>/dev/null || true
exit 0
HOOK
  chmod 0755 "$hook"
  # GitHub's prebuilt toolcache binaries (setup-python etc.) carry RUNPATH /opt/hostedtoolcache/...;
  # with the default _work/_tool cache they load the distro's libpython instead and crash.
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0755 /opt/hostedtoolcache
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.runner" && -f "$d/.service" ]] || continue
    svc=$(cat "$d/.service")
    install -d "/etc/systemd/system/${svc}.d"
    printf '[Service]\nPrivateTmp=yes\n' > "/etc/systemd/system/${svc}.d/10-gh-runner-setup.conf"
    envf="$d/.env"
    touch "$envf"; chown "$RUNNER_USER:$RUNNER_USER" "$envf"
    sed -i '/^ACTIONS_RUNNER_HOOK_JOB_STARTED=/d; /^AGENT_TOOLSDIRECTORY=/d; /^RUNNER_TOOL_CACHE=/d' "$envf"
    printf 'ACTIONS_RUNNER_HOOK_JOB_STARTED=%s\nAGENT_TOOLSDIRECTORY=/opt/hostedtoolcache\nRUNNER_TOOL_CACHE=/opt/hostedtoolcache\n' "$hook" >> "$envf"
  done
  systemctl daemon-reload
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.service" ]] || continue
    svc=$(cat "$d/.service")
    if pgrep -u "$RUNNER_USER" -f "Runner.Worker" >/dev/null && \
       pgrep -u "$RUNNER_USER" -af "Runner.Worker" | grep -q "${d%/}"; then
      log "WARN: $svc is running a job; restart it later to apply PrivateTmp"
    else
      systemctl restart "$svc"
    fi
  done
  log "hygiene: private /tmp per runner, job-start cleanup hook, tool cache at /opt/hostedtoolcache"
}

# -------------------------------------------------------------------- prune
phase_prune() {
  cat > /etc/systemd/system/runner-docker-prune.service <<'EOF'
[Unit]
Description=gh-runner-setup: prune Docker data older than a week

[Service]
Type=oneshot
ExecStart=/usr/bin/docker system prune -af --filter until=168h
ExecStart=/usr/bin/docker builder prune -af --filter until=168h
EOF
  cat > /etc/systemd/system/runner-docker-prune.timer <<'EOF'
[Unit]
Description=gh-runner-setup: weekly Docker prune

[Timer]
OnCalendar=weekly
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now runner-docker-prune.timer >/dev/null 2>&1
  log "prune: weekly timer enabled"
}

# ------------------------------------------------------------------- verify
phase_verify() {
  local fails=0 warns=0
  pass() { printf 'PASS  %s\n' "$*"; }
  fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
  warn() { printf 'WARN  %s\n' "$*"; warns=$((warns + 1)); }
  rej_count() { iptables -L RUNNER-EGRESS -v -x -n 2>/dev/null | awk '$3=="REJECT"{s+=$1} END{print s+0}'; }

  [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" == 1 ]] && pass "IPv6 disabled" || fail "IPv6 is enabled"
  [[ -f /etc/ssh/sshd_config.d/10-runner-hardening.conf ]] && pass "SSH hardening in place" || fail "SSH hardening file missing"
  systemctl is-active --quiet qemu-guest-agent && pass "qemu-guest-agent active" || warn "qemu-guest-agent not active"
  systemctl is-active --quiet docker && pass "docker active" || fail "docker not active"
  systemctl is-active --quiet runner-firewall && pass "runner-firewall.service active" || fail "runner-firewall.service not active"
  systemctl is-enabled --quiet runner-firewall && pass "runner-firewall.service enabled at boot" || fail "runner-firewall.service not enabled"
  iptables -C OUTPUT -j RUNNER-EGRESS 2>/dev/null && pass "egress hook on OUTPUT" || fail "egress hook missing on OUTPUT"
  iptables -C DOCKER-USER -j RUNNER-EGRESS 2>/dev/null && pass "egress hook on DOCKER-USER" || fail "egress hook missing on DOCKER-USER"
  iptables -C INPUT -j RUNNER-INPUT 2>/dev/null && pass "ingress hook on INPUT" || fail "ingress hook missing on INPUT"
  if [[ "$(systemctl show -p SubState --value runner-fw-deadman.timer 2>/dev/null)" == waiting ]]; then
    fail "dead-man timer still armed (run firewall-confirm from a new SSH session)"
  else
    pass "no dead-man timer pending"
  fi
  systemctl is-enabled --quiet runner-docker-prune.timer 2>/dev/null && pass "docker prune timer enabled" || warn "docker prune timer not enabled"
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.service" ]] || continue
    [[ "$(systemctl show -p PrivateTmp --value "$(cat "$d/.service")")" == yes ]] && pass "private /tmp for $(basename "$d")" || fail "no private /tmp for $(basename "$d") (run hygiene)"
    grep -qx 'ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/bin/runner-job-started.sh' "$d/.env" 2>/dev/null && [[ -x /usr/local/bin/runner-job-started.sh ]] && pass "job-start cleanup hook for $(basename "$d")" || fail "no job-start hook for $(basename "$d") (run hygiene)"
  done
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.service" ]] || continue
    grep -qx 'RUNNER_TOOL_CACHE=/opt/hostedtoolcache' "$d/.env" 2>/dev/null && pass "tool cache /opt/hostedtoolcache for $(basename "$d")" || fail "tool cache not /opt/hostedtoolcache for $(basename "$d") (run hygiene)"
  done
  command -v node >/dev/null && pass "node $(node --version)" || fail "node missing"
  fc-list | grep -q 'Liberation Sans Narrow' && pass "Liberation fonts present" || fail "Liberation fonts missing"
  [[ -s "$OUTER_MARKER" ]] && pass "outer pfSense layer verified at $(cat "$OUTER_MARKER")" || fail "outer pfSense layer never verified (netcheck)"

  # privilege
  if [[ "$RUNNER_SUDO" == none ]]; then
    if sudo -u "$RUNNER_USER" sudo -n true 2>/dev/null; then fail "runner user can sudo"; else pass "runner user has no sudo"; fi
  else
    warn "runner user has sudo ($RUNNER_SUDO) by configuration"
  fi

  # runners
  local n=0 d svc
  for d in "$RUNNER_BASE"/*/; do
    [[ -f "$d/.runner" ]] || continue
    n=$((n + 1))
    svc=$(cat "$d/.service" 2>/dev/null || true)
    if [[ -n "$svc" ]] && systemctl is-active --quiet "$svc"; then pass "runner service $svc active"; else fail "runner in $d is not running"; fi
  done
  (( n > 0 )) && pass "$n runner(s) configured" || warn "no runners configured yet"

  # egress policy: internet yes, LAN no — for host processes AND containers.
  local target lan_ip lan_port b a ok
  target=${VERIFY_LAN_TARGET:-$(ip -4 route show default | awk '{print $3; exit}'):80}
  lan_ip=${target%%:*}; lan_port=${target##*:}
  getent hosts github.com >/dev/null && pass "DNS resolves github.com" || fail "DNS lookup failed"
  sudo -u "$RUNNER_USER" curl -fsS -m 15 -o /dev/null https://api.github.com \
    && pass "runner user reaches api.github.com" || fail "runner user cannot reach api.github.com"

  b=$(rej_count)
  if sudo -u "$RUNNER_USER" timeout 6 bash -c "exec 3<>/dev/tcp/$lan_ip/$lan_port" 2>/dev/null; then ok=1; else ok=0; fi
  a=$(rej_count)
  if (( a > b )); then pass "LAN $lan_ip:$lan_port blocked for runner processes"
  elif (( ok )); then fail "LAN $lan_ip:$lan_port REACHABLE from runner processes"
  else fail "LAN test inconclusive for runner processes (connection failed but no RUNNER-EGRESS reject counted)"; fi

  if command -v docker >/dev/null 2>&1; then
    sudo -u "$RUNNER_USER" docker run --rm hello-world >/dev/null 2>&1 \
      && pass "runner user can run containers" || fail "runner user cannot run containers"
    sudo -u "$RUNNER_USER" docker run --rm alpine:3 wget -q -T 15 --spider https://github.com >/dev/null 2>&1 \
      && pass "containers reach github.com" || fail "containers cannot reach github.com"
    b=$(rej_count)
    if sudo -u "$RUNNER_USER" docker run --rm alpine:3 wget -q -T 6 -O /dev/null "http://$lan_ip:$lan_port" >/dev/null 2>&1; then ok=1; else ok=0; fi
    a=$(rej_count)
    if (( a > b )); then pass "LAN $lan_ip:$lan_port blocked for containers"
    elif (( ok )); then fail "LAN $lan_ip:$lan_port REACHABLE from containers"
    else fail "LAN test inconclusive for containers (connection failed but no RUNNER-EGRESS reject counted)"; fi
  fi

  if [[ -n "$WAZUH_MANAGER" ]]; then
    systemctl is-active --quiet wazuh-agent && pass "wazuh-agent active" || fail "wazuh-agent not active"
  fi
  [[ -f /var/run/reboot-required ]] && warn "reboot required (pending kernel/libc update)"

  echo "----"
  echo "verify: $fails fail(s), $warns warning(s)"
  (( fails == 0 ))
}

# --------------------------------------------------------------------- main
[[ $EUID -eq 0 ]] || die "run as root (sudo)"
case "${1:-}" in
  base)             phase_base ;;
  netcheck)         phase_netcheck ;;
  docker)           phase_docker ;;
  firewall)         phase_firewall ;;
  firewall-confirm) phase_firewall_confirm ;;
  runners)          phase_runners ;;
  wazuh)            phase_wazuh ;;
  prune)            phase_prune ;;
  hygiene)          phase_hygiene ;;
  verify)           phase_verify ;;
  *) awk 'NR>1 && /^# shellcheck/{exit} NR>1 && /^#/{print; next} NR>1{exit}' "$0"; exit 2 ;;
esac
