# proxmox-github-runner

A GitHub Actions self-hosted runner on a Proxmox VM, built into its own isolated VLAN, with a
read-only preflight that catches isolation mistakes before anything is created, and a one-variable
switch that moves workflows between GitHub-hosted and self-hosted runners.

Built for a self-hosted security stack where the runner must never reach the rest of the network,
and where a mistake in the firewall should fail the build, not be discovered later.

![ci](https://github.com/chiefghost47/proxmox-github-runner/actions/workflows/ci.yml/badge.svg)

## What you get

- **An isolated runner.** The VM lives on a dedicated VLAN. The outer firewall (pfSense here,
  but any firewall with the same rules works) blocks every private range, allows DNS and NTP
  only to named public servers, allows web traffic only to non-private addresses, allows SSH
  only to GitHub's published git ranges, and ends with a default deny. Rules match first-hit, so
  the private-range block goes first when the DNS and NTP servers are public; if you point the
  runner at a private resolver or time source instead, those two exceptions must sit above the
  block. The LAN side gets one pass rule, from one admin host to the runner's SSH port through
  the hypervisor, and a block for everything else.
- **A second layer inside the VM.** An iptables egress filter that rejects private ranges for
  host processes and containers, an ingress filter that accepts SSH only from the admin host, and
  a five-minute dead-man switch so a bad rule cannot lock you out.
- **Hygiene for a persistent runner.** One systemd service per repository, each with a private
  `/tmp`, a job-start hook that empties it, GitHub's tool cache at `/opt/hostedtoolcache` so
  `setup-python` and friends work, Docker with fixed address pools, and a weekly prune.
- **A preflight that reads, never writes.** It cannot prove isolation, only catch the common
  mistakes before anything exists. It checks the VLAN is trunked
  to the bridge, memory and ZFS headroom, the PAT's scopes against every repo, and the firewall's
  own config over SSH for the rule order, the NAT rule and the LAN block.
- **A switch, not a migration.** `runs-on: ${{ vars.RUNNER || 'ubuntu-latest' }}`. One repository
  variable moves jobs to the runner; unsetting it moves them back.

## Layout

| Path | Runs where | What it does |
| :- | :- | :- |
| `scripts/preflight.sh` | workstation | read-only checks of host, firewall, PAT and repos; must print `0 fail(s)` |
| `scripts/proxmox-create-runner-vm.sh` | Proxmox host, as root | `recon`, `netcheck`, `create` (cloud image, checksum-verified, cloud-init, VLAN tag, balloon off), `ip`, `firewall`, `fw-status` |
| `scripts/runner-vm-setup.sh` | inside the VM, as root | phases `base`, `docker`, `netcheck`, `firewall`, `firewall-confirm`, `runners`, `prune`, `hygiene`, `verify` |
| `scripts/github-runner-api.sh` | workstation or host | GitHub REST helpers: check repos, mint registration tokens, smoke-test a runner, set the `RUNNER` variable, open the switch PR |
| `examples/runs-on-switch.yml` | your repos | the one-line change per workflow |
| `docs/LESSONS.md` | | what broke and why |
| `inputs.env.example` | workstation | every input, with placeholder values |

## Build order

1. **Network first, by hand.** Tag the VLAN on the switch ports to the hypervisor and the
   firewall. Add it to the bridge's `bridge-vids`. On the firewall: the VLAN interface with a
   static address and no DHCP, an alias with GitHub's git IPv4 ranges from `api.github.com/meta`,
   the rules above in first-hit order, an outbound NAT rule, and the two LAN rules.
2. **Preflight.** Copy `inputs.env.example` to `inputs.env`, fill it in, then run
   `bash scripts/preflight.sh`. Fix every FAIL. Do not build with a FAIL.
3. **Create the VM** on the host: `recon`, then `create`. It downloads and verifies the Ubuntu
   cloud image, builds the VM with the VLAN tag and a fixed memory size, and waits for the guest
   agent.
4. **Set up the VM** in phase order. `netcheck` must pass before `firewall`: it checks that the outer
   layer blocks the sampled LAN targets on its own, so the in-VM filter is a second layer, never the only one.
   Probe LAN hosts that are known to be up: an unreachable port on a dead host proves nothing.
   After `firewall`, open a new SSH session and run `firewall-confirm` within five minutes.
5. **Register runners** with one-hour registration tokens minted by the API helper. The PAT
   itself never leaves the workstation.
6. **Smoke-test** each repo with a throwaway workflow on an orphan branch, then set `RUNNER` and
   open the switch PR.
7. **Verify** with `runner-vm-setup.sh verify` whenever you touch anything. It exits non-zero on
   any FAIL.

## Security model, honestly

CI jobs run as an unprivileged `runner` user with no sudo. That user is in the `docker` group,
which is root-equivalent inside the VM, so the in-VM firewall stops accidents and lazy malware,
not a determined job. The real boundary is the VM plus the outer firewall on its own VLAN. The
runner serves private repositories only; a self-hosted runner on a public repository executes
code from any fork's pull request.

## Requirements

Proxmox VE 8 or 9 with a VLAN-aware bridge, a firewall you can read over SSH (`xmllint` on
pfSense), a workstation with `ssh`, `curl`, `jq`, `base64` and `shred` (Git Bash works), a
fine-grained PAT with Administration read/write and Actions read/write on the target repos, and
an Ubuntu 24.04 cloud image (fetched and checksum-verified by the create script).

## License

MIT.
