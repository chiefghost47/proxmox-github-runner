# Lessons from running this

Each of these has cost someone real time. They are here so they cost you none.

## Exhausted hosted minutes look exactly like a broken runner

When a personal account's free GitHub-hosted minutes run out, every job that asks for
`ubuntu-latest` or `windows-latest` fails in two seconds with no steps and this annotation:

> The job was not started because recent account payments have failed or your spending limit
> needs to be increased.

GitHub uses the same text for a failed payment and for a spending limit of zero. Jobs on the
self-hosted runner keep passing. Check the job's runner label and the annotation before you
touch the runner.

## A job-level `container:` runs as root on your runner's workspace

The runner bind-mounts its `_work/<repo>/<repo>` directory into the job container. A job that
uses `container: ubuntu:24.04` writes there as root. The next job, running as the `runner` user,
cannot delete those files and fails at checkout with "not a git repository". Two fixes:

- end the container job with an `if: always()` step that hands ownership back,
  `chown -R "$(stat -c '%u:%g' /__w)" "$GITHUB_WORKSPACE" "$RUNNER_TEMP"`, and set
  `defaults.run.shell: bash`, because the default shell inside a job container is `sh`;
- or keep the job as a normal runner job and run only the root-needing part through
  `docker run --rm -v "$PWD:/src:ro" ...`, so root never touches the workspace.

Recovery when it has already happened: remove the workspace directory on the runner as root.
It is scratch; checkout recreates it.

## A push run uses the workflow files of the pushed branch

Pull-request runs use the merged workflow, so a PR opened before the `runs-on` switch landed
still runs on the runner. The same branch's push runs do not: they read the branch's own old
workflow files. Merge the default branch into long-lived branches after changing CI.

## The job hook must end in `.sh`

`ACTIONS_RUNNER_HOOK_JOB_STARTED` silently ignores a script whose name has no `.sh` suffix.

## Self-hosted runners need the tool cache

`actions/setup-python` and similar actions expect `RUNNER_TOOL_CACHE=/opt/hostedtoolcache`,
owned by the runner user, or they fail to install toolchains the way they do on hosted runners.

## Persistent runners leak state between jobs

Without a private `/tmp` per runner service and a hook that empties it at job start, one job's
leftovers are visible to the next. `PrivateTmp=yes` in the systemd unit plus the hook fixes it.

## Prove the outer layer before adding the inner one

Run the in-VM `netcheck` phase before the in-VM `firewall` phase. If the LAN is reachable from
the VM with only the outer firewall in place, the outer firewall is wrong, and an in-VM filter
would only hide that.

## A dead-man switch for the in-VM firewall

Apply the rules with a timer that flushes them after five minutes unless a fresh SSH login
confirms. An ingress rule that locks out the admin host then costs five minutes, not a console
session.

## Read the firewall's config, don't trust the GUI

The preflight parses the firewall's XML config over SSH and checks the rule order itself. A
pass rule placed above the private-range block, which is easy to do in a GUI, is a FAIL before
the VM exists rather than a surprise after it.

## Windows CRLF breaks remote scripts

Scripts written on Windows and piped to a Linux host arrive with carriage returns. `jq` on
Windows adds them to its output too, which corrupts URLs, base64 and registration tokens. The
API helper forces `jq -b`; check every script with `cat -A` before it leaves the workstation.
