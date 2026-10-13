#!/usr/bin/env bash
# =============================================================================
# github-runner-api.sh  —  GitHub REST helpers for the self-hosted runner build
#
# Runs on the Proxmox host. The PAT is read from $GITHUB_PAT_FILE and only ever
# handed to curl through a 0600 header file. It is never printed, logged, or
# sent to the runner VM. Only 1-hour runner registration tokens go to the VM.
#
#   whoami
#   check-repos OWNER/REPO...             private? admin? archived? exit 3 if any repo is unusable
#   registrations OUTFILE OWNER/REPO...   mint runner registration tokens into a 0600 file
#   runners OWNER/REPO                    list self-hosted runners: name status busy labels
#   wait-online OWNER/REPO PREFIX [SEC]   wait for an online runner whose name starts with PREFIX
#   get-var OWNER/REPO NAME               print an Actions variable (exit 4 if missing)
#   set-var OWNER/REPO NAME VALUE         create; never changes an existing different value unless FORCE=1
#   smoke-test OWNER/REPO [LABEL]         run a throwaway workflow on [self-hosted, LABEL] from an
#                                         orphan branch (so no other workflow triggers), then delete it
#   default-branch OWNER/REPO
#   workflow-files OWNER/REPO [REF]       list .github/workflows/*.yml|*.yaml paths
#   get-file OWNER/REPO PATH REF OUTFILE  download a file; prints its blob sha
#   create-branch OWNER/REPO BRANCH       new branch from the default branch head (ci/* names only)
#   put-file OWNER/REPO PATH BRANCH MESSAGE LOCALFILE [BLOB_SHA]
#   open-pr OWNER/REPO HEAD TITLE BODYFILE   PR into the default branch; prints its URL
#   delete-branch OWNER/REPO BRANCH       only branches this tooling creates (runner-smoke-test-*, ci/*)
#   resolve-sha OWNER/REPO REF            commit sha for a tag or branch (for pinning actions)
# =============================================================================
set -Eeuo pipefail
# Windows jq writes CRLF; that corrupts URLs, base64 and registration tokens. -b = binary (LF) output.
case "${OSTYPE:-}" in msys*|cygwin*) jq() { command jq -b "$@"; } ;; esac

PAT_FILE="${GITHUB_PAT_FILE:-/root/.gh-runner-pat}"
API="${GITHUB_API:-https://api.github.com}"
WORK=$(mktemp -d)
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
HDR="$WORK/auth"
CODE="$WORK/code"
BODY="$WORK/body"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
valid_repo()   { [[ "$1" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "bad repo name '$1' (want owner/repo)"; }
valid_branch() { [[ "$1" =~ ^[A-Za-z0-9._/-]+$ && "$1" != *..* ]] || die "bad branch name '$1'"; }

auth() {
  [[ -s "$HDR" ]] && return 0
  [[ -r "$PAT_FILE" ]] || die "PAT file $PAT_FILE not readable"
  local tok
  tok=$(tr -d '[:space:]' < "$PAT_FILE")
  [[ -n "$tok" ]] || die "PAT file $PAT_FILE is empty"
  ( umask 077; printf 'Authorization: Bearer %s\n' "$tok" > "$HDR" )
}

# api METHOD PATH [JSON_BODY] [ACCEPT]
# Prints the response body. Returns 0 on 2xx, 1 otherwise. HTTP status -> $(code).
api() {
  local m=$1 p=$2 body=${3-} accept=${4:-application/vnd.github+json} status
  auth
  local args=(-sS -X "$m" -H "@$HDR" -H "Accept: $accept" -H "User-Agent: gh-runner-setup"
              -o "$BODY" -w '%{http_code}')
  if [[ -n "$body" ]]; then
    status=$(curl "${args[@]}" -H 'Content-Type: application/json' --data-binary @- "$API$p" <<<"$body") \
      || die "network error on $m $p"
  else
    status=$(curl "${args[@]}" "$API$p") || die "network error on $m $p"
  fi
  printf '%s' "$status" > "$CODE"
  cat "$BODY"
  [[ "$status" == 2* ]]
}
code()    { cat "$CODE" 2>/dev/null || echo "?"; }
api_msg() { jq -r '.message? // empty' "$BODY" 2>/dev/null || true; }
fail_api() { die "$1: HTTP $(code) $(api_msg)"; }

default_branch() {
  local j
  j=$(api GET "/repos/$1") || fail_api "read repo $1"
  jq -r '.default_branch' <<<"$j"
}

# ---------------------------------------------------------------- commands
cmd_whoami() {
  local j
  j=$(api GET /user) || fail_api "GET /user (is the PAT valid?)"
  jq -r '.login' <<<"$j"
}

cmd_check_repos() {
  (( $# )) || die "usage: check-repos OWNER/REPO..."
  local bad=0 r info priv admin arch def wf
  printf 'repo\tprivate\tadmin\tarchived\tdefault_branch\tworkflows\n'
  for r in "$@"; do
    valid_repo "$r"
    if ! info=$(api GET "/repos/$r"); then
      printf '%s\tERROR HTTP %s %s\n' "$r" "$(code)" "$(api_msg)"; bad=1; continue
    fi
    priv=$(jq -r '.private' <<<"$info")
    admin=$(jq -r 'if .permissions then (.permissions.admin | tostring) else "unknown" end' <<<"$info")
    arch=$(jq -r '.archived' <<<"$info")
    def=$(jq -r '.default_branch' <<<"$info")
    wf=$(api GET "/repos/$r/actions/workflows?per_page=100" | jq -r '.total_count' 2>/dev/null || echo "?")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$r" "$priv" "$admin" "$arch" "$def" "$wf"
    [[ "$priv" == true && "$arch" == false && "$admin" != false ]] || bad=1
  done
  if (( bad )); then
    echo "one or more repos are public, archived, not admin-accessible or unreadable: do NOT register runners on them" >&2
    return 3
  fi
}

cmd_registrations() {
  (( $# >= 2 )) || die "usage: registrations OUTFILE OWNER/REPO..."
  local out=$1 r tok; shift
  ( umask 077; : > "$out" )
  for r in "$@"; do
    valid_repo "$r"
    tok=$(api POST "/repos/$r/actions/runners/registration-token" | jq -r '.token') \
      || fail_api "registration token for $r (the PAT needs Administration: write)"
    [[ -n "$tok" && "$tok" != null ]] || die "empty registration token for $r"
    printf '%s %s\n' "$r" "$tok" >> "$out"
  done
  log "wrote $(wc -l < "$out") registration(s) to $out (tokens expire after 1 hour)"
}

cmd_runners() {
  local j
  valid_repo "$1"
  j=$(api GET "/repos/$1/actions/runners?per_page=100") || fail_api "list runners for $1"
  jq -r '.runners[] | [.name, .status, (if .busy then "busy" else "idle" end), ([.labels[].name] | join(","))] | @tsv' <<<"$j"
}

cmd_wait_online() {
  local r=$1 prefix=$2 t=${3:-300} s=$SECONDS
  valid_repo "$r"
  while (( SECONDS - s < t )); do
    if api GET "/repos/$r/actions/runners?per_page=100" \
        | jq -e --arg p "$prefix" '[.runners[] | select((.name | startswith($p)) and .status == "online")] | length > 0' >/dev/null; then
      log "$r: runner $prefix* is online"
      return 0
    fi
    sleep 10
  done
  die "$r: no online runner named $prefix* after ${t}s"
}

cmd_get_var() {
  local v
  valid_repo "$1"
  if v=$(api GET "/repos/$1/actions/variables/$2"); then
    jq -r '.value' <<<"$v"
  elif [[ "$(code)" == 404 ]]; then
    return 4
  else
    fail_api "get variable $2 on $1"
  fi
}

cmd_set_var() {
  local r=$1 n=$2 val=$3 cur rc=0 payload
  valid_repo "$r"
  payload=$(jq -nc --arg n "$n" --arg v "$val" '{name: $n, value: $v}')
  cur=$(cmd_get_var "$r" "$n") || rc=$?
  if (( rc == 0 )); then
    if [[ "$cur" == "$val" ]]; then log "$r: $n is already '$val'"; return 0; fi
    [[ "${FORCE:-0}" == 1 ]] || die "$r: variable $n exists with a different value ('$cur'); not overwriting (FORCE=1 to override)"
    api PATCH "/repos/$r/actions/variables/$n" "$payload" >/dev/null || fail_api "update $n on $r"
  elif (( rc == 4 )); then
    api POST "/repos/$r/actions/variables" "$payload" >/dev/null || fail_api "create $n on $r (the PAT needs Variables: write)"
  else
    die "$r: could not read variable $n"
  fi
  log "$r: $n = $val"
}

cmd_delete_branch() {
  local r=$1 b=$2
  valid_repo "$r"; valid_branch "$b"
  [[ "$b" == runner-smoke-test-* || "$b" == ci/* ]] \
    || die "refusing to delete '$b': only runner-smoke-test-* and ci/* branches created by this tooling"
  api DELETE "/repos/$r/git/refs/heads/$b" >/dev/null || fail_api "delete branch $b on $r"
  log "$r: deleted branch $b"
}

cmd_smoke_test() {
  local r=$1 label=${2:-proxmox} ts branch wf blob tree commit runs run_id status concl jobs t0
  valid_repo "$r"
  [[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad label '$label'"
  ts=$(date -u +%Y%m%d%H%M%S)
  branch="runner-smoke-test-$ts"
  wf=$(cat <<EOF
# Temporary smoke test for the self-hosted runner (gh-runner-setup).
# Lives on an orphan branch that is deleted right after the run.
name: runner-smoke-test
on:
  push:
    branches: ['runner-smoke-test-*']
jobs:
  smoke:
    runs-on: [self-hosted, ${label}]
    timeout-minutes: 15
    steps:
      - name: Identify runner
        run: |
          echo "runner=\$RUNNER_NAME os=\$RUNNER_OS arch=\$RUNNER_ARCH"
          id
          uname -a
      - name: Docker works
        run: docker run --rm hello-world
      - name: Internet egress works
        run: curl -fsS -o /dev/null -w 'api.github.com -> %{http_code}\n' https://api.github.com
EOF
)
  # An orphan commit containing ONLY this workflow, so nothing else in the repo triggers.
  blob=$(api POST "/repos/$r/git/blobs" "$(jq -nc --arg c "$wf" '{content: $c, encoding: "utf-8"}')" | jq -r '.sha') \
    || fail_api "create blob on $r (the PAT needs Contents: write)"
  tree=$(api POST "/repos/$r/git/trees" \
    "$(jq -nc --arg s "$blob" '{tree: [{path: ".github/workflows/runner-smoke-test.yml", mode: "100644", type: "blob", sha: $s}]}')" \
    | jq -r '.sha') || fail_api "create tree on $r"
  commit=$(api POST "/repos/$r/git/commits" \
    "$(jq -nc --arg t "$tree" '{message: "runner smoke test (temporary orphan branch, deleted automatically)", tree: $t, parents: []}')" \
    | jq -r '.sha') || fail_api "create commit on $r"
  api POST "/repos/$r/git/refs" "$(jq -nc --arg ref "refs/heads/$branch" --arg sha "$commit" '{ref: $ref, sha: $sha}')" >/dev/null \
    || fail_api "create branch $branch on $r (the PAT needs Workflows: write)"
  log "$r: pushed orphan branch $branch; waiting for the run (up to 20 min)"

  t0=$SECONDS; run_id=""; status=""
  while (( SECONDS - t0 < 1200 )); do
    sleep "${SMOKE_POLL_SEC:-15}"
    runs=$(api GET "/repos/$r/actions/runs?branch=$branch&per_page=5") || continue
    run_id=$(jq -r '.workflow_runs[0].id // empty' <<<"$runs")
    [[ -n "$run_id" ]] || continue
    status=$(jq -r '.workflow_runs[0].status' <<<"$runs")
    [[ "$status" == completed ]] && break
  done

  local rc=1
  if [[ -z "$run_id" ]]; then
    log "$r: no workflow run appeared for $branch (are Actions enabled for this repo?)"
  else
    jobs=$(api GET "/repos/$r/actions/runs/$run_id/jobs") || fail_api "read jobs for run $run_id"
    concl=$(jq -r '.jobs[0].conclusion // "none"' <<<"$jobs")
    printf 'run:        %s\n' "$(jq -r '.jobs[0].html_url // empty' <<<"$jobs")"
    printf 'status:     %s\n' "$(jq -r '.jobs[0].status // empty' <<<"$jobs")"
    printf 'conclusion: %s\n' "$concl"
    printf 'runner:     %s\n' "$(jq -r '.jobs[0].runner_name // "none"' <<<"$jobs")"
    printf 'labels:     %s\n' "$(jq -r '(.jobs[0].labels // []) | join(",")' <<<"$jobs")"
    [[ "$concl" == success ]] && rc=0
    if [[ "$status" != completed ]]; then
      log "$r: run $run_id did not finish in 20 min; cancelling it"
      api POST "/repos/$r/actions/runs/$run_id/cancel" >/dev/null || true
    fi
  fi
  cmd_delete_branch "$r" "$branch" || log "WARN: could not delete $branch on $r"
  return "$rc"
}

cmd_workflow_files() {
  local r=$1 ref=${2:-} list
  valid_repo "$r"
  [[ -n "$ref" ]] || ref=$(default_branch "$r")
  if list=$(api GET "/repos/$r/contents/.github/workflows?ref=$ref"); then
    jq -r '.[] | select(.type == "file" and (.name | test("\\.ya?ml$"))) | .path' <<<"$list"
  elif [[ "$(code)" == 404 ]]; then
    return 0
  else
    fail_api "list workflows on $r@$ref"
  fi
}

cmd_get_file() {
  local r=$1 path=$2 ref=$3 out=$4 j
  valid_repo "$r"
  j=$(api GET "/repos/$r/contents/$path?ref=$ref") || fail_api "get $path from $r@$ref"
  jq -r '.content' <<<"$j" | base64 -d > "$out"
  jq -r '.sha' <<<"$j"
}

cmd_create_branch() {
  local r=$1 b=$2 def sha
  valid_repo "$r"; valid_branch "$b"
  [[ "$b" == ci/* ]] || die "create-branch only makes ci/* branches"
  def=$(default_branch "$r")
  sha=$(api GET "/repos/$r/git/ref/heads/$def" | jq -r '.object.sha') || fail_api "read $def head on $r"
  api POST "/repos/$r/git/refs" "$(jq -nc --arg ref "refs/heads/$b" --arg sha "$sha" '{ref: $ref, sha: $sha}')" >/dev/null \
    || fail_api "create branch $b on $r"
  log "$r: created $b from $def ($sha)"
}

cmd_put_file() {
  local r=$1 path=$2 b=$3 msg=$4 local_file=$5 blob=${6:-} payload def
  valid_repo "$r"; valid_branch "$b"
  [[ -f "$local_file" ]] || die "no such file: $local_file"
  def=$(default_branch "$r")
  [[ "$b" != "$def" ]] || die "refusing to commit to the default branch ($def)"
  payload=$(jq -nc --arg m "$msg" --arg c "$(base64 -w0 < "$local_file")" --arg b "$b" --arg s "$blob" \
    '{message: $m, content: $c, branch: $b} + (if $s == "" then {} else {sha: $s} end)')
  api PUT "/repos/$r/contents/$path" "$payload" >/dev/null || fail_api "commit $path to $b on $r"
  log "$r: committed $path to $b"
}

cmd_open_pr() {
  local r=$1 head=$2 title=$3 body_file=$4 def pr
  valid_repo "$r"; valid_branch "$head"
  def=$(default_branch "$r")
  pr=$(api POST "/repos/$r/pulls" \
    "$(jq -nc --arg t "$title" --arg h "$head" --arg b "$def" --rawfile body "$body_file" '{title: $t, head: $h, base: $b, body: $body}')") \
    || fail_api "open PR $head -> $def on $r"
  jq -r '.html_url' <<<"$pr"
}

cmd_resolve_sha() {
  local repo=$1 ref=$2 sha
  valid_repo "$repo"
  sha=$(api GET "/repos/$repo/commits/$ref" "" "application/vnd.github.sha") || fail_api "resolve $repo@$ref"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "unexpected sha for $repo@$ref: $sha"
  echo "$sha"
}

# --------------------------------------------------------------------- main
command -v jq >/dev/null || die "jq is required (apt-get install -y jq)"
command -v curl >/dev/null || die "curl is required"
cmd=${1:-}; shift || true
case "$cmd" in
  whoami)          cmd_whoami ;;
  check-repos)     cmd_check_repos "$@" ;;
  registrations)   cmd_registrations "$@" ;;
  runners)         cmd_runners "$@" ;;
  wait-online)     cmd_wait_online "$@" ;;
  get-var)         cmd_get_var "$@" ;;
  set-var)         cmd_set_var "$@" ;;
  smoke-test)      cmd_smoke_test "$@" ;;
  default-branch)  valid_repo "$1"; default_branch "$1" ;;
  workflow-files)  cmd_workflow_files "$@" ;;
  get-file)        cmd_get_file "$@" ;;
  create-branch)   cmd_create_branch "$@" ;;
  put-file)        cmd_put_file "$@" ;;
  open-pr)         cmd_open_pr "$@" ;;
  delete-branch)   cmd_delete_branch "$@" ;;
  resolve-sha)     cmd_resolve_sha "$@" ;;
  *) awk 'NR>1 && /^# shellcheck/{exit} NR>1 && /^#/{print; next} NR>1{exit}' "$0"; exit 2 ;;
esac
