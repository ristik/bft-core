# Portable helpers of the lane scripts (Mac and a Linux CI runner). Definitions only: sourcing this file starts nothing and reads nothing.
# The caller sets REPO_ROOT. AGRE_ROOT is the lane's explicit root (builds/, briefs/devnet-runs, .devnet-lock live under it): the caller's value, else the parent of the checkout.

lane_agre_root() { echo "${AGRE_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}"; }

# The devnet-lock script: the workspace copy where there is one (the Mac's briefs/devnet-lock.sh, whose lock directory is the same convention), else the repository's.
lane_lock_script() {
  local root; root=$(lane_agre_root)
  if [ -x "$root/briefs/devnet-lock.sh" ]; then echo "$root/briefs/devnet-lock.sh"; else echo "$REPO_ROOT/scripts/ci/devnet-lock.sh"; fi
}

# sha256 of a file / of stdin (GNU sha256sum, else BSD/perl shasum)
p_sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
# size in bytes (GNU stat -c, else BSD stat -f)
p_size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }
# epoch seconds of a UTC time stamp YYYY-MM-DDTHH:MM:SSZ (GNU date -d, else BSD date -j)
p_epoch() { date -u -d "$1" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ "$1" +%s; }
# timeout SECONDS COMMAND...: GNU timeout, Homebrew gtimeout, else the command unbounded (the caller's own deadline then applies)
p_timeout() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$@"; else shift; "$@"; fi; }

# The file a run's host evidence goes to: the Mac keeps pmset-<when>.log.gz, a runner writes host-<when>.log.gz
host_evidence_file() { if [ "$(uname -s)" = Darwin ]; then echo "$1/pmset-$2.log.gz"; else echo "$1/host-$2.log.gz"; fi; }

# Host evidence of a run, replacing the Mac power logs: host_evidence before|after FILE.gz. A Mac keeps its pmset log (the run must not sleep); a Linux runner
# records its own metadata, UTC and monotonic times, cgroup memory counters and the kernel's OOM lines where readable. Missing power logs are NOT evidence of anything on a runner.
host_evidence() {
  local when=$1 file=$2
  {
    echo "host-evidence $when"
    date -u +%FT%TZ
    if [ "$(uname -s)" = Darwin ]; then
      pmset -g log 2>/dev/null
    else
      echo "monotonic uptime s: $(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
      uname -a; { . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"; } || true
      echo "runner: os=${RUNNER_OS:-?} arch=${RUNNER_ARCH:-?} image=${ImageVersion:-?} name=${RUNNER_NAME:-?}"
      echo "github: repository=${GITHUB_REPOSITORY:-?} run=${GITHUB_RUN_ID:-?}.${GITHUB_RUN_ATTEMPT:-?} sha=${GITHUB_SHA:-?} workflow=${GITHUB_WORKFLOW:-?}"
      echo "cpus: $(nproc 2>/dev/null)"; free -m 2>/dev/null; df -h 2>/dev/null
      for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events; do [ -r "$f" ] && { echo "$f:"; cat "$f"; }; done
      echo "kernel OOM lines (dmesg, if readable):"; { dmesg 2>/dev/null || sudo -n dmesg 2>/dev/null; } | grep -i -E 'out of memory|oom-kill|killed process' | tail -n 20
    fi
  } 2>&1 | gzip >"$file" || true
}

# A Go tool of scripts/<name>: the prebuilt binary in $LANE_TOOLS_DIR when there is one (a CI run job carries binaries only), else `go run ./scripts/<name>`.
lane_go_run() { local t=$1; shift; if [ -n "${LANE_TOOLS_DIR:-}" ] && [ -x "$LANE_TOOLS_DIR/$t" ]; then "$LANE_TOOLS_DIR/$t" "$@"; else go run "./scripts/$t" "$@"; fi; }
# `go version -m BIN...` (module and VCS information embedded in a Go binary): the prebuilt buildinfo tool when $LANE_TOOLS_DIR has it, else the go command.
lane_buildinfo() { if [ -n "${LANE_TOOLS_DIR:-}" ] && [ -x "$LANE_TOOLS_DIR/buildinfo" ]; then "$LANE_TOOLS_DIR/buildinfo" "$@"; else go version -m "$@"; fi; }

# A command that must not reach the network (the offline F7 verification). lane_net_deny_mechanism prints how it is done here, or nothing when no real mechanism
# exists (the caller then keeps its stripped-proxy-environment fallback and says so); lane_net_deny_run CMD... runs CMD with the network denied: macOS sandbox-exec,
# or on Linux a fresh network namespace (sudo -n unshare -n, back to the calling user: an unprivileged user namespace is restricted on the runner image).
lane_net_deny_mechanism() {
  if command -v sandbox-exec >/dev/null 2>&1; then echo "macOS sandbox-exec"
  elif [ "$(uname -s)" = Linux ] && command -v unshare >/dev/null 2>&1 && sudo -n true 2>/dev/null && sudo -n unshare -n true 2>/dev/null; then echo "Linux network namespace"
  fi
}
lane_net_deny_run() {
  case "$(lane_net_deny_mechanism)" in
    "macOS sandbox-exec") env -i PATH="$PATH" sandbox-exec -p '(version 1) (allow default) (deny network*)' "$@" ;;
    "Linux network namespace") sudo -n unshare -n -- sudo -n -u "$(id -un)" env -i PATH="$PATH" "$@" ;;
    *) return 125 ;;
  esac
}
