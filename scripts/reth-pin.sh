#!/bin/bash
# reth-pin.sh - command-line front for scripts/lib/reth-pin.sh, for workflow steps and local use.
#
#   ./scripts/reth-pin.sh platform
#   ./scripts/reth-pin.sh obtain --cache-dir DIR --dest DIR [--platform P]
#       fetch (or take from cache) the pinned upstream release artifact, verify its sha256 on every
#       use, extract it, and verify the binary reports the pinned commit. Prints the binary's path.
#   ./scripts/reth-pin.sh verify PATH
#       verify an operator-supplied binary (e.g. one built from the pinned commit) by its revision.
#   ./scripts/reth-pin.sh validate-archive ARCHIVE [--nodes DIR] [--min-node-logs N] [--require NAME]...
#       check an evidence archive: required files present, node logs present, no secret inside.
#       Exit 0 validated, 1 incomplete but secret-free, 2 not publishable (secret or unreadable).
#   ./scripts/reth-pin.sh select-upload --out DIR --quarantine DIR [--nodes DIR] [--min-node-logs N]
#                                       [--require NAME]... ARCHIVE...
#       validate each archive and put only the publishable ones into --out, the one directory a
#       workflow uploads; a rejected archive is moved to --quarantine and only a diagnostic about it
#       is published. --out/MANIFEST.txt records every verdict.
#
# Every refusal exits nonzero with a "reth-pin:" or "reth-evidence:" line saying why. There is no
# fallback: nothing here ever substitutes an unverified binary.

set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/reth-pin.sh"

usage() { sed -n '2,21p' "$0"; exit 2; }

cmd=${1:-}; [ -n "$cmd" ] || usage; shift
case "$cmd" in
  platform) rethPinPlatform ;;
  verify)
    [ $# -eq 1 ] || usage
    rethPinVerifyBinary "$1" ;;
  obtain)
    cacheDir= dest= platform=
    while [ $# -gt 0 ]; do
      case "$1" in
        --cache-dir) cacheDir=$2; shift 2 ;;
        --dest) dest=$2; shift 2 ;;
        --platform) platform=$2; shift 2 ;;
        *) usage ;;
      esac
    done
    [ -n "$cacheDir" ] && [ -n "$dest" ] || usage
    rethPinObtainPinned "$cacheDir" "$dest" "$platform" || exit 1
    echo "reth-pin: $dest/reth ready (cache $RETH_PIN_CACHE_STATE, $RETH_PIN_ASSET, sha256 $RETH_PIN_SHA256)" ;;
  validate-archive)
    archive=${1:-}; [ -n "$archive" ] || usage; shift
    nodes= minLogs=0 required=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --nodes) nodes=$2; shift 2 ;;
        --min-node-logs) minLogs=$2; shift 2 ;;
        --require) required+=("$2"); shift 2 ;;
        *) usage ;;
      esac
    done
    rethEvidenceValidate "$archive" "$nodes" "$minLogs" ${required[@]+"${required[@]}"} ;;
  select-upload)
    out= quar= nodes= minLogs=0 required=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --out) out=$2; shift 2 ;;
        --quarantine) quar=$2; shift 2 ;;
        --nodes) nodes=$2; shift 2 ;;
        --min-node-logs) minLogs=$2; shift 2 ;;
        --require) required+=("$2"); shift 2 ;;
        --) shift; break ;;
        -*) usage ;;
        *) break ;;
      esac
    done
    [ -n "$out" ] && [ -n "$quar" ] || usage
    rethEvidenceSelect "$out" "$quar" "$nodes" "$minLogs" "${required[*]:-}" "$@" ;;
  *) usage ;;
esac
