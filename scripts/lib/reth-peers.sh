# Execution-client peering of the lanes' ureth validators (definitions only; needs helper.sh's rpc and pyget, and rethEthBase).
#
# ureth carries transaction-only gossip among the validators (ristik/ureth#34): the network is built with trusted_nodes_only, so a validator's execution client connects only to
# peers it was told to TRUST, in both directions (admin_addPeer adds a static peer and is not enough). Trusting follows the validator set: a member that joins is trusted by
# the others and trusts them; a member that retires is removed from the others. An older ureth (no gossip) has the same admin methods and ignores them, so these calls are safe
# on either build.
#
#   reth_enode I                  the enode of execution client I (cached under test-nodes/reth-enodes so it is still known after I stops)
#   reth_trust I J                client I trusts J (I will connect to J and accept J)
#   reth_trust_mesh "I J K..."    every listed client trusts every other listed client
#   reth_untrust I J              client I stops trusting J and drops the session (a retired member)

reth_enode() {
  local i=$1 f="test-nodes/reth-enodes/$1" e
  mkdir -p test-nodes/reth-enodes
  if e=$(rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_nodeInfo '[]' 2>/dev/null | pyget "['result']['enode']") && [ -n "$e" ] && [ "$e" != None ]; then
    printf '%s\n' "$e" >"$f"
  fi
  [ -s "$f" ] && cat "$f"
}

reth_trust() { # I J
  local i=$1 j=$2 e
  e=$(reth_enode "$j") || return 1
  [ -n "$e" ] || { echo "reth_trust: no enode for execution client $j" >&2; return 1; }
  rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_addTrustedPeer "[\"$e\"]" >/dev/null
}

reth_trust_mesh() { # "I J K..."
  local i j
  for i in $1; do for j in $1; do [ "$i" = "$j" ] || reth_trust "$i" "$j" || return 1; done; done
}

reth_untrust() { # I J
  local i=$1 j=$2 e
  e=$(cat "test-nodes/reth-enodes/$j" 2>/dev/null) || return 0
  [ -n "$e" ] || return 0
  rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_removeTrustedPeer "[\"$e\"]" >/dev/null 2>&1 || true
  rpc "http://127.0.0.1:$((rethEthBase + i - 1))" admin_removePeer "[\"$e\"]" >/dev/null 2>&1 || true
}
