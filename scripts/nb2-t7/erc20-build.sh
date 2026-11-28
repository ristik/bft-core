#!/usr/bin/env bash
# Sourced by run.sh to build before claiming the slot.
: "${NB2_ERC20_CONTRACTS:?path to contracts #107 merge checkout}"
: "${NB2_ERC20_PLUGIN:?path to pinned plug-ins checkout}"
: "${NB2_ERC20_ORACLE_SOURCE:?path to the bft-core #1338 checkout}"
: "${NB2_ERC20_ORACLE_REV:?pinned bft-core #1338 revision}"
export NB2_ERC20_CONTRACTS_REV=de62921f10be506f3cd7a559ae8541bcb644d0f4
export NB2_ERC20_PLUGIN_REV="${NB2_ERC20_PLUGIN_REV:-43c4535deccee68f45a2400848ec9b28dbec9999}"
test "$(git -C "$NB2_ERC20_CONTRACTS" rev-parse HEAD)" = "$NB2_ERC20_CONTRACTS_REV"
test "$(git -C "$NB2_ERC20_PLUGIN" rev-parse HEAD)" = "$NB2_ERC20_PLUGIN_REV"
test "$(git -C "$NB2_ERC20_ORACLE_SOURCE" rev-parse HEAD)" = "$NB2_ERC20_ORACLE_REV"
test -f "$NB2_ERC20_ORACLE_SOURCE/nb2ref/erc20_vectors_test.go"
for checkout in "$NB2_ERC20_CONTRACTS" "$NB2_ERC20_PLUGIN" "$NB2_ERC20_ORACLE_SOURCE"; do
  test -z "$(git -C "$checkout" status --porcelain --untracked-files=no)"
done

# Export the pinned gitlinks too. The source checkouts only supply Git objects.
export_contracts() {
  local checkout=$1 revision=$2 destination=$3
  local entry metadata path mode type object tree
  mkdir -p "$destination"
  git -C "$checkout" archive "$revision" | tar -x -C "$destination"
  tree=$(git -C "$checkout" ls-tree -r "$revision")
  while IFS=$'\t' read -r metadata path; do
    read -r mode type object <<<"$metadata"
    if [[ "$mode" = 160000 ]]; then
      export_contracts "$checkout/$path" "$object" "$destination/$path"
    fi
  done <<<"$tree"
}
contracts_build="$plugin_build/erc20-contracts"
export_contracts "$NB2_ERC20_CONTRACTS" "$NB2_ERC20_CONTRACTS_REV" "$contracts_build"
(
  cd "$contracts_build"
  forge build --offline -j 4 src/nb2/erc20
)
export NB2_ERC20_ARTIFACTS="$contracts_build/out"
bash scripts/nb2-t7/build-plugin.sh "$NB2_ERC20_PLUGIN" "$NB2_ERC20_PLUGIN_REV" "$plugin_build/erc20-plugin"
export NB2_ERC20_PLUGIN="$plugin_build/erc20-plugin"
