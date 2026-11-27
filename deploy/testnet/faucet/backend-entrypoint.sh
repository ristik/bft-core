#!/bin/sh
set -eu
# Key and captcha secret are mounted files, never command arguments or image layers.
export HCAPTCHA_SECRET="$(cat /run/secrets/hcaptcha_secret)"
test -n "$HCAPTCHA_SECRET"
# The payout per claim, UCT (generate.py --faucet-payout): the guard's network.json names the same value and its health check refuses a signer that reports another.
: "${FAUCET_PAYOUT:?Set FAUCET_PAYOUT, the payout per claim in UCT (network.json payout)}"
case "$FAUCET_PAYOUT" in *[!0-9.]*|.*|*.|*.*.*) echo "FAUCET_PAYOUT must be a decimal number of UCT" >&2; exit 1;; esac
exec /app/eth-faucet -wallet.keyjson /run/secrets/faucet_keystore \
  -wallet.keypass /run/secrets/faucet_password \
  -faucet.name 'Unicity testnet — no real value' -faucet.symbol UCT \
  -faucet.amount "$FAUCET_PAYOUT" -faucet.minutes 1440 -proxycount 1
