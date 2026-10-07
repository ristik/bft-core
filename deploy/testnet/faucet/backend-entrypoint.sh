#!/bin/sh
set -eu
# Key and captcha secret are mounted files, never command arguments or image layers.
export HCAPTCHA_SECRET="$(cat /run/secrets/hcaptcha_secret)"
test -n "$HCAPTCHA_SECRET"
exec /app/eth-faucet -wallet.keyjson /run/secrets/faucet_keystore \
  -wallet.keypass /run/secrets/faucet_password \
  -faucet.name 'Unicity testnet — no real value' -faucet.symbol UCT \
  -faucet.amount 0.01 -faucet.minutes 1440 -proxycount 1
