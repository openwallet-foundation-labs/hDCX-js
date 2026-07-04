#!/usr/bin/env bash
# Fully headless PID issuance via the PRE-AUTHORIZED code grant.
#
# No authorization endpoint and no browser auth: Chrome drives the portal in pre-auth mode
# (fills the FormEU test form, authorizes) to obtain a pre-authorized offer + transaction
# code, then the Kotlin harness redeems them directly at the token endpoint.
#
#   cd tools/headless-interop && npm install && ./run-preauth.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$HERE/../../kotlin"
TMP="${TMPDIR:-/tmp}"
OFFER="$TMP/eudi-preauth-offer.txt"
TXCODE="$TMP/eudi-preauth-txcode.txt"

echo "== 1/3 portal (pre-auth mode) -> offer + tx_code (headless Chrome)"
node "$HERE/drive.js" preauth "$OFFER" "$TXCODE"
echo "tx_code: $(cat "$TXCODE")"

echo "== 2/3 redeem pre-authorized_code at token endpoint (Kotlin, no browser)"
( cd "$KOTLIN" && EUDI_LIVE=preauth EUDI_OFFER="$(cat "$OFFER")" EUDI_TXCODE="$(cat "$TXCODE")" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.preAuthIssue' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'pre-auth offer|credentials received|credential saved|PASSED|FAILED' )

echo "== 3/3 verify captured PID via x5c leaf key (Kotlin)"
( cd "$KOTLIN" && ./gradlew :openid4vci:test --tests '*VerifySavedPidTest*' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'VERIFIED REAL|vct:|given_name|family_name|birthdate|holder-bound|PASSED|FAILED' )

echo "== done. credential at $TMP/eudi-credential.txt"
