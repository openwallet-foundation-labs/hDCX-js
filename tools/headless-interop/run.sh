#!/usr/bin/env bash
# Fully headless live PID issuance from issuer.eudiw.dev.
#
# Orchestrates: Chrome-driven portal (offer) -> Kotlin PAR (step1) -> Chrome-driven
# FormEU auth (code) -> Kotlin token+credential exchange (step2) -> x5c verification.
# No human browser interaction.
#
#   cd tools/headless-interop && npm install && ./run.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$HERE/../../kotlin"
TMP="${TMPDIR:-/tmp}"
OFFER="$TMP/eudi-offer.txt"
AUTHURL="$TMP/eudi-authurl.txt"

echo "== 1/5 portal -> credential offer (headless Chrome)"
node "$HERE/drive.js" offer "$OFFER"

echo "== 2/5 PAR -> authorization URL (Kotlin)"
rm -f "$TMP/eudi-redirect.txt"
( cd "$KOTLIN" && EUDI_LIVE=prepare EUDI_OFFER="$(cat "$OFFER")" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.step1_prepare' --console=plain --rerun-tasks 2>&1 \
    | grep -oE 'https://issuer.eudiw.dev/oidc/authorization[^ ]*' | head -1 ) > "$AUTHURL"
echo "authorization URL: $(cat "$AUTHURL")"

echo "== 3/5 FormEU auth -> authorization code (headless Chrome)"
node "$HERE/drive.js" auth "$AUTHURL" "$TMP/eudi-redirect.txt"

echo "== 4/5 token + credential exchange (Kotlin)"
( cd "$KOTLIN" && EUDI_LIVE=finish \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.step2_finish' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'credentials received|credential saved|PASSED|FAILED' )

echo "== 5/5 verify captured PID via x5c leaf key (Kotlin)"
( cd "$KOTLIN" && EUDI_LIVE=x ./gradlew :trust:test --tests '*LiveTrustE2eTest.verifyRealPidWithChain' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'REAL PID VERIFIED|vct:|given_name|family_name|birthdate|holder-bound|PASSED|FAILED' )

echo "== done. credential at $TMP/eudi-credential.txt"
