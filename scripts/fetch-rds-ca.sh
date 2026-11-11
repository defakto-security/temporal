#!/usr/bin/env bash
# Fetches the AWS RDS trust bundle into build/certs/ for the image.
#
# The server connects to RDS with sslmode=verify-full, which needs the RDS CA
# chain. ubuntu's ca-certificates does not carry it. AWS replaces this file in
# place when it rotates a CA, so a pinned hash would fail the build on every
# rotation; instead the download is checked for shape (real certificates, a
# plausible count) and the build fails if the check does not pass.
set -euo pipefail

URL="${RDS_CA_URL:-https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem}"
OUT_DIR="${1:-build/certs}"
OUT="${OUT_DIR}/rds-global-bundle.pem"
MIN_CERTS=20 # the global bundle holds well over 100

mkdir -p "${OUT_DIR}"
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
	--retry 3 --max-time 60 --output "${tmp}" "${URL}"

count="$(grep -c 'BEGIN CERTIFICATE' "${tmp}" || true)"
if [ "${count}" -lt "${MIN_CERTS}" ]; then
	echo "fetch-rds-ca: ${URL} has ${count} certificates, want at least ${MIN_CERTS}" >&2
	exit 1
fi
# Every block must parse as an X.509 certificate.
if ! openssl crl2pkcs7 -nocrl -certfile "${tmp}" >/dev/null 2>&1; then
	echo "fetch-rds-ca: ${URL} is not a valid PEM certificate bundle" >&2
	exit 1
fi

install -m 0644 "${tmp}" "${OUT}"
echo "fetch-rds-ca: wrote ${count} certificates to ${OUT}"
