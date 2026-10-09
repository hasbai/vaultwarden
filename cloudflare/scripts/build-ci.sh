#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Workers Builds does not include Rust in its documented build image.
# Do not initialize runtime secrets, Auth0 or production D1 from this build.
if ! command -v rustup >/dev/null 2>&1; then
    installer="$(mktemp)"
    curl --fail --location --retry 3 https://sh.rustup.rs --output "$installer"
    sh "$installer" -y --profile minimal --default-toolchain none
    rm "$installer"
fi
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.95.0
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --component rustfmt --component clippy --target wasm32-unknown-unknown
cargo install worker-build --version 0.8.7 --locked
npm run web-vault
npm run check
node tests/crypto.mjs
node tests/auth0.mjs
node tests/sso-entry.mjs
npm run build
