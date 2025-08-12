#!/usr/bin/env bash
set -euo pipefail

# Colors for CI logs
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # reset

export RUSTFLAGS="${RUSTFLAGS:-} --cfg substrate_runtime"

# First arg is the cargo command (e.g., check, build)
COMMAND="$1"
shift || true  # Remove it so $@ is now only the additional args

status=0

while IFS= read -r CARGO_TOML; do
    DIR=$(dirname "$CARGO_TOML")
    echo -e "${YELLOW}==> Checking in directory:${NC} $DIR"

    # Skip if no `std` feature
    if ! grep -q "\[features\]" "$CARGO_TOML" || ! grep -q "std = \[" "$CARGO_TOML"; then
        echo -e "${YELLOW}    Skipping:${NC} no 'std' feature found."
        continue
    fi

    # Determine if runtime-benchmarks feature should be added
    if grep -q "\[features\]" "$CARGO_TOML" && grep -q "runtime-benchmarks = \[" "$CARGO_TOML"; then
        echo -e "${GREEN}    Found:${NC} runtime-benchmarks feature. Running with it..."
        if ! cargo "$COMMAND" "$@" \
            --features runtime-benchmarks \
            --manifest-path "$CARGO_TOML"; then
            echo -e "${RED}    FAILED:${NC} $DIR"
            status=1
        else
            echo -e "${GREEN}    OK:${NC} $DIR"
        fi
    else
        echo -e "${YELLOW}    No runtime-benchmarks feature. Running without it...${NC}"
        if ! cargo "$COMMAND" "$@" \
            --manifest-path "$CARGO_TOML"; then
            echo -e "${RED}    FAILED:${NC} $DIR"
            status=1
        else
            echo -e "${GREEN}    OK:${NC} $DIR"
        fi
    fi
done < <(find . -name "Cargo.toml")

if [ "$status" -ne 0 ]; then
    echo -e "${RED}One or more crates failed.${NC}"
    exit 1
else
    echo -e "${GREEN}All crates passed.${NC}"
fi
