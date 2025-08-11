export RUSTFLAGS="$RUSTFLAGS --cfg substrate_runtime"

find . -name "Cargo.toml" | while read -r CARGO_TOML; do
  DIR=$(dirname "$CARGO_TOML")
  echo "Checking in directory: $DIR"

  # Skip the loop if the crate does not have a feature `std`
  if ! grep -q "\[features\]" "$CARGO_TOML" || ! grep -q "std = \[" "$CARGO_TOML"; then
      echo "Feature 'std' not found in $CARGO_TOML. Skipping."
      continue
  fi

    if grep -q "runtime-benchmarks = \[" "$CARGO_TOML"; then
        if grep -q "ksm = \[" "$CARGO_TOML"; then
            echo "Features 'runtime-benchmarks' and 'ksm' found, adding both features."
            cargo $COMMAND $@ --features "runtime-benchmarks ksm" --manifest-path "$CARGO_TOML"
        else
            echo "Feature 'runtime-benchmarks' found, adding this feature."
            cargo $COMMAND $@ --features runtime-benchmarks --manifest-path "$CARGO_TOML"
        fi
    else
        if grep -q "ksm = \[" "$CARGO_TOML"; then
            echo "Feature 'ksm' found, adding this feature."
            cargo $COMMAND $@ --features ksm --manifest-path "$CARGO_TOML"
        else
            echo "No relevant features found, running command without additional features."
            cargo $COMMAND $@ --manifest-path "$CARGO_TOML"
        fi
    fi
done
