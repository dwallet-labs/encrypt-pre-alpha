default: check

# Build all crates
build:
    cargo build --workspace

# Build example programs (SBF binaries)
build-sbf:
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/voting/pinocchio/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/voting/native/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/voting/anchor/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/counter/pinocchio/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/counter/native/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/counter/anchor/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/acl/pinocchio/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/acl/native/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/acl/anchor/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/coin-flip/pinocchio/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/coin-flip/native/Cargo.toml
    cargo build-sbf --tools-version v1.54 --manifest-path chains/solana/examples/coin-flip/anchor/Cargo.toml

# Check all crates
check:
    cargo check --workspace

# Format
fmt:
    cargo fmt --all

# Format check
fmt-check:
    cargo fmt --all -- --check

# Clippy
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Lint (fmt + clippy)
lint: fmt-check clippy

# Unit tests (fast, no .so needed)
test-unit:
    cargo test --workspace --lib

# Example Mollusk tests (instruction-level, needs example .so)
test-examples-mollusk: build-sbf
    cargo test --test mollusk -p confidential-voting-pinocchio
    cargo test --test mollusk -p confidential-voting-native
    cargo test --test mollusk -p confidential-voting-anchor
    cargo test --test mollusk -p confidential-counter
    cargo test --test mollusk -p encrypted-coin-flip
    cargo test --test mollusk -p encrypted-acl

# Example LiteSVM tests (e2e, needs .so)
test-examples-litesvm: build-sbf
    cargo test --test litesvm -p confidential-voting-pinocchio
    cargo test --test litesvm -p confidential-voting-native
    cargo test --test litesvm -p confidential-voting-anchor
    cargo test --test litesvm -p confidential-counter
    cargo test --test litesvm -p encrypted-coin-flip
    cargo test --test litesvm -p encrypted-acl

# Example solana-program-test tests (e2e, needs .so)
test-examples-program-test: build-sbf
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --test program_test -p confidential-voting-pinocchio
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --test program_test -p confidential-voting-native
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --test program_test -p confidential-voting-anchor
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --test program_test -p confidential-counter
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --test program_test -p encrypted-coin-flip
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --test program_test -p encrypted-acl

# All example tests (unit + integration)
test-examples: build-sbf
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test -p confidential-voting-pinocchio
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test -p confidential-voting-native
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test -p confidential-voting-anchor
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test -p confidential-counter
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test -p encrypted-coin-flip
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test -p encrypted-acl

# All tests
test: build-sbf
    cp -n bin/encrypt_program.so target/deploy/encrypt_program.so 2>/dev/null || true
    BPF_OUT_DIR={{justfile_directory()}}/target/deploy cargo test --workspace

# Run all e2e voting demos (against devnet pre-alpha)
# Usage: just demo <ENCRYPT_PROGRAM_ID> <VOTING_PROGRAM_ID>
demo encrypt_id voting_id: (demo-web3 encrypt_id voting_id) (demo-kit encrypt_id voting_id) (demo-gill encrypt_id voting_id) (demo-rust encrypt_id voting_id)

# Run e2e voting demo (web3.js)
demo-web3 encrypt_id voting_id:
    bun chains/solana/examples/voting/e2e/e2e-voting-web3.ts {{encrypt_id}} {{voting_id}}

# Run e2e voting demo (@solana/kit)
demo-kit encrypt_id voting_id:
    bun chains/solana/examples/voting/e2e/e2e-voting-kit.ts {{encrypt_id}} {{voting_id}}

# Run e2e voting demo (gill)
demo-gill encrypt_id voting_id:
    bun chains/solana/examples/voting/e2e/e2e-voting-gill.ts {{encrypt_id}} {{voting_id}}

# Run e2e voting demo (Rust)
demo-rust encrypt_id voting_id:
    cargo run --manifest-path chains/solana/examples/voting/e2e/e2e-voting-rust/Cargo.toml -- {{encrypt_id}} {{voting_id}}

# Run e2e counter demo
demo-counter encrypt_id counter_id:
    bun chains/solana/examples/counter/e2e/main.ts {{encrypt_id}} {{counter_id}}

# Run e2e coin flip demo
demo-coin-flip encrypt_id coinflip_id:
    bun chains/solana/examples/coin-flip/e2e/main.ts {{encrypt_id}} {{coinflip_id}}

# Run e2e ACL demo
demo-acl encrypt_id acl_id:
    bun chains/solana/examples/acl/e2e/main.ts {{encrypt_id}} {{acl_id}}

# Generate Codama IDL + Rust/TypeScript clients
generate-clients:
    bun chains/solana/scripts/generate-clients.ts

# TypeScript lint
lint-ts:
    bunx eslint .

# TypeScript format
fmt-ts:
    bunx prettier --write .

# TypeScript format check
fmt-ts-check:
    bunx prettier --check .
