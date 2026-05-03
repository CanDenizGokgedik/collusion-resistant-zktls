#!/usr/bin/env bash
# quicktest.sh — Clone-and-run smoke test for collusion-resistant-zktls.
#
# Usage (from repo root):
#   chmod +x quicktest.sh && ./quicktest.sh
#
# Optional flags:
#   --mode2        Run the full TLS-PRF co-SNARK circuit (~64s setup + ~23s prove)
#   --contracts    Run Solidity tests with Foundry (requires forge)
#   --skip-build   Skip rebuilding if workspace already built

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[..]${NC}  $*"; }
fail() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

# ── Repo ──────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/CanDenizGokgedik/collusion-resistant-zktls-cosnark"
REPO_DIR="collusion-resistant-zktls-cosnark"

# ── Auto-clone if not inside the repo ────────────────────────────────────────
if [ ! -f "Cargo.toml" ] || ! grep -q "tls-attestation" Cargo.toml 2>/dev/null; then
  info "Not inside repo root — attempting to clone..."
  command -v git &>/dev/null || fail "git not found. Install git first."
  if [ -d "$REPO_DIR" ]; then
    info "Directory '$REPO_DIR' already exists — skipping clone."
  else
    git clone "$REPO_URL" "$REPO_DIR" \
      || fail "Clone failed. Check your internet connection or run:
  git clone $REPO_URL"
    ok "Cloned into $REPO_DIR"
  fi
  cd "$REPO_DIR"
  ok "Changed into $(pwd)"
fi

# ── Flags ─────────────────────────────────────────────────────────────────────
RUN_MODE2=0
RUN_CONTRACTS=0
SKIP_BUILD=0
for arg in "$@"; do
  case $arg in
    --mode2)       RUN_MODE2=1 ;;
    --contracts)   RUN_CONTRACTS=1 ;;
    --skip-build)  SKIP_BUILD=1 ;;
  esac
done

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     collusion-resistant-zktls — quick smoke test                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Rust toolchain ─────────────────────────────────────────────────────────
info "Checking Rust toolchain..."
command -v rustup &>/dev/null || fail "rustup not found. Install from https://rustup.rs"
command -v cargo  &>/dev/null || fail "cargo not found. Run: rustup update stable"

RUST_VER=$(rustc --version 2>/dev/null || echo "unknown")
RUST_MINOR=$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f2 || echo "0")
if [ "${RUST_MINOR}" -lt 75 ] 2>/dev/null; then
  fail "Rust 1.75+ required (found $RUST_VER). Run: rustup update stable"
fi
ok "Rust: $RUST_VER"

# ── 2. Build workspace ────────────────────────────────────────────────────────
FEATURES="frost,secp256k1"

if [ "$SKIP_BUILD" = "1" ]; then
  ok "Build skipped (--skip-build)"
else
  info "Building workspace (features: $FEATURES) — may take 3–5 min on first run..."
  cargo build --workspace --features "$FEATURES" --release \
    || fail "Workspace build failed. Run 'cargo build --workspace --features $FEATURES --release' for details."
  ok "Workspace built"
fi

# ── 3. Unit + integration tests ───────────────────────────────────────────────
info "Running unit & integration tests..."
cargo test --workspace --features "$FEATURES" --release --quiet \
  || fail "Tests failed. Run 'cargo test --workspace --features $FEATURES' for details."
ok "All tests passed"

# ── 4. Smoke: DVRF + TSS benchmark (LAN, ~2s) ────────────────────────────────
echo ""
echo "─── Benchmark: DVRF + FROST TSS (Fig. 9) ──────────────────────────────"
info "Measures RC Phase + Signing Phase across t-of-n configs (~2s total)"
echo ""

cargo run --package tls-attestation-bench --bin bench_dvrf_tss --release \
  || fail "bench_dvrf_tss failed."
ok "bench_dvrf_tss complete"

# ── 5. Smoke: Full pipeline — stub co-SNARK (Table II, ~5s) ──────────────────
echo ""
echo "─── Benchmark: Full pipeline — stub co-SNARK (Table II) ───────────────"
info "RC → dx-DCTLS (stub) → FROST Sign → on-chain ABI — demonstrates O(1) prover"
echo ""

cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
  || fail "bench_full_pipeline failed."
ok "bench_full_pipeline complete"

# ── 6. Smoke: co-SNARK Mode 1 + dx-DCTLS overhead (§IX, ~30s) ────────────────
echo ""
echo "─── Benchmark: co-SNARK + dx-DCTLS overhead (§IX) ─────────────────────"
info "R1CS constraint counts, CRS setup, Mode 1 prove/verify timing"
info "Expected: Mode 1 ~16ms prove, ~1ms verify, CRS setup ~60ms"
echo ""

cargo run --package tls-attestation-bench --bin bench_dctls --release \
  || fail "bench_dctls failed."
ok "bench_dctls complete"

# ── 7. Full pipeline — real co-SNARK Mode 1 (~30s) ───────────────────────────
echo ""
echo "─── Benchmark: Full pipeline — real co-SNARK Mode 1 (~769 R1CS) ───────"
info "RC → dx-DCTLS (Groth16 Mode 1) → FROST Sign → on-chain ABI"
info "Expected: CRS setup ~60ms, Attest ~16ms constant across all configs"
echo ""

cargo run --package tls-attestation-bench --bin bench_full_cosnark --release \
  || fail "bench_full_cosnark failed."
ok "bench_full_cosnark complete"

# ── 8. Full pipeline — real co-SNARK Mode 2 (optional, ~30min) ───────────────
if [ "$RUN_MODE2" = "1" ]; then
  echo ""
  echo "─── Benchmark: Full pipeline — real co-SNARK Mode 2 (~1.9M R1CS) ──────"
  info "CRS setup ~64s (one-time). Prove ~23s per config. Verify ~1ms."
  info "Paper reports 4,700ms (gnark/BLS12-381 on M3); expect ~23,000ms (arkworks/BN254 on M1)"
  echo ""

  cargo run --package tls-attestation-bench --bin bench_full_cosnark_mode2 --release \
    || fail "bench_full_cosnark_mode2 failed."
  ok "bench_full_cosnark_mode2 complete"
else
  echo ""
  info "Mode 2 full pipeline skipped (~30min total). Enable with: ./quicktest.sh --mode2"
fi

# ── 9. Solidity tests (optional, requires forge) ──────────────────────────────
if [ "$RUN_CONTRACTS" = "1" ]; then
  echo ""
  echo "─── Solidity tests (FrostVerifier + DctlsVerifier) ─────────────────────"
  if ! command -v forge &>/dev/null; then
    fail "forge not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
  fi
  (cd contracts && forge test -v) \
    || fail "Solidity tests failed. Run 'cd contracts && forge test -v' for details."
  ok "Solidity tests passed (17 tests)"
else
  echo ""
  info "Solidity tests skipped. Enable with: ./quicktest.sh --contracts (requires forge)"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  All checks passed.                                              ║"
echo "║                                                                  ║"
echo "║  Useful flags:                                                   ║"
echo "║    --mode2        Full Mode 2 co-SNARK pipeline  (~30 min)      ║"
echo "║    --contracts    Solidity tests via forge                       ║"
echo "║    --skip-build   Skip rebuild, run tests only                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""