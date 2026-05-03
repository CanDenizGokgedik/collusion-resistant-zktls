#!/usr/bin/env bash
# quicktest.sh — Clone-and-run smoke test for collusion-resistant-zktls.
#
# Usage (from repo root):
#   chmod +x quicktest.sh && ./quicktest.sh
#
# Flags:
#   --no-mode2     Skip the full TLS-PRF Mode 2 benchmark (~30 min)
#   --contracts    Run Solidity tests with Foundry (requires forge)
#   --skip-build   Skip rebuilding if workspace already built

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo -e "${YELLOW}[..]${NC}  $*"; }
fail() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }
time_msg() { echo -e "${CYAN}[⏱ ]${NC}  $*"; }

# ── Timing helper ─────────────────────────────────────────────────────────────
# Usage: timed "label" command args...
timed() {
  local label="$1"; shift
  local t0
  t0=$(date +%s)
  "$@"
  local status=$?
  local t1
  t1=$(date +%s)
  local elapsed=$(( t1 - t0 ))
  time_msg "$label finished in ${elapsed}s"
  return $status
}

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
RUN_MODE2=1       # Mode 2 runs by default; use --no-mode2 to skip
RUN_CONTRACTS=0
SKIP_BUILD=0
for arg in "$@"; do
  case $arg in
    --no-mode2)    RUN_MODE2=0 ;;
    --contracts)   RUN_CONTRACTS=1 ;;
    --skip-build)  SKIP_BUILD=1 ;;
  esac
done

SCRIPT_START=$(date +%s)

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     collusion-resistant-zktls — full smoke test                 ║"
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
  timed "cargo build" cargo build --workspace --features "$FEATURES" --release \
    || fail "Workspace build failed."
  ok "Workspace built"
fi

# ── 3. Unit + integration tests ───────────────────────────────────────────────
info "Running unit & integration tests..."
timed "cargo test" cargo test --workspace --features "$FEATURES" --release --quiet \
  || fail "Tests failed. Run 'cargo test --workspace --features $FEATURES' for details."
ok "All tests passed"

# ── 4. DVRF + TSS benchmark — Fig. 9 (~2s) ───────────────────────────────────
echo ""
echo "─── Benchmark: DVRF + FROST TSS (Fig. 9) ──────────────────────────────"
info "RC Phase + Signing Phase across t-of-n configs"
echo ""
timed "bench_dvrf_tss" cargo run --package tls-attestation-bench --bin bench_dvrf_tss --release \
  || fail "bench_dvrf_tss failed."
ok "bench_dvrf_tss complete"

# ── 5. Full pipeline — stub co-SNARK — Table II (~5s) ────────────────────────
echo ""
echo "─── Benchmark: Full pipeline — stub co-SNARK (Table II) ───────────────"
info "RC → dx-DCTLS (stub) → FROST Sign → on-chain ABI — O(1) prover"
echo ""
timed "bench_full_pipeline" cargo run --package tls-attestation-bench --bin bench_full_pipeline --release \
  || fail "bench_full_pipeline failed."
ok "bench_full_pipeline complete"

# ── 6. co-SNARK + dx-DCTLS overhead — §IX (~30s) ─────────────────────────────
echo ""
echo "─── Benchmark: co-SNARK + dx-DCTLS overhead (§IX) ─────────────────────"
info "R1CS counts, Mode 1 prove/verify timing"
info "Expected: Mode 1 ~16ms prove, ~1ms verify, CRS setup ~60ms"
echo ""
timed "bench_dctls" cargo run --package tls-attestation-bench --bin bench_dctls --release \
  || fail "bench_dctls failed."
ok "bench_dctls complete"

# ── 7. Full pipeline — real co-SNARK Mode 1 (~30s) ───────────────────────────
echo ""
echo "─── Benchmark: Full pipeline — real co-SNARK Mode 1 (~769 R1CS) ───────"
info "RC → Groth16 Mode 1 → FROST Sign → on-chain ABI"
info "Expected: CRS ~60ms, Attest ~16ms constant (O(1) prover complexity)"
echo ""
timed "bench_full_cosnark" cargo run --package tls-attestation-bench --bin bench_full_cosnark --release \
  || fail "bench_full_cosnark failed."
ok "bench_full_cosnark complete"

# ── 8. Full pipeline — real co-SNARK Mode 2 (~30min) ─────────────────────────
if [ "$RUN_MODE2" = "1" ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║  Mode 2: Full TLS-PRF circuit (~1.9M R1CS constraints)          ║"
  echo "║                                                                  ║"
  echo "║  CRS setup  : ~64s  (one-time trusted setup)                    ║"
  echo "║  Prove      : ~23s  per config  (O(1) in n)                     ║"
  echo "║  Verify     : ~1ms  per config                                  ║"
  echo "║  Paper ref  : 4,700ms (gnark/BLS12-381 on M3)                   ║"
  echo "║  This impl  : ~23,000ms (arkworks/BN254 on M1, ~4.5× slower)    ║"
  echo "║                                                                  ║"
  echo "║  Expected output:                                                ║"
  echo "║    Config    RC(ms) Attest(ms) Sign(ms) OnChain(ms) Total(ms)   ║"
  echo "║    3-of-5        9     26,494        1           0     26,504   ║"
  echo "║    5-of-9       45     23,650        1           0     23,696   ║"
  echo "║    7-of-13     102     23,500        3           0     23,605   ║"
  echo "║    10-of-19    533     25,654        4           0     26,191   ║"
  echo "║    15-of-29    955     22,475        8           0     23,438   ║"
  echo "║    20-of-39   2226     23,944       13           0     26,183   ║"
  echo "║    30-of-59   7587     22,998       26           0     30,611   ║"
  echo "║    50-of-99  34358     24,185       67           0     58,610   ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo ""
  timed "bench_full_cosnark_mode2" \
    cargo run --package tls-attestation-bench --bin bench_full_cosnark_mode2 --release \
    || fail "bench_full_cosnark_mode2 failed."
  ok "bench_full_cosnark_mode2 complete"
else
  echo ""
  info "Mode 2 skipped (--no-mode2). Remove this flag to run the full ~30min benchmark."
fi

# ── 9. Solidity tests (optional, requires forge) ──────────────────────────────
if [ "$RUN_CONTRACTS" = "1" ]; then
  echo ""
  echo "─── Solidity tests (FrostVerifier + DctlsVerifier) ─────────────────────"
  if ! command -v forge &>/dev/null; then
    fail "forge not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
  fi
  timed "forge test" sh -c 'cd contracts && forge test -v' \
    || fail "Solidity tests failed. Run 'cd contracts && forge test -v' for details."
  ok "Solidity tests passed (17 tests)"
else
  echo ""
  info "Solidity tests skipped. Enable with: ./quicktest.sh --contracts (requires forge)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
SCRIPT_END=$(date +%s)
TOTAL=$(( SCRIPT_END - SCRIPT_START ))
TOTAL_MIN=$(( TOTAL / 60 ))
TOTAL_SEC=$(( TOTAL % 60 ))

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  All checks passed.                                              ║"
printf "║  Total elapsed: %2dm %02ds                                        ║\n" "$TOTAL_MIN" "$TOTAL_SEC"
echo "║                                                                  ║"
echo "║  Flags:                                                          ║"
echo "║    --no-mode2     Skip Mode 2 (~30 min)  [default: runs]        ║"
echo "║    --contracts    Solidity tests via forge                       ║"
echo "║    --skip-build   Skip rebuild, run tests only                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""