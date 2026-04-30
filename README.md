# Π_coll-min: Collusion-Minimized TLS Attestation

> **Prototype implementation** of the protocol described in:
>
> **"Collusion-Minimized TLS Attestation Protocol for Decentralized Applications"**
> *Cryptology ePrint Archive, Paper 2026/277* — https://eprint.iacr.org/2026/277
>
> This repository implements the **DVRF-then-Sign component** (RC Phase + Signing
> Phase) in full, plus the structural scaffolding for the dx-DCTLS Attestation
> Phase. The ZK and 2PC components use prototype implementations.

---

## Table of Contents

1. [What is Π_coll-min?](#what-is-coll-min)
2. [Protocol Overview](#protocol-overview)
3. [Architecture](#architecture)
4. [Crate Reference](#crate-reference)
5. [Smart Contracts](#smart-contracts)
6. [Binaries](#binaries)
7. [Benchmarks](#benchmarks)
8. [Building](#building)
9. [Running a Local Network](#running-a-local-network)
10. [Security Notes](#security-notes)

---

## What is Π_coll-min?

TLS attestation lets a third party prove, without involving the server, that a specific HTTP response was served over a genuine TLS session.

Existing DCTLS schemes (DECO, TLSNotary, Distefano) rely on a **single designated verifier**, creating a collusion problem: if the prover and that verifier collude, they can forge an attestation. **Π_coll-min** distributes the verifier role across a *t-of-n* quorum — forging an attestation requires corrupting at least *t* independent verifiers.

Π_coll-min has three phases (paper §V, §VIII, Fig. 8):

1. **RC Phase** — Distributed Verifiable Random Function (DVRF): the verifier quorum runs DKG and jointly generates an unbiasable `rand` that will bind the attestation session.
2. **Attestation Phase** — dx-DCTLS: the coordinator runs a single DCTLS session with the prover, binding the handshake to `rand` via co-SNARK (DECO/TLS 1.2) or v2PC (Distefano/TLS 1.3). The resulting exportable proof lets auxiliary verifiers validate the session without joining it.
3. **Signing Phase** — TSS: auxiliary verifiers check the proofs and, if valid, jointly produce a FROST threshold Schnorr signature over the attested statement.

The key advantage over DECO-DON (naive decentralization): prover complexity drops from **O(n) to O(1)** — one TLS session regardless of verifier set size.

---

## Protocol Overview

```
 Prover              Coordinator (Vcoord)         Aux Verifiers V_1..V_n
   │                       │                              │
   │                       │◄── RC Phase (offline) ──────┤
   │                       │  DKG(pp, t, n) → (ski, pk)  │
   │                       │  PartialEval(α, ski) → γi ──►│
   │                       │  Combine(pk, α, {γi}) → rand │
   │                       │                              │
   │── AttestationRequest ►│                              │
   │                       │                              │
   │   Attestation Phase: dx-DCTLS (paper §VIII.C)        │
   │◄──────────── HSP ─────►│                              │
   │  3-party TLS handshake │                              │
   │  K_MAC = K^P ⊕ K^V    │                              │
   │  Vcoord: π_HSP ← co-SNARK.Execute({K^P,K^V}, Zp)    │
   │                       │                              │
   │◄──────────── QP ──────►│                              │
   │  P gets (Q, R)         │                              │
   │  Vcoord gets (Q̂, R̂)   │                              │
   │                       │                              │
   │  PGP: π_dx ← ZKP.Prove(x=(Q,R,θs), w=(Q̂,R̂,spv,b)) │
   │──── π_dx, π_HSP ──────►│                              │
   │                       │──── broadcast π_dx, π_HSP ──►│
   │                       │                              │
   │   Signing Phase: FROST (paper §VIII.B)                │
   │                       │◄──── Round 1 (commitments) ──┤
   │                       │◄──── Round 2 (shares) ───────┤
   │                       │  σ ← Aggregate(shares)       │
   │◄── FrostAttestationEnvelope (σ, π_HSP, π_dx) ────────│
   │                       │                              │
   │   On-chain: SC.Verify(σ, pk) + ZKP.Verify(π_HSP, π_dx)
```

---

## Architecture

```
collusion-resistant-zktls/
├── crates/
│   ├── core/           # Domain types: VerifierId, DigestBytes, Epoch, QuorumSpec
│   ├── crypto/         # FROST (ed25519+secp256k1), DVRF, DKG
│   ├── zk/             # Groth16 circuits: co-SNARK π_HSP, TLS-PRF, session binding
│   ├── attestation/    # dx-DCTLS session logic (DECO + Distefano variants)
│   ├── network/        # Serializable wire messages for FROST rounds
│   ├── node/           # CoordinatorNode + FrostAuxiliaryNode + TCP transport
│   ├── storage/        # InMemorySessionStore, SqliteSessionStore
│   ├── bench/          # DVRF-then-Sign benchmarks (paper §IX Fig. 9–12)
│   └── testing/        # Integration test helpers, mock TLS sessions
│
└── contracts/
    ├── src/
    │   ├── FrostVerifier.sol   # secp256k1 Schnorr SC.Verify (ecrecover trick)
    │   └── DctlsVerifier.sol   # Groth16 BN254 ZKP.Verify (EIP-197)
    └── test/
        ├── FrostVerifier.t.sol
        └── DctlsVerifier.t.sol
```

---

## Crate Reference

### `tls-attestation-core`

Pure domain types — no I/O, no crypto.

```rust
use tls_attestation_core::{
    ids::{VerifierId, ProverId, SessionId},
    types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    hash::{DigestBytes, sha256},
};
```

### `tls-attestation-crypto`

All cryptographic primitives, feature-gated.

| Feature | What it enables |
|---------|----------------|
| *(default)* | `PrototypeDvrf` (XOR-based, not secure), `PrototypeThresholdSigner` |
| `frost` | Ed25519 FROST (RFC 9591) via `frost-core` — used by coordinator/aux nodes |
| `secp256k1` | secp256k1 FROST + DDH-DVRF — EVM-compatible, used in benchmarks and `FrostVerifier.sol` |

**RC Phase — DVRF (paper §III, §V):**

```rust
use tls_attestation_crypto::dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput};

// Each aux verifier:
let input = Secp256k1DvrfInput::new(alpha);
let partial = Secp256k1Dvrf::partial_eval(&participant, &input)?;

// Coordinator:
let rand = Secp256k1Dvrf::combine(&group_key, &input, &partials, &participants)?;
```

**DKG:**

```rust
// Distributed (production):
use tls_attestation_crypto::dkg_secp256k1::run_secp256k1_dkg;
let outputs = run_secp256k1_dkg(&verifier_ids, threshold)?;

// Trusted dealer (tests/benchmarks only — dealer sees all shares):
use tls_attestation_crypto::frost_adapter::frost_trusted_dealer_keygen;
let keys = frost_trusted_dealer_keygen(&verifier_ids, threshold)?;
```

### `tls-attestation-zk`

Groth16 zero-knowledge backend (arkworks 0.4, BN254).

| Module | What it implements | Paper ref |
|--------|--------------------|-----------|
| `co_snark` | π_HSP: Groth16 proof that K_MAC = K^P ⊕ K^V from Zp | §VIII.C eq. 2 |
| `tls_prf_circuit` | TLS 1.2 PRF R1CS circuit | §IX ref [19] |
| `hmac_sha256_gadget` | HMAC-SHA256 R1CS gadget (~74k constraints/call) | §IX ref [19] |
| `tls_session_binding` | PGP proof: ZKP.Prove(x=(Q,R,θs), w=(Q̂,R̂,spv,b)) | §VIII.C PGP |
| `vk_export` | Export arkworks verifying key → Solidity calldata | §IX |

```rust
use tls_attestation_zk::{CoSnarkCrs, co_snark_execute, co_snark_verify};

let crs = CoSnarkCrs::setup()?;   // one-time trusted setup
let proof = co_snark_execute(&crs, &prover_share, &verifier_share, &pms)?;
co_snark_verify(&crs.vk, &k_mac_commitment, &proof)?;
```

> **Prototype limitation:** The coordinator assembles the full witness `{K^P_MAC, K^V_MAC}` before proving. In the paper's design (ref [32], Özdemir & Boneh), each party runs their own sub-prover — K_MAC is never reconstructed in one place. This distributed co-SNARK is left as future work.

### `tls-attestation-attestation`

dx-DCTLS session logic — DECO and Distefano variants.

| Module | TLS version | Handshake binding | Paper ref |
|--------|-------------|-------------------|-----------|
| `deco_dx_dctls` | TLS 1.2 | co-SNARK π_HSP over K_MAC | §VIII.C eq. 2 |
| `distefano_dx_dctls` | TLS 1.3 | v2PC π_2PC over traffic secrets | §VIII.C eq. 3 |
| `rc_phase` | — | DKG + DVRF orchestration | §V RC Phase |
| `onchain` | — | FrostAttestationEnvelope → on-chain format | §IX |

> **Prototype limitation:** Both variants use `mock_tls12_session` / `mock_tls13_session` instead of a real rustls session. The `--features tls` path wires up a real rustls connector but is not exercised in the benchmarks.

### `tls-attestation-node`

Coordinator and auxiliary verifier node implementations.

**Coordinator — orchestrates all three phases:**

```rust
use tls_attestation_node::{CoordinatorNode, coordinator::CoordinatorConfig};

let coordinator = CoordinatorNode::new(config, store, dvrf, engine);

// In-process (tests, single binary):
let envelope = coordinator.attest_frost_distributed(
    request, &response_bytes, &aux_nodes, &group_key
)?;

// Over TCP (real network):
let envelope = coordinator.attest_frost_distributed_over_transport(
    request, &response_bytes, &transport_refs, &group_key
)?;
```

**Auxiliary node — holds key share, serves FROST round requests:**

```rust
use tls_attestation_node::FrostAuxiliaryNode;

// Built from DKG output:
let node = FrostAuxiliaryNode::new(dkg_output.participant);
```

**Transport layer:**

| Type | Use case |
|------|----------|
| `InProcessTransport` | Tests, zero-copy single-binary |
| `TcpNodeTransport` | Production TCP (coordinator → aux) |
| `TcpAuxServer` | Production TCP (aux node listener) |
| `AuthTcpNodeTransport` | Ed25519-signed TCP (`--features auth`) |
| `MtlsTcpNodeTransport` | Mutual TLS (`--features mtls`) |

### `tls-attestation-storage`

Session store for coordinator's in-flight state.

```rust
use tls_attestation_storage::InMemorySessionStore;  // tests / single binary
use tls_attestation_storage::SqliteSessionStore;    // persistent / production
```

---

## Smart Contracts

Located in `contracts/`. Requires [Foundry](https://getfoundry.sh/).

### `FrostVerifier.sol` — on-chain SC.Verify

Verifies secp256k1 FROST Schnorr signatures (paper §VIII.B, Table I).

```solidity
function verify(
    bytes32 message_hash,
    uint256 pk_x,
    uint256 pk_y,
    uint256 sig_R_x,
    uint256 sig_s
) public view returns (bool)
```

The EVM has no secp256k1 scalar multiplication precompile (0x06/0x07 are BN254-only). This contract implements Schnorr verification via the `ecrecover` precompile (0x01), which internally uses secp256k1. Gas cost: **~14,000 gas**.

Challenge hash convention (EVM-compatible, differs from RFC 9591):
```
e = keccak256(R_x ‖ pk_x ‖ message_hash) mod N
```

### `DctlsVerifier.sol` — on-chain ZKP.Verify

Verifies Groth16 proofs on BN254 using EIP-196/197 precompiles (paper §IX).

```solidity
// Set verifying keys once after deployment (owner only):
function setHspVK(VerifyingKey calldata vk, uint256[2][4] calldata ic) external onlyOwner;
function setSessionBindingVK(VerifyingKey calldata vk, uint256[2][5] calldata ic) external onlyOwner;

// Atomic verification — reverts if any proof is invalid:
function verifyFullAttestation(
    Proof calldata hspProof,
    Proof calldata sessionProof,
    uint256 kMacCommitment,
    uint256 randBinding,
    uint256 pmsHash,
    uint256 macCommitmentQ,
    uint256 macCommitmentR
) external view;
```

Gas cost: **~181,000 gas** per `verifyFullAttestation` (4-pairing BN254 check).

### Running Contract Tests

```bash
cd contracts && forge test -v
```

Output (17 tests, 0 failures — measured on this machine):
```
Ran 8 tests for FrostVerifier.t.sol:
[PASS] test_Deploy()          (gas:     2,462)
[PASS] test_GasCost()         (gas:    13,918)  ← ~14k gas, paper Table I
[PASS] test_ValidSignature()  (gas:    12,424)
[PASS] test_WrongMessage()    (gas:    12,422)
[PASS] test_WrongPubKeyX()    (gas:    12,252)
[PASS] test_WrongRx()         (gas:     8,269)
[PASS] test_WrongSigS()       (gas:    12,284)
[PASS] test_ZeroSignature()   (gas:     8,176)

Ran 9 tests for DctlsVerifier.t.sol:
[PASS] test_Deploy()                              (gas:      8,212)
[PASS] test_OwnerCanSetVK()                       (gas:     55,359)
[PASS] test_OwnerCanSetHspMode2VK()               (gas:     60,945)
[PASS] test_OwnerCanSetSessionBindingVK()         (gas:     65,932)
[PASS] test_OnlyOwnerCanSetVK()                   (gas:     12,142)
[PASS] test_Gas_HspMode1()                        (gas:    263,682)  ← ~181k pairing gas
[PASS] test_ZeroProofWithZeroVK_IsAccepted_ByPairing() (gas: 261,232)
[PASS] test_FullAttestation_ZeroProof_PassesTrivially() (gas: 561,728)
[PASS] test_FullZKP_Skipped()                     (gas:        524)
```

> **Warning:** `DctlsVerifier.sol` accepts all-zero proofs when the verifying key is all-zero (BN254 identity). Always call `setHspVK` and `setSessionBindingVK` with real circuit keys before accepting proofs.

---

## Binaries

### `aux-node`

```bash
cargo build --package tls-attestation-node --features frost,tcp --bin aux-node --release
./target/release/aux-node --config node-0.json
```

Holds one FROST key share and serves `FrostRound1` + `FrostRound2` requests over TCP. Optionally supports Ed25519 node authentication (`--features auth`) and mTLS (`--features mtls`).

### `coordinator`

```bash
cargo build --package tls-attestation-node --features frost,tcp --bin coordinator --release
./target/release/coordinator --config coordinator.json
```

HTTP server (default: `:9100`) that accepts attestation requests, runs the DVRF and FROST rounds against aux nodes, and returns a `FrostAttestationEnvelope`.

### `dkg-ceremony`

```bash
cargo build --package tls-attestation-node --features frost --bin dkg-ceremony --release
./target/release/dkg-ceremony --threshold 10 --num-nodes 19 --output-dir /keys/
```

Runs a Pedersen DKG ceremony in-process and writes one key file per node. For production, each node must run its own DKG participant process.

### `gen-test-vectors`

```bash
cargo run --package tls-attestation-node --features frost,tcp,secp256k1 \
  --bin gen-test-vectors --release
```

Generates secp256k1 Schnorr test vectors with the exact `keccak256(R_x ‖ pk_x ‖ msg) mod N` challenge used by `FrostVerifier.sol`.

---

## Benchmarks

All benchmarks measure the **DVRF-then-Sign** component (paper §IX). This is the component the paper benchmarks fully. dx-DCTLS overhead is derived analytically from existing DECO measurements in the paper.

### LAN: DVRF + TSS execution time (Fig. 9)

```bash
cargo run --package tls-attestation-bench --bin bench_dvrf_tss --release
```

Measures DVRF (PartialEval + Combine) and FROST signing (Round1 + Round2 + Aggregate) across t-of-n configurations. Corresponds to Fig. 9 in the paper.

Sample output (Apple M1, release build):

```
Config      DKG (ms)   DVRF (ms)   TSS (ms)   Total (ms)
─────────────────────────────────────────────────────────
2-of-3             3           1          1           5
3-of-5            13           1          1          15
4-of-7            30           1          2          33
5-of-9            60           2          2          64
7-of-13          159           4          4         167
10-of-19         459           6          7         472
15-of-29        1511          12         13        1536
```

### Full pipeline — end-to-end (Table II)

```bash
cargo run --package tls-attestation-bench --bin bench_full_pipeline --release
```

RC Phase → dx-DCTLS → FROST Sign → on-chain ABI encoding. Demonstrates O(1) prover complexity.

Sample output (Apple M1, release build):

```
Config      RC (ms)   Attest (ms)   Sign (ms)   OnChain (ms)   Total (ms)
──────────────────────────────────────────────────────────────────────────
2-of-3            5             0           2              0           7
3-of-5           21             0           1              0          22
5-of-9           62             0           2              0          64
7-of-13         162             0           3              0         165
10-of-19        469             0           8              0         477
```

> Attest and OnChain columns show 0 ms because the benchmark uses stub co-SNARK and mock TLS session (no real Groth16 proof). See `bench_dctls` for co-SNARK timing.

### Full pipeline — real co-SNARK across t-of-n configurations

```bash
cargo run --package tls-attestation-bench --bin bench_full_cosnark --release
```

RC Phase → dx-DCTLS (real Groth16 Mode 1) → FROST Sign → on-chain ABI. Groth16 CRS is set up once and reused across all configurations.

Sample output (Apple M1, release build):

```
Groth16 CRS setup (Mode 1, ~769 R1CS)... 61ms

Config       RC (ms)   Attest (ms)   Sign (ms)   OnChain (ms)   Total (ms)
───────────────────────────────────────────────────────────────────────────
3-of-5             8            16           0              0          24
5-of-9            37            17           1              0          55
7-of-13           99            17           2              0         118
10-of-19         292            17           4              0         313
15-of-29         930            16           7              0         953
20-of-39        2185            16          12              0        2213
30-of-59        7499            16          25              0        7540
50-of-99       34384            16          65              0       34465
```

**Key observation:** Attest sütunu tüm konfigürasyonlarda sabit **~16–17 ms** — n'den bağımsız. Bu O(1) prover complexity'yi doğrudan ölçüyor. RC (DKG) O(n²) büyüyor ve dominant oluyor; gerçek üretimde DKG bir kere yapılır ve bu maliyet tekrarlanmaz.

### co-SNARK + dx-DCTLS overhead (§IX)

```bash
cargo run --package tls-attestation-bench --bin bench_dctls --release
```

Measures HSP proof generation (Groth16), QP, and PGP phases. Compares R1CS constraint counts against paper reference [19].

Sample output (Apple M1, release build):

```
R1CS Constraint Counts:
  Mode 1 (K_MAC split only):          769 constraints
  Mode 2 (full TLS-PRF):        1,927,271 constraints
  Paper [19] (gnark BLS12-381): 1,719,598 constraints
  Delta (arkworks BN254):            +12.1%

Phase                    Min(ms)  Max(ms)  Avg(ms)   Paper [19]
───────────────────────────────────────────────────────────────
HSP Mode 1 (769 R1CS)        27       27       27       N/A
HSP Mode 2 (extrapolated)     —        —   ~10,534    4,700ms
QP — HMAC commit              0        0        0        ~0ms
PGP — statement proof         0        0        0      varies
```

Mode 2 is extrapolated: `Mode 1 rate × (1,927,271 / 769) × 2` (BN254 is ~2× slower than gnark/BLS12-381). Paper's 4,700 ms uses gnark on BLS12-381; our estimate is ~10,500 ms on arkworks/BN254.

---

## Building

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.78+ | All Rust crates |
| Foundry (`forge`) | latest | Solidity tests |
| OpenSSL | 3.x | `--features mtls` only |

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

git clone <repo-url> && cd tls
```

### Build

```bash
# Default (no crypto features):
cargo build --workspace

# FROST + TCP (coordinator + aux-node):
cargo build --workspace --features frost,tcp

# Full (includes secp256k1 DVRF + EVM path):
cargo build --workspace --features frost,tcp,secp256k1
```

### Feature Matrix

| Feature | Description |
|---------|-------------|
| `frost` | Ed25519 FROST (RFC 9591) — coordinator and aux-node |
| `secp256k1` | secp256k1 FROST + DDH-DVRF — EVM-compatible RC Phase |
| `tcp` | TCP transport layer |
| `auth` | Ed25519-signed node-to-node authentication |
| `mtls` | Mutual TLS transport |
| `tls` | Real TLS 1.2 session capture via rustls |
| `sqlite` | Persistent session store |

### Tests

```bash
# Rust unit + integration tests:
cargo test --workspace --features frost,tcp,secp256k1

# Solidity tests:
cd contracts && forge test -v
```

---

## Running a Local Network

3-of-5 network on localhost — all in-process using `InProcessTransport`.

### Step 1 — DKG

```bash
./target/release/dkg-ceremony \
  --threshold 3 \
  --num-nodes 5 \
  --output-dir /tmp/keys/
```

Produces `/tmp/keys/node-{0..4}.json` (key shares) and `/tmp/keys/group-key.json`.

### Step 2 — Start aux nodes

```bash
for i in 0 1 2 3 4; do
  ./target/release/aux-node --config /tmp/keys/node-$i.json &
done
```

Default ports: `9200`–`9204`.

### Step 3 — Start coordinator

```bash
./target/release/coordinator --config coordinator.json
```

### Step 4 — Request attestation

```bash
curl -X POST http://localhost:9100/attest \
  -H "Content-Type: application/json" \
  -d '{
    "prover_id_hex": "0101010101010101010101010101010101010101010101010101010101010101",
    "client_nonce_hex": "0202020202020202020202020202020202020202020202020202020202020202",
    "statement_tag": "example.com/balance",
    "query": "GET /balance HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "requested_ttl_secs": 3600
  }'
```

Response — `FrostAttestationEnvelope` JSON:

```json
{
  "session": { "prover_id": "...", "epoch": 1, "nonce": "..." },
  "randomness": { "rand_binding": "...", "dvrf_proof": "..." },
  "statement": { "tag": "example.com/balance", "digest": "..." },
  "frost_approval": {
    "signature_r": "...",
    "signature_s": "...",
    "group_verifying_key": "..."
  },
  "envelope_digest": "..."
}
```

Submit `frost_approval` to `FrostVerifier.sol` for on-chain verification.

---

## Security Notes

### Prototype Components

The following are **not production-safe**:

- `PrototypeDvrf` — uses `H(key XOR alpha)` instead of DDH-based DVRF. Correct interface, insecure construction.
- `PrototypeThresholdSigner` — single-round, single-party. Does not threshold.
- `PrototypeAttestationEngine` — skips real TLS session verification.
- `frost_trusted_dealer_keygen` — the dealer sees all key shares. For tests and benchmarks only.
- `mock_tls12_session` / `mock_tls13_session` — synthetic session parameters.

The production path uses `Secp256k1Dvrf` (DDH-DVRF on secp256k1) and ed25519/secp256k1 FROST from `frost-core`.

### co-SNARK is Single-Party

The paper (§VIII.C eq. 2) specifies:

```
(K_MAC, π_HSP) ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp)
```

where each party holds their witness independently. This implementation instead has the coordinator assemble the full `{K^P_MAC, K^V_MAC}` and run a standard single-prover Groth16. The coordinator therefore learns K_MAC. This is acceptable under the paper's honest-but-curious coordinator assumption (§IV) but is not the full co-SNARK design. Full distributed co-SNARK (ref [32], Özdemir & Boneh, USENIX Security 2022) is future work.

### BN254 Zero-Verifying-Key

`DctlsVerifier.sol` will accept any proof if the verifying key is all-zero (BN254 pairing identity). Always deploy with real circuit verifying keys set via `setHspVK` / `setSessionBindingVK`.

### Schnorr Challenge Divergence

`FrostVerifier.sol` uses `keccak256(R_x ‖ pk_x ‖ msg) mod N` — not the RFC 9591 domain-separated SHA-512 challenge. Test vectors from `gen-test-vectors` match this contract exactly.

---