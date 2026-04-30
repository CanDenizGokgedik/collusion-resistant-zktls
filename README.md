# dx-DCTLS: Decentralized Cross-TLS Attestation

> **Reference implementation** of the protocol described in:
>
> **"Collusion-Minimized TLS Attestation Protocol for Decentralized Applications"**
> *Cryptology ePrint Archive, Paper 2026/277* — https://eprint.iacr.org/2026/277
>
> This codebase implements every protocol component from the paper end-to-end:
> the Π_coll-min framework, dx-DCTLS exportable attestation, Distributed Verifiable
> Random Function (DVRF), FROST threshold Schnorr signing, Groth16 zero-knowledge
> proofs, on-chain EVM verification, and a TCP-based auxiliary-node network.

---

## Table of Contents

1. [What is dx-DCTLS?](#what-is-dx-dctls)
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

## What is dx-DCTLS?

TLS attestation answers the question: *"Can a third party prove, without involving the server, that a specific HTTP response was served over a genuine TLS session?"*

Existing schemes (DECO, TLSNotary) rely on a single trusted notary. **dx-DCTLS** removes that single point of trust by replacing the notary with a **decentralized quorum** of *t-of-n* auxiliary verifiers. No single verifier can forge an attestation — collusion of at least *t* parties is required.

### Key Properties

| Property | Mechanism |
|----------|-----------|
| **Decentralization** | t-of-n FROST threshold signing (paper §VIII.B) |
| **Randomness binding** | secp256k1 DVRF ties attestation to an unpredictable per-session nonce (paper §III, §V) |
| **Privacy** | co-SNARK/Groth16 ZKP proves K_MAC binding without revealing the TLS master secret (paper §VIII.C eq. 2) |
| **On-chain verifiability** | Single EVM transaction verifies FROST σ + Groth16 π (paper §IX) |
| **TLS 1.2 + 1.3** | DECO-based (§VIII.C) and Distefano v2PC-based (§VIII.C eq. 3) variants |

---

## Protocol Overview

The full attestation runs in four sequential phases (paper §VIII, Fig. 8):

```
 Prover                  Coordinator               Aux Verifiers (×n)
   │                         │                           │
   │── AttestationRequest ──►│                           │
   │                         │                           │
   │        ┌── Phase 1: RC (Randomness Creation) ──────┤
   │        │  DKG (offline) → group key vk_FROST        │
   │        │  DVRF.PartialEval × t ─────────────────►  │
   │        │  DVRF.Combine → rand ◄─────────────────── │
   │        └──────────────────────────────────────────  │
   │                         │                           │
   │        ┌── Phase 2: HSP (Handshake SubProtocol) ──────┤
   │        │  3-party TLS handshake: S + P + Vcoord     │
   │        │  2PC MAC key split: K_MAC = K^P ⊕ K^V     │
   │        │  co-SNARK: π_HSP proves handshake w/ rand  │
   │        └──────────────────────────────────────────  │
   │                         │                           │
   │        ┌── Phase 3: QP (Query Protocol) ──────────  │
   │        │  P + Vcoord jointly construct query (2PC)  │
   │        │  P gets (Q,R), Vcoord gets (Q̂,R̂) commits  │
   │        └──────────────────────────────────────────  │
   │                         │                           │
   │        ┌── Phase 4: PGP (Proof Generation Protocol) ┤
   │        │  FROST Round 1: commit (nonce) × t ─────► │
   │        │  FROST Round 2: share  × t        ─────► │
   │        │  Aggregate → σ = (R, s)                   │
   │        │  ZKP: π_θs = Groth16(session_binding)     │
   │        └──────────────────────────────────────────  │
   │                         │                           │
   │◄── FrostAttestationEnvelope (σ, π_HSP, π_θs) ─────│
   │                         │                           │
   │        On-chain: FrostVerifier.verify(σ, vk)       │
   │                  DctlsVerifier.verifyFullAttestation(π_HSP, π_θs)
```

### Verification Equation (paper §IX)

```
Valid attestation iff:
  SC.Verify(σ, vk_FROST, envelope_digest) = 1         // FROST Schnorr
  ZKP.Verify(π_HSP,  [K_MAC_commit, rand_binding]) = 1 // Groth16 Mode 2
  ZKP.Verify(π_θs,   [K_MAC_commit, mac_q, mac_r]) = 1 // session binding
  shared commitment consistency: K_MAC_commit matches in both proofs
```

---

## Architecture

```
tls/
├── crates/
│   ├── core/           # Domain types: VerifierId, DigestBytes, Epoch, QuorumSpec
│   ├── crypto/         # FROST adapter, DVRF, DKG, randomness engines
│   ├── zk/             # Groth16 circuits: HSP, session binding, TLS-PRF
│   ├── attestation/    # Protocol sessions, envelopes, engine trait
│   ├── network/        # Wire messages: FrostRound1Request/Response, etc.
│   ├── node/           # Coordinator + AuxiliaryNode + TCP transport
│   ├── storage/        # InMemorySessionStore, SqliteSessionStore
│   ├── bench/          # §IX benchmark suite
│   └── testing/        # Integration test helpers
│
├── contracts/
│   ├── src/
│   │   ├── FrostVerifier.sol   # secp256k1 Schnorr verifier (ecrecover trick)
│   │   └── DctlsVerifier.sol   # Groth16 BN254 verifier (EIP-197)
│   └── test/
│       ├── FrostVerifier.t.sol
│       └── DctlsVerifier.t.sol
```

---

## Crate Reference

### `tls-attestation-core`

No I/O, no async, no cryptography — pure domain types.

```rust
use tls_attestation_core::{
    ids::{VerifierId, ProverId},
    types::{Epoch, Nonce, QuorumSpec},
    hash::{DigestBytes, sha256},
};
```

### `tls-attestation-crypto`

All cryptographic primitives. Feature-gated to avoid pulling heavy dependencies into every consumer.

| Feature | What it enables |
|---------|----------------|
| *(default)* | `PrototypeDvrf`, `PrototypeThresholdSigner`, `FrostGroupKey` |
| `frost` | Ed25519 FROST (RFC 9591) via `frost-core` |
| `secp256k1` | secp256k1 FROST + DDH-DVRF (EVM-compatible, paper §IX Table I) |

```rust
// Trusted-dealer key generation (benchmarks / tests only)
use tls_attestation_crypto::frost_adapter::frost_trusted_dealer_keygen;
let keys = frost_trusted_dealer_keygen(&verifier_ids, threshold)?;

// Real distributed DKG (production)
use tls_attestation_crypto::dkg::run_dkg_ceremony;
```

**DVRF (paper §III Preliminaries, §V RC Phase)**

```rust
use tls_attestation_crypto::dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput};

let input = Secp256k1DvrfInput::new(session_alpha);
let partial = Secp256k1Dvrf::partial_eval(&participant, &input)?;
let rand = Secp256k1Dvrf::combine(&group_key, &input, partials, &participants)?;
```

### `tls-attestation-zk`

Groth16 zero-knowledge backend on BN254 (arkworks 0.4).

| Module | Circuit | Paper ref |
|--------|---------|-----------|
| `co_snark` | HSP proof: co-SNARK.Execute({K^P_MAC, K^V_MAC}, Zp) | §VIII.C eq. 2 |
| `tls_prf_circuit` | TLS-PRF R1CS (~37 k constraints/block) | §IX ref [19] |
| `hmac_sha256_gadget` | HMAC-SHA256 gadget (~74 k constraints/call) | §IX ref [19] |
| `tls_session_binding` | ZKP.Prove(x,w): x=(Q,R,θs), w=(Q̂,R̂,spv,b) | §VIII.C PGP |
| `vk_export` | arkworks BN254 → Solidity hex | §IX |

```rust
use tls_attestation_zk::{CoSnarkBackend, CoSnarkCrs, co_snark_execute, co_snark_verify};

let crs = CoSnarkCrs::setup()?;         // one-time trusted setup
let proof = co_snark_execute(&crs, witness)?;
assert!(co_snark_verify(&crs.vk, &public_inputs, &proof)?);
```

> **Note:** The current implementation runs Groth16 with a **single coordinator-held witness**. Full co-SNARK (distributed witness, no single party sees K_MAC) requires MPC-based R1CS extension and is left as future work. See §VIII.C eq. 2 and [32] (Özdemir & Boneh, USENIX Security 2022) and the [Security Notes](#security-notes) section.

### `tls-attestation-attestation`

Protocol session management, envelope construction, and auxiliary verifier logic.

```rust
use tls_attestation_attestation::engine::{CoordinatorNode, AttestationRequest};
use tls_attestation_attestation::dctls::verify_hsp_proof;
```

Protocol variants:

| Variant | TLS version | 2PC method | Module |
|---------|-------------|-----------|--------|
| DECO dx-DCTLS | TLS 1.2 | RFC 5705 exporter | `deco_dx_dctls` |
| Distefano dx-DCTLS | TLS 1.3 | v2PC traffic split | `distefano_dx_dctls` |

### `tls-attestation-network`

Wire protocol — serializable request/response messages.

```
FrostRound1Request  ↔  FrostRound1Response
FrostRound2Request  ↔  FrostRound2Response
HandshakeBindingRound1Request  ↔  HandshakeBindingRound1Response
HandshakeBindingRound2Request  ↔  HandshakeBindingRound2Response
AttestationRequest  ↔  AttestationResponse
```

All messages implement `serde::Serialize + serde::Deserialize`.

### `tls-attestation-node`

Coordinator and auxiliary verifier node implementations.

**Coordinator** (paper §VIII.B Signing Phase):

```rust
use tls_attestation_node::{CoordinatorNode, coordinator::CoordinatorConfig};

let coordinator = CoordinatorNode::new(config, store, dvrf, engine);

// In-process (tests / single binary):
let envelope = coordinator.attest_frost_distributed(&request, &response, &aux_nodes, &group_key)?;

// Over TCP (production):
let envelope = coordinator.attest_frost_distributed_over_transport(
    request, &response, &transport_refs, &group_key
)?;
```

**Auxiliary Node** (paper §VIII.B):

```rust
use tls_attestation_node::FrostAuxiliaryNode;

let node = FrostAuxiliaryNode::new(participant);
// Serves FrostRound1/Round2 requests
```

**Transports:**

| Type | Use case |
|------|----------|
| `InProcessTransport` | Tests, single-binary deployments |
| `TcpNodeTransport` | Production TCP (coordinator side) |
| `TcpAuxServer` | Production TCP (aux node side) |
| `AuthTcpNodeTransport` | Ed25519-authenticated TCP |
| `MtlsTcpNodeTransport` | mTLS-authenticated TCP |

### `tls-attestation-storage`

Session store implementations for the coordinator's session cache.

```rust
use tls_attestation_storage::InMemorySessionStore;  // tests
use tls_attestation_storage::SqliteSessionStore;    // production
```

---

## Smart Contracts

Located in `contracts/`. Requires [Foundry](https://getfoundry.sh/).

### `FrostVerifier.sol`

On-chain FROST secp256k1 Schnorr signature verifier (paper §VIII.B `SC.Verify`).

```solidity
function verify(
    bytes32 message_hash,
    uint256 pk_x,
    uint256 pk_y,
    uint256 sig_R_x,
    uint256 sig_s
) public view returns (bool valid)
```

**Implementation note:** EVM has no native secp256k1 scalar multiplication precompile (`ecMul`/`ecAdd` at 0x06/0x07 are BN254-only). This contract uses the **`ecrecover` trick** to perform the verification equation `s·G − e·PK = R` using only the secp256k1 ECDSA recovery precompile at `0x01` — no external dependencies.

Gas cost: **~14,000 gas** per verification call.

### `DctlsVerifier.sol`

On-chain Groth16 verifier for dx-DCTLS ZK proofs (paper §IX). Uses EIP-196/197 BN254 precompiles.

```solidity
// Register verifying keys (owner only, done once at deployment):
function setHspMode1VK(VerifyingKey calldata vk, uint256[2][3] calldata ic) external onlyOwner;
function setHspMode2VK(VerifyingKey calldata vk, uint256[2][4] calldata ic) external onlyOwner;
function setSessionBindingVK(VerifyingKey calldata vk, uint256[2][5] calldata ic) external onlyOwner;

// Verify individual proofs:
function verifyHspMode1(Proof calldata proof, uint256 kMacCommitment, uint256 randBinding) external view returns (bool);
function verifyHspMode2(...) external view returns (bool);
function verifySessionBinding(...) external view returns (bool);

// Atomic full attestation (reverts on any invalid proof):
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

Gas cost: **~181,000 gas** per `verifyFullAttestation` (4-pair BN254 pairing, EIP-197).

### Running Contract Tests

```bash
cd contracts
forge test -v
```

```
Ran 8 tests for test/FrostVerifier.t.sol:FrostVerifierTest
[PASS] test_Deploy()          (gas: 2,462)
[PASS] test_GasCost()         (gas: 13,918)  ← ~14k gas
[PASS] test_ValidSignature()  (gas: 12,424)
[PASS] test_WrongMessage()    (gas: 12,422)
[PASS] test_WrongPubKeyX()    (gas: 12,252)
[PASS] test_WrongRx()         (gas: 8,269)
[PASS] test_WrongSigS()       (gas: 12,284)
[PASS] test_ZeroSignature()   (gas: 8,176)

Ran 9 tests for test/DctlsVerifier.t.sol:DctlsVerifierTest
[PASS] test_Deploy()
[PASS] test_OwnerCanSetVK()
[PASS] test_OnlyOwnerCanSetVK()     ← access control
[PASS] test_ZeroProofWithZeroVK_IsAccepted_ByPairing()  ← documents BN254 identity
[PASS] test_FullAttestation_ZeroProof_PassesTrivially()
[PASS] test_Gas_HspMode1()          (gas: 263,682) ← ~180k pairing gas
...

17 tests total, 0 failed.
```

> **BN254 identity note:** With all-zero proof + all-zero verifying key, the pairing product trivially equals 1 (identity element). Production deployments must always set real circuit verifying keys via `setHspMode*VK` before accepting proofs.

---

## Binaries

### `coordinator`

```bash
cargo build --package tls-attestation-node --features frost,tcp --bin coordinator --release
./target/release/coordinator --config coordinator.json
```

**Config format (`coordinator.json`):**

```json
{
  "coordinator_id_hex": "0000...ff",
  "listen_addr": "0.0.0.0:9100",
  "threshold": 10,
  "verifiers": ["<vid_hex_1>", "<vid_hex_2>", "..."],
  "epoch": 1,
  "default_ttl_secs": 3600
}
```

HTTP endpoints:
- `POST /attest` — accepts `AttestationRequest` JSON, returns `FrostAttestationEnvelope` JSON
- `GET  /health` — liveness check

### `aux-node`

```bash
cargo build --package tls-attestation-node --features frost,tcp --bin aux-node --release
./target/release/aux-node --config node-0.json
```

**Config format:**

```json
{
  "verifier_id_hex": "0000...01",
  "key_file": "/keys/node-0.json",
  "listen_addr": "0.0.0.0:9200",
  "threshold": 10,
  "num_nodes": 19
}
```

Serves FROST Round 1 + Round 2 requests over TCP.
Optionally supports Ed25519 authentication (`--features auth`) and mTLS (`--features mtls`).

### `dkg-ceremony`

```bash
cargo build --package tls-attestation-node --features frost --bin dkg-ceremony --release
./target/release/dkg-ceremony \
  --threshold 10 \
  --num-nodes 19 \
  --output-dir /keys/
```

Runs a full Pedersen DKG ceremony among `n` participants and writes one key file per node.

### `gen-test-vectors`

```bash
cargo run --package tls-attestation-node \
  --features frost,tcp,secp256k1 \
  --bin gen-test-vectors --release
```

Generates secp256k1 Schnorr test vectors using the exact `keccak256(R_x ‖ pk_x ‖ msg) mod N` challenge hash formula from `FrostVerifier.sol`. Output is ready to paste into Solidity tests.

---

## Benchmarks

All benchmarks live in `crates/bench/src/bin/`. Paper reference: **§IX, Fig. 9–12**.

### DVRF + TSS (Fig. 9)

```bash
cargo run --package tls-attestation-bench --bin bench_dvrf_tss --release
```

Measures DVRF (partial eval + combine) and FROST signing (round1 + round2 + aggregate) separately across all t-of-n configurations.

### Full Pipeline (Fig. 10/11)

```bash
cargo run --package tls-attestation-bench --bin bench_full_pipeline --release
```

End-to-end: DKG → DVRF → FROST signing → ZKP generation → envelope assembly.

### WAN Benchmark — Simulated (Fig. 12)

```bash
cargo run --package tls-attestation-bench --bin bench_wan --release
```

Simulates WAN latency entirely via `Thread::sleep`. Fast to run, no network required.

### WAN Benchmark — Real Crypto (Fig. 12)

```bash
cargo run --package tls-attestation-bench --features tcp --bin bench_wan_real --release
```

Runs **actual** ed25519 FROST cryptography with per-message latency injected through `LatencyTransport`. Separates CPU time from network time.

Sample output on Apple M-series (debug build):

```
╔══════════════════════════════════════════════════════════════════╗
║  Real FROST WAN Benchmark — Paper §IX, Fig. 12                  ║
╚══════════════════════════════════════════════════════════════════╝

Config        LAN(ms)   WAN1(ms)   WAN1-net   WAN2(ms)   WAN2-net
──────────────────────────────────────────────────────────────────
2-of-3            13ms       391ms       321ms       652ms       581ms
3-of-5            24ms       591ms       482ms      1036ms       906ms
5-of-9            45ms      1034ms       794ms      1695ms      1489ms
7-of-13           78ms      1449ms      1122ms      2437ms      2114ms
10-of-19         157ms      2141ms      1602ms      3475ms      2963ms
```

**WAN profiles used:**

| Profile | RTT | Bandwidth | Packet loss |
|---------|-----|-----------|-------------|
| LAN  | 0 ms    | 1000 Mbps | 0.0% |
| WAN1 | 80 ms   | 50 Mbps   | 0.1% |
| WAN2 | 150 ms  | 20 Mbps   | 0.2% |

Paper §IX claims: *"15-of-29 WAN2 without DKG ≈ 1,000ms additional overhead."* Extrapolating the table above to 15-of-29 is consistent with this claim.

For real hardware experiments:
```bash
# Linux only — requires root
sudo tc qdisc add dev lo root netem delay 40ms 5ms loss 0.1%   # WAN1
# Then run the benchmark with real TCP transports
```

---

## Building

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.78+ | All Rust crates |
| Foundry (`forge`) | latest | Solidity tests |
| OpenSSL | 3.x | mTLS feature |

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Clone
git clone <repo-url>
cd tls
```

### Build All (default features)

```bash
cargo build --workspace
```

### Build with FROST + TCP

```bash
cargo build --workspace --features frost,tcp
```

### Feature Matrix

| Feature | Crates | Description |
|---------|--------|-------------|
| `frost` | `crypto`, `network`, `node` | Ed25519 FROST (RFC 9591) |
| `secp256k1` | `crypto`, `attestation` | secp256k1 FROST + DDH-DVRF (EVM path) |
| `tcp` | `network`, `node` | TCP transport layer |
| `auth` | `node` | Ed25519 node authentication |
| `mtls` | `node` | mTLS (mutual TLS) transport |
| `tls` | `attestation` | Real TLS session capture via rustls |
| `sqlite` | `storage` | Persistent session store |

### Run All Tests

```bash
# Rust tests
cargo test --workspace --features frost,tcp

# Solidity tests
cd contracts && forge test -v
```

---

## Running a Local Network

This example runs a 3-of-5 network entirely on localhost.

### Step 1: DKG Ceremony

```bash
./target/release/dkg-ceremony \
  --threshold 3 \
  --num-nodes 5 \
  --output-dir /tmp/dx-dctls-keys/
```

Generates `/tmp/dx-dctls-keys/node-{0..4}.json` and `group-key.json`.

### Step 2: Start Aux Nodes

```bash
for i in 0 1 2 3 4; do
  ./target/release/aux-node \
    --config /tmp/dx-dctls-keys/node-$i.json &
done
```

Aux nodes listen on ports `9200`, `9201`, `9202`, `9203`, `9204`.

### Step 3: Start Coordinator

```bash
./target/release/coordinator --config coordinator.json
```

### Step 4: Request an Attestation

```bash
curl -X POST http://localhost:9100/attest \
  -H "Content-Type: application/json" \
  -d '{
    "prover_id_hex": "0101...01",
    "client_nonce_hex": "0202...02",
    "statement_tag": "example.com/api/v1/balance",
    "query": "GET /api/v1/balance HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "requested_ttl_secs": 3600
  }'
```

Response: `FrostAttestationEnvelope` JSON containing:
- `session`: session context (prover, epoch, nonce)
- `randomness`: DVRF rand binding
- `transcript`: TLS transcript commitments
- `statement`: query + response digest
- `coordinator_evidence`: DVRF partial evaluations
- `frost_approval`: 64-byte aggregate Schnorr signature `(R, s)` + group verifying key
- `envelope_digest`: canonical hash of all above fields

---

## Security Notes

### Production Readiness

All items named `Prototype*` (`PrototypeDvrf`, `PrototypeThresholdSigner`, `PrototypeAttestationEngine`) are **not production-safe**. They are structurally correct but make simplifying assumptions:

- `PrototypeDvrf` uses a hash-based XOR scheme instead of DDH-based DVRF
- `PrototypeAttestationEngine` skips TLS session verification
- Trusted-dealer DKG (`frost_trusted_dealer_keygen`) is for tests only — the dealer sees all key shares

### Honest-Coordinator Assumption

The current ZK implementation runs Groth16 with the coordinator holding the full witness (K_MAC). The paper describes a setting where coordinator (Vcoord) is honest-but-curious (paper §IV, Problem Formulation).

A fully trustless implementation requires **collaborative zk-SNARKs** where each auxiliary verifier contributes its witness share `wᵢ` without revealing it to the coordinator (paper §VIII.C eq. 2, and ref [32]). This is left as future work and would require MPC-based R1CS witness extension (e.g., Pianist or a port of Alex Özdemir's collaborative-zksnark to arkworks 0.4 + BN254).

### BN254 Pairing Trivial Acceptance

`DctlsVerifier.sol` accepts any proof against an all-zero verifying key (BN254 identity element). Always call `setHspMode*VK` with real circuit verifying keys before going live.

### FROST Signature Convention

`FrostVerifier.sol` uses the **even-y R convention** (BIP-340 compatible). The Schnorr challenge is:
```
e = keccak256(R_x ‖ pk_x ‖ message_hash) mod N
```
This differs from the standard FROST RFC 9591 challenge (domain-separated SHA-512). Test vectors from `gen-test-vectors` use this exact formula and are the only vectors guaranteed to verify correctly.

---

## License

See `LICENSE` file.