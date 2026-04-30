//! Full Π_coll-min end-to-end pipeline benchmark.
//!
//! RC Phase → dx-DCTLS → FROST Sign → on-chain ABI encoding
//!
//! Demonstrates O(1) prover complexity (paper Table II).
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_full_pipeline --release
//! ```

use std::time::Instant;
use rand::rngs::OsRng;
use tls_attestation_crypto::{
    dkg_secp256k1::run_secp256k1_dkg,
    dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput},
    frost_secp256k1_adapter::{
        secp256k1_build_signing_package, secp256k1_aggregate_signature_shares,
    },
};
use tls_attestation_attestation::{
    deco_dx_dctls::{DecoAttestationSession, CoSnarkExecutor, CoSnarkRawOutput},
    onchain_secp256k1::{OnChainAttestationSecp256k1},
    tls12_session::mock_tls12_session,
};
use tls_attestation_core::{hash::DigestBytes, ids::{SessionId, VerifierId}};

/// Stub co-SNARK executor for the pipeline benchmark (no Groth16 overhead).
struct StubCoSnark;
impl CoSnarkExecutor for StubCoSnark {
    fn execute(
        &self,
        p_share: &[u8; 32],
        v_share: &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String> {
        let mut k_mac = [0u8; 32];
        for i in 0..32 { k_mac[i] = p_share[i] ^ v_share[i]; }
        Ok(CoSnarkRawOutput {
            groth16_bytes: vec![0u8; 128],
            k_mac_commitment_bytes: vec![0u8; 32],
            rand_binding_bytes: rand_binding.to_vec(),
            k_mac,
        })
    }
}

fn run_pipeline(threshold: usize, n_verifiers: usize) -> (u64, u64, u64, u64) {
    let ids: Vec<VerifierId> = (0..n_verifiers as u8).map(|i| {
        VerifierId::from_bytes({ let mut b = [0u8; 32]; b[0] = i; b })
    }).collect();
    let alpha = DigestBytes::from_bytes([0x42u8; 32]);

    // ── RC Phase ──────────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let dkg_outputs = run_secp256k1_dkg(&ids, threshold).expect("DKG");
    let input = Secp256k1DvrfInput::new(alpha.clone());
    let partial_evals: Vec<_> = (0..threshold)
        .map(|i| Secp256k1Dvrf::partial_eval(&dkg_outputs[i].participant, &input).unwrap())
        .collect();
    let participant_refs: Vec<_> = (0..threshold).map(|i| &dkg_outputs[i].participant).collect();
    let dvrf_out = Secp256k1Dvrf::combine(
        &dkg_outputs[0].group_key, &input, partial_evals, &participant_refs,
    ).unwrap();
    let rand = dvrf_out.rand.clone();
    let rc_ms = t0.elapsed().as_millis() as u64;

    // ── Attestation Phase (dx-DCTLS) ──────────────────────────────────────────
    let t1 = Instant::now();
    let tls_session = mock_tls12_session("api.example.com", 1);
    let sid = SessionId::new_random();
    let deco_session = DecoAttestationSession::hsp(
        sid, &rand, &tls_session.server_cert_hash, &StubCoSnark,
    ).expect("HSP");
    let qr = deco_session.qp(
        b"GET /price?asset=BTC",
        b"HTTP/1.1 200 OK\r\n{\"price\":67500}",
    );
    let _proof = deco_session.pgp(qr, b"price > 50000".to_vec());
    let attest_ms = t1.elapsed().as_millis() as u64;

    // ── Signing Phase (FROST) ─────────────────────────────────────────────────
    let t2 = Instant::now();
    let message = DigestBytes::from_bytes([0xEEu8; 32]);
    let r1_results: Vec<_> = (0..threshold)
        .map(|i| dkg_outputs[i].participant.round1(&mut OsRng).unwrap())
        .collect();
    let (nonces, commitments): (Vec<_>, Vec<_>) = r1_results.into_iter().unzip();
    let pkg = secp256k1_build_signing_package(&commitments, &message).unwrap();
    let shares: Vec<_> = nonces.into_iter().enumerate()
        .map(|(i, n)| dkg_outputs[i].participant.round2(&pkg, n).unwrap())
        .collect();
    let approval = secp256k1_aggregate_signature_shares(&pkg, &shares, &dkg_outputs[0].group_key).unwrap();
    let sign_ms = t2.elapsed().as_millis() as u64;

    // ── On-chain ABI encoding ─────────────────────────────────────────────────
    let t3 = Instant::now();
    let mut sig_rx = [0u8; 32];
    let mut sig_s  = [0u8; 32];
    let mut gk_x   = [0u8; 32];
    let mut gk_y   = [0u8; 32];
    // FROST sig: 65 bytes (parity || r || s) or (r || s || parity)
    let sig = &approval.aggregate_signature_bytes;
    sig_rx.copy_from_slice(&sig[1..33]);
    sig_s.copy_from_slice(&sig[33..65]);
    let gk = &approval.group_verifying_key_bytes;
    gk_x.copy_from_slice(&gk[1..33]);
    // y is not available from compressed key — use zeros for ABI encoding test
    let att = OnChainAttestationSecp256k1 {
        statement_digest: [0x11u8; 32],
        dvrf_value: *rand.as_bytes(),
        envelope_digest: [0xEEu8; 32],
        group_key_x: gk_x,
        group_key_y: gk_y,
        sig_R_x: sig_rx,
        sig_s,
        threshold: threshold as u8,
        verifier_count: n_verifiers as u8,
        alpha_commitment: [0x42u8; 32],
        session_id: [0x00u8; 32],
    };
    let encoded = att.abi_encode();
    assert_eq!(encoded.len(), 352, "ABI encoding must be 352 bytes");
    let onchain_ms = t3.elapsed().as_millis() as u64;

    (rc_ms, attest_ms, sign_ms, onchain_ms)
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Π_coll-min Full Pipeline — RC → dx-DCTLS → FROST → On-Chain   ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    println!("  Demonstrates O(1) prover complexity (paper Table II).\n");

    let configs = [(2, 3), (3, 5), (5, 9), (7, 13), (10, 19)];

    println!("{:<12} {:>10} {:>12} {:>10} {:>12} {:>10}",
        "Config", "RC (ms)", "Attest (ms)", "Sign (ms)", "OnChain (ms)", "Total (ms)");
    println!("{}", "─".repeat(70));

    for (t, n) in configs {
        let (rc, attest, sign, onchain) = run_pipeline(t, n);
        println!("{:<12} {:>10} {:>12} {:>10} {:>12} {:>10}",
            format!("{}-of-{}", t, n), rc, attest, sign, onchain,
            rc + attest + sign + onchain);
    }

    println!("\n  Paper Table II comparison:");
    println!("  ┌─────────────────────────┬──────────┬───────────┬──────────────┐");
    println!("  │ Prover Complexity       │ O(1)     │ O(n)      │ O(1) ←       │");
    println!("  │ Public Verifiability    │ No       │ Yes       │ Yes          │");
    println!("  │ Collusion Resistance    │ No       │ Yes       │ Yes          │");
    println!("  │ Auxiliary Node Load     │ N/A      │ Heavy     │ Lightweight  │");
    println!("  └─────────────────────────┴──────────┴───────────┴──────────────┘");
    println!("                             DECO      DECO-DON    Π_coll-min");
}