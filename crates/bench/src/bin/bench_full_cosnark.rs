//! Full Π_coll-min pipeline benchmark with real co-SNARK (Groth16 Mode 1).
//!
//! RC Phase → dx-DCTLS (real Groth16) → FROST Sign → On-Chain ABI
//!
//! Groth16 CRS is set up once and reused across all t-of-n configurations.
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_full_cosnark --release
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
    onchain_secp256k1::OnChainAttestationSecp256k1,
    tls12_session::mock_tls12_session,
};
use tls_attestation_zk::co_snark::{CoSnarkBackend, HspProof};
use tls_attestation_zk::tls12_hmac::{ProverMacKeyShare, VerifierMacKeyShare, combine_mac_key_shares};
use tls_attestation_core::{hash::DigestBytes, ids::{SessionId, VerifierId}};

// ── Real co-SNARK executor ────────────────────────────────────────────────────

struct RealCoSnark {
    backend: CoSnarkBackend,
}

impl CoSnarkExecutor for RealCoSnark {
    fn execute(
        &self,
        p_share: &[u8; 32],
        v_share: &[u8; 32],
        rand_binding: &[u8; 32],
    ) -> Result<CoSnarkRawOutput, String> {
        let p = ProverMacKeyShare(*p_share);
        let v = VerifierMacKeyShare(*v_share);
        let k_mac = combine_mac_key_shares(&p, &v);

        let proof: HspProof = self.backend
            .execute(&p, &v, rand_binding)
            .map_err(|e| e.to_string())?;

        Ok(CoSnarkRawOutput {
            groth16_bytes:           proof.groth16_bytes,
            k_mac_commitment_bytes:  proof.k_mac_commitment_bytes,
            rand_binding_bytes:      rand_binding.to_vec(),
            k_mac:                   k_mac.0,
        })
    }
}

// ── Pipeline ─────────────────────────────────────────────────────────────────

fn run_pipeline(
    threshold: usize,
    n_verifiers: usize,
    cosnark: &RealCoSnark,
) -> (u64, u64, u64, u64) {
    let ids: Vec<VerifierId> = (0..n_verifiers as u8).map(|i| {
        VerifierId::from_bytes({ let mut b = [0u8; 32]; b[0] = i; b })
    }).collect();
    let alpha = DigestBytes::from_bytes([0x42u8; 32]);

    // ── RC Phase (DKG + DVRF) ─────────────────────────────────────────────────
    let t0 = Instant::now();
    let dkg_outputs = run_secp256k1_dkg(&ids, threshold).expect("DKG");
    let input = Secp256k1DvrfInput::new(alpha.clone());
    let partial_evals: Vec<_> = (0..threshold)
        .map(|i| Secp256k1Dvrf::partial_eval(&dkg_outputs[i].participant, &input).unwrap())
        .collect();
    let participant_refs: Vec<_> = (0..threshold)
        .map(|i| &dkg_outputs[i].participant)
        .collect();
    let dvrf_out = Secp256k1Dvrf::combine(
        &dkg_outputs[0].group_key, &input, partial_evals, &participant_refs,
    ).unwrap();
    let rand = dvrf_out.rand.clone();
    let rc_ms = t0.elapsed().as_millis() as u64;

    // ── Attestation Phase (dx-DCTLS + real Groth16) ───────────────────────────
    let t1 = Instant::now();
    let tls_session = mock_tls12_session("api.example.com", 1);
    let sid = SessionId::new_random();
    let deco_session = DecoAttestationSession::hsp(
        sid, &rand, &tls_session.server_cert_hash, cosnark,
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
    let approval = secp256k1_aggregate_signature_shares(
        &pkg, &shares, &dkg_outputs[0].group_key,
    ).unwrap();
    let sign_ms = t2.elapsed().as_millis() as u64;

    // ── On-chain ABI encoding ─────────────────────────────────────────────────
    let t3 = Instant::now();
    let mut sig_rx = [0u8; 32];
    let mut sig_s  = [0u8; 32];
    let mut gk_x   = [0u8; 32];
    let mut gk_y   = [0u8; 32];
    let sig = &approval.aggregate_signature_bytes;
    sig_rx.copy_from_slice(&sig[1..33]);
    sig_s.copy_from_slice(&sig[33..65]);
    let gk = &approval.group_verifying_key_bytes;
    gk_x.copy_from_slice(&gk[1..33]);
    let att = OnChainAttestationSecp256k1 {
        statement_digest:  [0x11u8; 32],
        dvrf_value:        *rand.as_bytes(),
        envelope_digest:   [0xEEu8; 32],
        group_key_x:       gk_x,
        group_key_y:       gk_y,
        sig_R_x:           sig_rx,
        sig_s,
        threshold:         threshold as u8,
        verifier_count:    n_verifiers as u8,
        alpha_commitment:  [0x42u8; 32],
        session_id:        [0x00u8; 32],
    };
    let encoded = att.abi_encode();
    assert_eq!(encoded.len(), 352);
    let onchain_ms = t3.elapsed().as_millis() as u64;

    (rc_ms, attest_ms, sign_ms, onchain_ms)
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Π_coll-min Full Pipeline — Real co-SNARK (Groth16 Mode 1)      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // One-time CRS setup — shared across all configs.
    print!("  Groth16 CRS setup (Mode 1, ~769 R1CS)... ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let setup_t = Instant::now();
    let backend = CoSnarkBackend::setup().expect("co-SNARK CRS setup");
    println!("{}ms", setup_t.elapsed().as_millis());

    let cosnark = RealCoSnark { backend };

    let configs: &[(usize, usize)] = &[
        (3, 5), (5, 9), (7, 13), (10, 19),
        (15, 29), (20, 39), (30, 59), (50, 99),
    ];

    println!();
    println!("{:<12} {:>10} {:>14} {:>10} {:>14} {:>11}",
        "Config", "RC (ms)", "Attest (ms)", "Sign (ms)", "OnChain (ms)", "Total (ms)");
    println!("{}", "─".repeat(75));

    let mut results = Vec::new();

    for &(t, n) in configs {
        print!("{:<12}  running...\r", format!("{}-of-{}", t, n));
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let (rc, attest, sign, onchain) = run_pipeline(t, n, &cosnark);
        let total = rc + attest + sign + onchain;

        println!("{:<12} {:>10} {:>14} {:>10} {:>14} {:>11}",
            format!("{}-of-{}", t, n), rc, attest, sign, onchain, total);

        results.push((t, n, rc, attest, sign, onchain, total));
    }

    println!();
    println!("  Notes:");
    println!("  • RC includes DKG (run once per network) + DVRF.");
    println!("  • Attest = real Groth16 Mode 1 (~769 R1CS constraints, BN254).");
    println!("  • Sign = FROST in-process (no network latency).");
    println!("  • OnChain = ABI encoding only, no EVM execution.");

    let json = serde_json::json!({
        "benchmark": "full-pipeline-cosnark",
        "co_snark_mode": "mode1",
        "r1cs_constraints": 769,
        "results": results.iter().map(|&(t, n, rc, attest, sign, onchain, total)| {
            serde_json::json!({
                "config": format!("{}-of-{}", t, n),
                "rc_ms": rc,
                "attest_ms": attest,
                "sign_ms": sign,
                "onchain_ms": onchain,
                "total_ms": total,
            })
        }).collect::<Vec<_>>(),
    });
    println!("\nJSON:\n{}", serde_json::to_string_pretty(&json).unwrap());
}