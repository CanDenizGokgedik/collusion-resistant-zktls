//! §IX DVRF-then-Sign benchmark — Fig. 9/10/11/12.
//!
//! Measures execution time of DKG + DVRF + TSS for varying t-of-n configurations.
//! Matches paper Fig. 9 configurations exactly.
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_dvrf_tss --release
//! ```

use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use tls_attestation_crypto::{
    dkg_secp256k1::run_secp256k1_dkg,
    dvrf_secp256k1::{Secp256k1Dvrf, Secp256k1DvrfInput},
    frost_secp256k1_adapter::{
        secp256k1_build_signing_package, secp256k1_aggregate_signature_shares,
    },
};
use tls_attestation_core::{hash::DigestBytes, ids::VerifierId};

fn make_verifier_ids(n: usize) -> Vec<VerifierId> {
    (0..n as u8).map(|i| VerifierId::from_bytes({
        let mut b = [0u8; 32]; b[0] = i; b[1] = 0xFF; b
    })).collect()
}

fn bench_one(threshold: usize, n_verifiers: usize, iters: usize) -> (u64, u64, u64) {
    let ids = make_verifier_ids(n_verifiers);
    let alpha = DigestBytes::from_bytes([0x42u8; 32]);
    let message = DigestBytes::from_bytes([0xEEu8; 32]);

    let mut dkg_total = Duration::ZERO;
    let mut dvrf_total = Duration::ZERO;
    let mut tss_total = Duration::ZERO;

    for _ in 0..iters {
        // ── DKG ──────────────────────────────────────────────────────────────
        let t0 = Instant::now();
        let dkg_outputs = run_secp256k1_dkg(&ids, threshold).expect("DKG");
        dkg_total += t0.elapsed();

        // ── DVRF ─────────────────────────────────────────────────────────────
        let t1 = Instant::now();
        let input = Secp256k1DvrfInput::new(alpha.clone());
        let partial_evals: Vec<_> = (0..threshold)
            .map(|i| Secp256k1Dvrf::partial_eval(&dkg_outputs[i].participant, &input).unwrap())
            .collect();
        let participant_refs: Vec<_> = (0..threshold).map(|i| &dkg_outputs[i].participant).collect();
        let _dvrf = Secp256k1Dvrf::combine(
            &dkg_outputs[0].group_key, &input, partial_evals, &participant_refs,
        ).unwrap();
        dvrf_total += t1.elapsed();

        // ── TSS (FROST) ───────────────────────────────────────────────────────
        let t2 = Instant::now();
        let r1_results: Vec<_> = (0..threshold)
            .map(|i| dkg_outputs[i].participant.round1(&mut OsRng).unwrap())
            .collect();
        let (nonces, commitments): (Vec<_>, Vec<_>) = r1_results.into_iter().unzip();
        let pkg = secp256k1_build_signing_package(&commitments, &message).unwrap();
        let shares: Vec<_> = nonces.into_iter().enumerate()
            .map(|(i, n)| dkg_outputs[i].participant.round2(&pkg, n).unwrap())
            .collect();
        let _approval = secp256k1_aggregate_signature_shares(
            &pkg, &shares, &dkg_outputs[0].group_key,
        ).unwrap();
        tss_total += t2.elapsed();
    }

    let n = iters as u64;
    (
        dkg_total.as_millis() as u64 / n,
        dvrf_total.as_millis() as u64 / n,
        tss_total.as_millis() as u64 / n,
    )
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Π_coll-min DVRF-then-Sign Benchmark — Paper §IX, Fig. 9        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Paper Fig. 9 exact configurations: (threshold, n_verifiers, iterations).
    // Larger configs use 1 iteration due to O(n²) DKG cost.
    let configs: &[(usize, usize, usize)] = &[
        (3,  5,  3),
        (5,  9,  3),
        (7,  13, 2),
        (10, 19, 2),
        (15, 29, 1),
        (20, 39, 1),
        (30, 59, 1),
        (50, 99, 1),
    ];

    println!("{:<12} {:>10} {:>10} {:>10} {:>12} {:>14}",
        "Config", "DKG (ms)", "DVRF (ms)", "TSS (ms)", "w/ DKG (ms)", "w/o DKG (ms)");
    println!("{}", "─".repeat(72));

    let mut results = Vec::new();
    for &(t, n, iters) in configs {
        print!("  {:<10}  running...\r", format!("{}-of-{}", t, n));
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let (dkg_ms, dvrf_ms, tss_ms) = bench_one(t, n, iters);
        let with_dkg    = dkg_ms + dvrf_ms + tss_ms;
        let without_dkg = dvrf_ms + tss_ms;

        println!("{:<12} {:>10} {:>10} {:>10} {:>12} {:>14}",
            format!("{}-of-{}", t, n), dkg_ms, dvrf_ms, tss_ms, with_dkg, without_dkg);

        results.push(serde_json::json!({
            "config":         format!("{}-of-{}", t, n),
            "dkg_ms":         dkg_ms,
            "dvrf_ms":        dvrf_ms,
            "tss_ms":         tss_ms,
            "with_dkg_ms":    with_dkg,
            "without_dkg_ms": without_dkg,
        }));
    }

    println!("\nNotes:");
    println!("  • w/ DKG  = paper Fig. 9 orange line (DKG + DVRF + TSS).");
    println!("  • w/o DKG = paper Fig. 9 blue line  (DVRF + TSS only, production path).");
    println!("  • DKG is O(n²) and runs once at network setup — not per attestation.");
    println!("  • DVRF + TSS is O(t) — scales well at high threshold sizes.");

    println!("\nJSON:");
    println!("{}", serde_json::to_string_pretty(
        &serde_json::json!({
            "benchmark":      "dvrf-tss",
            "paper_section":  "§IX",
            "paper_fig":      "Fig. 9",
            "results":        results,
        })
    ).unwrap());
}