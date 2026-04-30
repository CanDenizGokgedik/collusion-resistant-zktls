//! co-SNARK Mode 2 benchmark — full TLS-PRF circuit (~1.9M R1CS, BN254).
//!
//! Measures Groth16 proof generation time for the full TLS-PRF derivation:
//!   K_MAC = TLS-PRF(Zp, "key expansion", CR||SR)[0..32]
//!
//! CRS setup is done once; proving is run per iteration.
//!
//! # Usage
//! ```bash
//! cargo run --package tls-attestation-bench --bin bench_cosnark_mode2 --release
//! ```

use std::time::Instant;
use rand::rngs::OsRng;
use tls_attestation_zk::co_snark::{CoSnarkBackend, count_r1cs_constraints};
use tls_attestation_zk::tls_prf_circuit::{TlsPrfCircuit, pms_hash};
use tls_attestation_zk::{MacKey, split_mac_key, derive_k_mac_from_pms, PreMasterSecret};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  co-SNARK Mode 2 — Full TLS-PRF Circuit (BN254/arkworks)        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // ── Constraint counts ─────────────────────────────────────────────────────
    let mode1_r1cs = count_r1cs_constraints(TlsPrfCircuit::dummy());
    let mode2_r1cs = count_r1cs_constraints(TlsPrfCircuit::dummy_full_prf());

    println!("  R1CS Constraint Counts:");
    println!("    Mode 1 (K_MAC split only):         {:>10}", mode1_r1cs);
    println!("    Mode 2 (full TLS-PRF, BN254):      {:>10}", mode2_r1cs);
    println!("    Paper target (gnark/BLS12-381):    {:>10}", 1_719_598u32);
    println!("    Delta:                             {:>9.1}%",
        (mode2_r1cs as f64 / 1_719_598.0 - 1.0) * 100.0);
    println!();

    // ── CRS setup (Mode 2) ────────────────────────────────────────────────────
    print!("  CRS setup (Mode 2, ~1.9M R1CS)... ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let t = Instant::now();
    let backend = CoSnarkBackend::setup_mode2().expect("mode2 CRS setup");
    let setup_ms = t.elapsed().as_millis();
    println!("{}ms\n", setup_ms);

    // ── Witnesses ─────────────────────────────────────────────────────────────
    let pms: Vec<u8>   = vec![0x22u8; 48];
    let client_random  = [0x01u8; 32];
    let server_random  = [0x02u8; 32];
    let rand_binding   = [0x77u8; 32];

    // Derive K_MAC natively from PMS (consistent with Mode 2 circuit).
    let pms_typed = PreMasterSecret(pms.clone().try_into().unwrap_or([0x22u8; 48]));
    let k_mac = derive_k_mac_from_pms(&pms_typed, &client_random, &server_random);
    let (p_share, v_share) = split_mac_key(&k_mac, &mut OsRng);
    let expected_pms_fe = pms_hash(&pms);

    // ── Prove + Verify iterations ─────────────────────────────────────────────
    let iterations = 3;
    let mut prove_times  = Vec::new();
    let mut verify_times = Vec::new();
    let mut proof_size   = 0usize;

    println!("  Running {} iterations...\n", iterations);

    for i in 1..=iterations {
        print!("  iter {}: prove... ", i);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let tp = Instant::now();
        let proof = backend.execute_mode2(
            &p_share, &v_share, &rand_binding,
            &pms, &client_random, &server_random,
        ).expect("mode2 execute");
        let prove_ms = tp.elapsed().as_millis() as u64;
        prove_times.push(prove_ms);
        proof_size = proof.groth16_bytes.len();

        print!("{}ms  verify... ", prove_ms);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let tv = Instant::now();
        backend.verify(&proof, Some(expected_pms_fe)).expect("mode2 verify");
        let verify_ms = tv.elapsed().as_millis() as u64;
        verify_times.push(verify_ms);

        println!("{}ms  proof_size={}B", verify_ms, proof_size);
    }

    let prove_avg  = prove_times.iter().sum::<u64>()  / prove_times.len()  as u64;
    let prove_min  = *prove_times.iter().min().unwrap();
    let prove_max  = *prove_times.iter().max().unwrap();
    let verify_avg = verify_times.iter().sum::<u64>() / verify_times.len() as u64;
    let verify_min = *verify_times.iter().min().unwrap();
    let verify_max = *verify_times.iter().max().unwrap();

    println!();
    println!("  Phase              Min(ms)   Max(ms)   Avg(ms)   Paper [19]");
    println!("  {}", "─".repeat(62));
    println!("  Prove  (Mode 1)      {:>5}     {:>5}     {:>5}       N/A",
        "~16", "~16", "~16");
    println!("  Prove  (Mode 2)   {:>7}   {:>7}   {:>7}   4,700ms (gnark)",
        prove_min, prove_max, prove_avg);
    println!("  Verify (Mode 2)   {:>7}   {:>7}   {:>7}       ~5ms",
        verify_min, verify_max, verify_avg);
    println!("  Proof size:       {} bytes", proof_size);

    println!();
    println!("  Notes:");
    println!("  • BN254/arkworks is ~2× slower than gnark/BLS12-381 used in paper.");
    println!("  • Verify is fast (~{}ms) regardless of mode — aux verifiers are cheap.",
        verify_avg);

    let json = serde_json::json!({
        "benchmark": "cosnark-mode2",
        "r1cs_mode1": mode1_r1cs,
        "r1cs_mode2": mode2_r1cs,
        "r1cs_paper": 1_719_598u32,
        "crs_setup_ms": setup_ms,
        "prove_min_ms": prove_min,
        "prove_max_ms": prove_max,
        "prove_avg_ms": prove_avg,
        "verify_avg_ms": verify_avg,
        "proof_size_bytes": proof_size,
        "paper_prove_ms": 4700,
    });
    println!("\nJSON:\n{}", serde_json::to_string_pretty(&json).unwrap());
}