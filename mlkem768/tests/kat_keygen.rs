//! Real ML-KEM-768 (FIPS 203) known-answer tests, verified byte-for-byte.
//!
//! `EK` here is the genuine NIST ACVP keyGen KAT vector (tgId=2,
//! tcId=26, parameterSet="ML-KEM-768"), fetched from
//! github.com/usnistgov/ACVP-Server on 2026-09-09. `DK`/`M`/`K`/`C` are
//! computed with `kyber-py` (an independent, pure-Python FIPS 203
//! implementation) from the same seed, giving full keygen/encaps/decaps
//! coverage. See `kat_vectors.txt` for provenance and how to regenerate.
//!
//! Root cause of the historical mismatch (fixed in mlkem768/src/lib.rs):
//! 1. `K-PKE.KeyGen` must expand `(rho, sigma) = G(d || k)` (the 32-byte
//!    seed with the module rank k=3 appended as one byte) -- the code was
//!    hashing `d` alone, a different domain-separation input entirely.
//! 2. The uniform-matrix XOF seed order was backwards: FIPS 203 builds
//!    the untransposed matrix as `A[i][j] = SampleNTT(XOF(rho, j, i))`
//!    (note the swapped `j, i`) and the transposed matrix as
//!    `A^T[i][j] = SampleNTT(XOF(rho, i, j))`; the code had these two
//!    swapped.
//! Both are visible in the "classic Kyber/FIPS-203 mismatch" categories
//! (seed expansion; XOF domain separation for matrix generation).

include!("kat_common.rs");

#[test]
fn nist_acvp_mlkem768_keygen_tcid26() {
    let v = KatVectors::load();
    let (ek, dk) = mlkem768::keygen_from_seed(&v.d, &v.z);
    assert_eq!(ek.0.len(), 1184);
    assert_eq!(dk.0.len(), 2400);
    assert_eq!(
        ek.0, v.ek,
        "encapsulation key must match the real NIST ACVP ML-KEM-768 keyGen KAT (tgId=2, tcId=26) byte-for-byte"
    );
    assert_eq!(
        dk.0, v.dk,
        "decapsulation key must match the independently-computed (kyber-py) reference byte-for-byte"
    );
}

#[test]
fn kat_encaps_matches_reference() {
    let v = KatVectors::load();
    let (ek, _dk) = mlkem768::keygen_from_seed(&v.d, &v.z);
    let (ct, ss) = mlkem768::encaps_with_randomness(&ek, &v.m);
    assert_eq!(ct.0, v.c, "ciphertext must match the reference encaps KAT byte-for-byte");
    assert_eq!(ss.0, v.k, "shared secret from encaps must match the reference KAT");
}

#[test]
fn kat_decaps_matches_reference() {
    let v = KatVectors::load();
    let (_ek, dk) = mlkem768::keygen_from_seed(&v.d, &v.z);
    let ct = mlkem768::Ciphertext(v.c.clone());
    let ss = mlkem768::decaps(&dk, &ct);
    assert_eq!(ss.0, v.k, "shared secret from decaps must match the reference KAT");
}
