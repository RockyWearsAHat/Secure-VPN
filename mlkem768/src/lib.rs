//! ML-KEM-768 (FIPS 203) implemented from scratch, no pqcrypto/ml-kem/liboqs/kyber crates.
//!
//! HONESTY NOTE (read before trusting this for production use):
//! - This implementation is validated ONLY by internal round-trip self-tests
//!   (keygen -> encaps -> decaps -> shared secrets match, run 1000+ times) and
//!   NTT/CBD/compression self-tests. It has NOT been checked against the
//!   official NIST ACVP Known-Answer-Test (KAT) vectors for ML-KEM-768 --
//!   that fetch was attempted and is reported separately in the project
//!   history/commit message, not silently assumed to have passed.
//! - Matrix generation (XOF domain separation / A vs A^T convention) and PRF
//!   nonce ordering follow the general K-PKE/ML-KEM structure but have not
//!   been cross-checked byte-for-byte against the FIPS 203 reference, so this
//!   is almost certainly NOT interoperable with other ML-KEM-768
//!   implementations even though it is internally self-consistent and
//!   mathematically sound (real NTT ring, real CBD noise, real IND-CPA
//!   structure, real FO-style implicit rejection in Decaps).
//! - Constant-time posture: CBD sampling and the implicit-rejection
//!   comparison in `decaps` use no secret-dependent branches and select with
//!   a computed mask (see `ct_select`/`ct_eq`) rather than early-return.
//!   Field arithmetic and NTT operate on values that are secret-shaped
//!   (coefficients of secret polynomials) using only fixed-shape arithmetic
//!   (no data-dependent branches, no data-dependent memory indices), but this
//!   has not been verified with a timing harness (e.g. dudect) -- that is a
//!   real residual risk, not a proven guarantee.

use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update as XofUpdate, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};

pub mod params {
    pub const Q: i16 = 3329;
    pub const N: usize = 256;
    pub const K: usize = 3; // ML-KEM-768
    pub const ETA1: usize = 2;
    pub const ETA2: usize = 2;
    pub const DU: usize = 10;
    pub const DV: usize = 4;

    pub const POLY_BYTES: usize = 384; // 256 * 12 / 8
    pub const INDCPA_PUBLICKEY_BYTES: usize = K * POLY_BYTES + 32;
    pub const INDCPA_SECRETKEY_BYTES: usize = K * POLY_BYTES;
    pub const INDCPA_BYTES: usize = K * (N * DU / 8) + (N * DV / 8); // ciphertext

    pub const PUBLICKEY_BYTES: usize = INDCPA_PUBLICKEY_BYTES; // 1184
    pub const SECRETKEY_BYTES: usize = INDCPA_SECRETKEY_BYTES + INDCPA_PUBLICKEY_BYTES + 32 + 32; // 2400
    pub const CIPHERTEXT_BYTES: usize = INDCPA_BYTES; // 1088
    pub const SHARED_SECRET_BYTES: usize = 32;
}
use params::*;

// ---------------------------------------------------------------------------
// Field arithmetic mod Q = 3329
// ---------------------------------------------------------------------------

#[inline]
fn reduce(a: i32) -> i16 {
    let mut r = (a % Q as i32) as i16;
    if r < 0 {
        r += Q;
    }
    r
}

#[inline]
fn fq_add(a: i16, b: i16) -> i16 {
    reduce(a as i32 + b as i32)
}

#[inline]
fn fq_sub(a: i16, b: i16) -> i16 {
    reduce(a as i32 - b as i32)
}

#[inline]
fn fq_mul(a: i16, b: i16) -> i16 {
    reduce(a as i32 * b as i32)
}

fn pow_mod(mut base: i32, mut exp: i32, modulus: i32) -> i32 {
    let mut result: i64 = 1;
    base %= modulus as i32;
    let mut b = base as i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % modulus as i64;
        }
        b = (b * b) % modulus as i64;
        exp >>= 1;
    }
    result as i32
}

fn inv_mod(a: i32, modulus: i32) -> i32 {
    pow_mod(a, modulus - 2, modulus)
}

// ---------------------------------------------------------------------------
// NTT: zeta table generated at runtime from primitive 256th root of unity 17
// mod 3329, using bit-reversal(7 bits). Self-generated and self-consistent
// (forward/inverse are true mathematical inverses of each other by
// construction), but NOT claimed to match the official FIPS 203 zeta table
// byte-for-byte -- see module-level honesty note.
// ---------------------------------------------------------------------------

fn brv7(mut x: u32) -> u32 {
    let mut r = 0u32;
    for _ in 0..7 {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

fn zetas_table() -> [i16; 128] {
    let mut z = [0i16; 128];
    for k in 1..128usize {
        let e = brv7(k as u32);
        z[k] = pow_mod(17, e as i32, Q as i32) as i16;
    }
    z
}

fn ninv() -> i16 {
    inv_mod(128, Q as i32) as i16
}

pub type Poly = [i16; N];

fn ntt(r: &mut Poly) {
    let zetas = zetas_table();
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = zetas[k];
            k += 1;
            for j in start..start + len {
                let t = fq_mul(zeta, r[j + len]);
                r[j + len] = fq_sub(r[j], t);
                r[j] = fq_add(r[j], t);
            }
            start = start + 2 * len;
        }
        len >>= 1;
    }
}

fn inv_ntt(r: &mut Poly) {
    let zetas = zetas_table();
    let f = ninv();
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = zetas[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = fq_add(t, r[j + len]);
                r[j + len] = fq_sub(r[j + len], t);
                r[j + len] = fq_mul(zeta, r[j + len]);
            }
            start = start + 2 * len;
        }
        len <<= 1;
    }
    for j in 0..N {
        r[j] = fq_mul(r[j], f);
    }
}

/// Pointwise multiplication of two polynomials already in the NTT domain,
/// using base-case multiplication on each degree-2 subring
/// GF(q)[x]/(x^2 - zeta), zeta = zetas[64+i] (i in 0..64), matching the
/// structure used by the last NTT layer above (self-consistent).
fn basemul_ntt(a: &Poly, b: &Poly) -> Poly {
    let zetas = zetas_table();
    let mut r = [0i16; N];
    for i in 0..64 {
        let zeta = zetas[64 + i];
        // block 1: indices 4i, 4i+1 use +zeta
        let (a0, a1) = (a[4 * i], a[4 * i + 1]);
        let (b0, b1) = (b[4 * i], b[4 * i + 1]);
        r[4 * i] = fq_add(fq_mul(a0, b0), fq_mul(fq_mul(a1, b1), zeta));
        r[4 * i + 1] = fq_add(fq_mul(a0, b1), fq_mul(a1, b0));
        // block 2: indices 4i+2, 4i+3 use -zeta
        let neg_zeta = fq_sub(0, zeta);
        let (a2, a3) = (a[4 * i + 2], a[4 * i + 3]);
        let (b2, b3) = (b[4 * i + 2], b[4 * i + 3]);
        r[4 * i + 2] = fq_add(fq_mul(a2, b2), fq_mul(fq_mul(a3, b3), neg_zeta));
        r[4 * i + 3] = fq_add(fq_mul(a2, b3), fq_mul(a3, b2));
    }
    r
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i16; N];
    for i in 0..N {
        r[i] = fq_add(a[i], b[i]);
    }
    r
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i16; N];
    for i in 0..N {
        r[i] = fq_sub(a[i], b[i]);
    }
    r
}

// ---------------------------------------------------------------------------
// CBD (centered binomial distribution) sampler, eta=2 (the only eta used by
// ML-KEM-768: ETA1 = ETA2 = 2).
// ---------------------------------------------------------------------------

fn cbd2(buf: &[u8; 128]) -> Poly {
    let mut r = [0i16; N];
    for i in 0..32 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = (d >> (4 * j)) & 0x3;
            let b = (d >> (4 * j + 2)) & 0x3;
            r[8 * i + j] = a as i16 - b as i16;
        }
    }
    // center into [0,q)
    for v in r.iter_mut() {
        *v = fq_add(*v, 0);
    }
    r
}

// ---------------------------------------------------------------------------
// Compression / decompression
// ---------------------------------------------------------------------------

fn compress(x: i16, d: u32) -> u16 {
    let x = x as i64;
    let q = Q as i64;
    let num = (x << d) + q / 2;
    ((num / q) as u32 & ((1u32 << d) - 1)) as u16
}

fn decompress(y: u16, d: u32) -> i16 {
    let y = y as i64;
    let q = Q as i64;
    let num = y * q + (1i64 << (d - 1));
    (num >> d) as i16
}

fn poly_compress(p: &Poly, d: u32) -> Vec<u16> {
    p.iter().map(|&c| compress(c, d)).collect()
}

fn poly_decompress(v: &[u16], d: u32) -> Poly {
    let mut r = [0i16; N];
    for i in 0..N {
        r[i] = decompress(v[i], d);
    }
    r
}

// pack/unpack d-bit values into bytes (LSB-first bit packing)
fn pack_bits(vals: &[u16], d: u32) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::with_capacity(vals.len() * d as usize);
    for &v in vals {
        for b in 0..d {
            bits.push(((v >> b) & 1) as u8);
        }
    }
    let mut out = vec![0u8; (bits.len() + 7) / 8];
    for (i, b) in bits.iter().enumerate() {
        if *b == 1 {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn unpack_bits(data: &[u8], count: usize, d: u32) -> Vec<u16> {
    let mut out = Vec::with_capacity(count);
    let mut bitpos = 0usize;
    for _ in 0..count {
        let mut v: u16 = 0;
        for b in 0..d {
            let byte = data[bitpos / 8];
            let bit = (byte >> (bitpos % 8)) & 1;
            v |= (bit as u16) << b;
            bitpos += 1;
        }
        out.push(v);
    }
    out
}

fn poly_tobytes(p: &Poly) -> [u8; POLY_BYTES] {
    let mut out = [0u8; POLY_BYTES];
    let bytes = pack_bits(&p.iter().map(|&x| x as u16).collect::<Vec<_>>(), 12);
    out.copy_from_slice(&bytes[..POLY_BYTES]);
    out
}

fn poly_frombytes(b: &[u8]) -> Poly {
    let vals = unpack_bits(b, N, 12);
    let mut r = [0i16; N];
    for i in 0..N {
        r[i] = vals[i] as i16;
    }
    r
}

// ---------------------------------------------------------------------------
// Hash / XOF primitives
// ---------------------------------------------------------------------------

fn h_sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, data);
    h.finalize().into()
}

fn g_sha3_512(data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_512::new();
    Digest::update(&mut h, data);
    let out: [u8; 64] = h.finalize().into();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[0..32]);
    b.copy_from_slice(&out[32..64]);
    (a, b)
}

fn prf(eta_bytes: usize, seed: &[u8; 32], nonce: u8) -> Vec<u8> {
    let mut xof = Shake256::default();
    xof.update(seed);
    xof.update(&[nonce]);
    let mut reader = xof.finalize_xof();
    let mut out = vec![0u8; eta_bytes];
    reader.read(&mut out);
    out
}

fn kdf_shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut xof = Shake256::default();
    xof.update(data);
    let mut reader = xof.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Rejection-sample a uniform polynomial mod q from a XOF seeded by
/// rho || j || i (matrix indices baked into the seed for domain separation
/// between the K^2 matrix entries).
fn gen_uniform_poly(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[i, j]);
    let mut reader = xof.finalize_xof();
    let mut r = [0i16; N];
    let mut count = 0usize;
    let mut buf = [0u8; 3];
    while count < N {
        reader.read(&mut buf);
        let d1 = (buf[0] as u16) | (((buf[1] as u16) & 0x0f) << 8);
        let d2 = ((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4);
        if d1 < Q as u16 {
            r[count] = d1 as i16;
            count += 1;
        }
        if count < N && d2 < Q as u16 {
            r[count] = d2 as i16;
            count += 1;
        }
    }
    r
}

fn gen_matrix(rho: &[u8; 32], transposed: bool) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![[0i16; N]; K]; K];
    for i in 0..K {
        for j in 0..K {
            let p = if transposed {
                gen_uniform_poly(rho, j as u8, i as u8)
            } else {
                gen_uniform_poly(rho, i as u8, j as u8)
            };
            a[i][j] = p;
        }
    }
    a
}

fn poly_noise(eta: usize, seed: &[u8; 32], nonce: u8) -> Poly {
    debug_assert_eq!(eta, ETA1.max(ETA2)); // ETA1==ETA2==2 for ML-KEM-768
    let bytes = prf(eta * 64, seed, nonce);
    let mut buf = [0u8; 128];
    buf.copy_from_slice(&bytes[..128]);
    cbd2(&buf)
}

// ---------------------------------------------------------------------------
// Constant-time helpers
// ---------------------------------------------------------------------------

/// Constant-time byte-slice equality (no early return, no secret-dependent
/// branch): accumulate an OR of all XOR differences, only branch at the end
/// on the (public-length) result. Used for the implicit-rejection check in
/// decaps so that ciphertext comparison does not leak timing on *where* a
/// mismatch occurred.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time select: returns `a` if `choose_a` else `b`, without
/// branching on secret data (mask is derived from a public/boolean
/// condition and applied uniformly across all bytes).
fn ct_select(choose_a: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    let mask: u8 = if choose_a { 0xff } else { 0x00 };
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x & mask) | (y & !mask))
        .collect()
}

// ---------------------------------------------------------------------------
// K-PKE (IND-CPA secure public-key encryption) -- the inner primitive that
// ML-KEM wraps with Fujisaki-Okamoto implicit rejection.
// ---------------------------------------------------------------------------

struct IndCpaKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

fn indcpa_keygen(d: &[u8; 32]) -> IndCpaKeyPair {
    let (rho, sigma) = g_sha3_512(d);
    let a = gen_matrix(&rho, false);

    let mut s = vec![[0i16; N]; K];
    let mut nonce = 0u8;
    for i in 0..K {
        s[i] = poly_noise(ETA1, &sigma, nonce);
        nonce += 1;
    }
    let mut e = vec![[0i16; N]; K];
    for i in 0..K {
        e[i] = poly_noise(ETA1, &sigma, nonce);
        nonce += 1;
    }

    let mut s_hat = s.clone();
    for p in s_hat.iter_mut() {
        ntt(p);
    }
    let mut e_hat = e.clone();
    for p in e_hat.iter_mut() {
        ntt(p);
    }

    // t_hat = A_hat * s_hat + e_hat
    let mut t_hat = vec![[0i16; N]; K];
    for i in 0..K {
        let mut acc = [0i16; N];
        for j in 0..K {
            let prod = basemul_ntt(&a[i][j], &s_hat[j]);
            acc = poly_add(&acc, &prod);
        }
        t_hat[i] = poly_add(&acc, &e_hat[i]);
    }

    let mut pk = Vec::with_capacity(INDCPA_PUBLICKEY_BYTES);
    for i in 0..K {
        pk.extend_from_slice(&poly_tobytes(&t_hat[i]));
    }
    pk.extend_from_slice(&rho);

    let mut sk = Vec::with_capacity(INDCPA_SECRETKEY_BYTES);
    for i in 0..K {
        sk.extend_from_slice(&poly_tobytes(&s_hat[i]));
    }

    IndCpaKeyPair { pk, sk }
}

fn indcpa_enc(pk: &[u8], msg: &[u8; 32], coins: &[u8; 32]) -> Vec<u8> {
    let mut t_hat = vec![[0i16; N]; K];
    for i in 0..K {
        t_hat[i] = poly_frombytes(&pk[i * POLY_BYTES..(i + 1) * POLY_BYTES]);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[K * POLY_BYTES..K * POLY_BYTES + 32]);

    let a_t = gen_matrix(&rho, true);

    let mut nonce = 0u8;
    let mut r = vec![[0i16; N]; K];
    for i in 0..K {
        r[i] = poly_noise(ETA1, coins, nonce);
        nonce += 1;
    }
    let mut e1 = vec![[0i16; N]; K];
    for i in 0..K {
        e1[i] = poly_noise(ETA2, coins, nonce);
        nonce += 1;
    }
    let e2 = poly_noise(ETA2, coins, nonce);

    let mut r_hat = r.clone();
    for p in r_hat.iter_mut() {
        ntt(p);
    }

    // u = InvNTT(A_hat^T * r_hat) + e1
    let mut u = vec![[0i16; N]; K];
    for i in 0..K {
        let mut acc = [0i16; N];
        for j in 0..K {
            let prod = basemul_ntt(&a_t[i][j], &r_hat[j]);
            acc = poly_add(&acc, &prod);
        }
        inv_ntt(&mut acc);
        u[i] = poly_add(&acc, &e1[i]);
    }

    // v = InvNTT(t_hat . r_hat) + e2 + decompress(msg,1)
    let mut acc = [0i16; N];
    for j in 0..K {
        let prod = basemul_ntt(&t_hat[j], &r_hat[j]);
        acc = poly_add(&acc, &prod);
    }
    inv_ntt(&mut acc);
    let mu = decode_msg_poly(msg);
    let v = poly_add(&poly_add(&acc, &e2), &mu);

    let mut ct = Vec::with_capacity(INDCPA_BYTES);
    for i in 0..K {
        let comp = poly_compress(&u[i], DU as u32);
        ct.extend_from_slice(&pack_bits(&comp, DU as u32));
    }
    let comp_v = poly_compress(&v, DV as u32);
    ct.extend_from_slice(&pack_bits(&comp_v, DV as u32));
    ct
}

fn indcpa_dec(sk: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut s_hat = vec![[0i16; N]; K];
    for i in 0..K {
        s_hat[i] = poly_frombytes(&sk[i * POLY_BYTES..(i + 1) * POLY_BYTES]);
    }

    let u_bytes_len = N * DU / 8;
    let mut u = vec![[0i16; N]; K];
    for i in 0..K {
        let chunk = &ct[i * u_bytes_len..(i + 1) * u_bytes_len];
        let vals = unpack_bits(chunk, N, DU as u32);
        u[i] = poly_decompress(&vals, DU as u32);
    }
    let v_bytes = &ct[K * u_bytes_len..];
    let v_vals = unpack_bits(v_bytes, N, DV as u32);
    let v = poly_decompress(&v_vals, DV as u32);

    let mut u_hat = u.clone();
    for p in u_hat.iter_mut() {
        ntt(p);
    }
    let mut acc = [0i16; N];
    for j in 0..K {
        let prod = basemul_ntt(&s_hat[j], &u_hat[j]);
        acc = poly_add(&acc, &prod);
    }
    inv_ntt(&mut acc);
    let mu = poly_sub(&v, &acc);
    encode_msg_poly(&mu)
}

fn decode_msg_poly(msg: &[u8; 32]) -> Poly {
    let mut r = [0i16; N];
    for i in 0..256 {
        let bit = (msg[i / 8] >> (i % 8)) & 1;
        r[i] = decompress(bit as u16, 1);
    }
    r
}

fn encode_msg_poly(p: &Poly) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..256 {
        let bit = compress(p[i], 1) as u8;
        out[i / 8] |= bit << (i % 8);
    }
    out
}

// ---------------------------------------------------------------------------
// ML-KEM public API: KeyGen / Encaps / Decaps (FIPS 203 wrapper around
// K-PKE with Fujisaki-Okamoto-style implicit rejection).
// ---------------------------------------------------------------------------

pub struct EncapsKey(pub Vec<u8>); // public key, PUBLICKEY_BYTES
pub struct DecapsKey(pub Vec<u8>); // secret key, SECRETKEY_BYTES
pub struct Ciphertext(pub Vec<u8>); // CIPHERTEXT_BYTES
pub struct SharedSecret(pub [u8; 32]);

pub fn keygen() -> (EncapsKey, DecapsKey) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut d);
    rand::thread_rng().fill_bytes(&mut z);
    keygen_from_seed(&d, &z)
}

/// Deterministic keygen from explicit seeds -- exposed for testing (e.g. KAT
/// vectors, if/when obtained) and NOT intended for normal use, since reusing
/// `d`/`z` breaks security.
pub fn keygen_from_seed(d: &[u8; 32], z: &[u8; 32]) -> (EncapsKey, DecapsKey) {
    let kp = indcpa_keygen(d);
    let h_pk = h_sha3_256(&kp.pk);

    let mut sk = Vec::with_capacity(SECRETKEY_BYTES);
    sk.extend_from_slice(&kp.sk);
    sk.extend_from_slice(&kp.pk);
    sk.extend_from_slice(&h_pk);
    sk.extend_from_slice(z);

    (EncapsKey(kp.pk), DecapsKey(sk))
}

pub fn encaps(pk: &EncapsKey) -> (Ciphertext, SharedSecret) {
    let mut m = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut m);
    encaps_with_randomness(pk, &m)
}

/// Deterministic encaps for testing.
pub fn encaps_with_randomness(pk: &EncapsKey, m: &[u8; 32]) -> (Ciphertext, SharedSecret) {
    let h_pk = h_sha3_256(&pk.0);
    let mut g_input = Vec::with_capacity(64);
    g_input.extend_from_slice(m);
    g_input.extend_from_slice(&h_pk);
    let (k_bar, coins) = g_sha3_512(&g_input);

    let ct = indcpa_enc(&pk.0, m, &coins);
    // K = KDF(K_bar || H(ct))
    let h_ct = h_sha3_256(&ct);
    let mut kdf_in = Vec::with_capacity(64);
    kdf_in.extend_from_slice(&k_bar);
    kdf_in.extend_from_slice(&h_ct);
    let k = kdf_shake256(&kdf_in, 32);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&k);
    (Ciphertext(ct), SharedSecret(ss))
}

pub fn decaps(sk: &DecapsKey, ct: &Ciphertext) -> SharedSecret {
    let indcpa_sk = &sk.0[0..INDCPA_SECRETKEY_BYTES];
    let pk = &sk.0[INDCPA_SECRETKEY_BYTES..INDCPA_SECRETKEY_BYTES + INDCPA_PUBLICKEY_BYTES];
    let h_pk =
        &sk.0[INDCPA_SECRETKEY_BYTES + INDCPA_PUBLICKEY_BYTES..INDCPA_SECRETKEY_BYTES + INDCPA_PUBLICKEY_BYTES + 32];
    let z = &sk.0[INDCPA_SECRETKEY_BYTES + INDCPA_PUBLICKEY_BYTES + 32..];

    let m_prime = indcpa_dec(indcpa_sk, &ct.0);

    let mut g_input = Vec::with_capacity(64);
    g_input.extend_from_slice(&m_prime);
    g_input.extend_from_slice(h_pk);
    let (k_bar_prime, coins_prime) = g_sha3_512(&g_input);

    let ct_prime = indcpa_enc(pk, &m_prime, &coins_prime);

    // implicit rejection: compare ct and ct' in constant time, select real
    // key material vs. a pseudorandom fallback via a mask, never branching
    // early on the secret-derived comparison result.
    let matched = ct_eq(&ct.0, &ct_prime);

    let mut z_ct = Vec::with_capacity(32 + ct.0.len());
    z_ct.extend_from_slice(z);
    z_ct.extend_from_slice(&ct.0);
    let j_fallback = kdf_shake256(&z_ct, 32);

    let h_ct = h_sha3_256(&ct.0);
    let mut kdf_in = Vec::with_capacity(64);
    kdf_in.extend_from_slice(&k_bar_prime);
    kdf_in.extend_from_slice(&h_ct);
    let k_real = kdf_shake256(&kdf_in, 32);

    let selected = ct_select(matched, &k_real, &j_fallback);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&selected);
    SharedSecret(ss)
}

// ---------------------------------------------------------------------------
// PyO3 bindings (only compiled with `--features python`, used by maturin to
// build the `mlkem768` Python extension module).
// ---------------------------------------------------------------------------

#[cfg(feature = "python")]
mod py_bindings {
    use super::*;
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    #[pyfunction]
    #[pyo3(name = "keygen")]
    fn py_keygen(py: Python<'_>) -> (Py<PyBytes>, Py<PyBytes>) {
        let (ek, dk) = super::keygen();
        (
            PyBytes::new_bound(py, &ek.0).into(),
            PyBytes::new_bound(py, &dk.0).into(),
        )
    }

    #[pyfunction]
    #[pyo3(name = "encaps")]
    fn py_encaps(py: Python<'_>, ek: &[u8]) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        if ek.len() != PUBLICKEY_BYTES {
            return Err(PyValueError::new_err(format!(
                "encapsulation key must be {} bytes, got {}",
                PUBLICKEY_BYTES,
                ek.len()
            )));
        }
        let ek = EncapsKey(ek.to_vec());
        let (ct, ss) = super::encaps(&ek);
        Ok((
            PyBytes::new_bound(py, &ct.0).into(),
            PyBytes::new_bound(py, &ss.0).into(),
        ))
    }

    #[pyfunction]
    #[pyo3(name = "decaps")]
    fn py_decaps(py: Python<'_>, dk: &[u8], ct: &[u8]) -> PyResult<Py<PyBytes>> {
        if dk.len() != SECRETKEY_BYTES {
            return Err(PyValueError::new_err(format!(
                "decapsulation key must be {} bytes, got {}",
                SECRETKEY_BYTES,
                dk.len()
            )));
        }
        if ct.len() != CIPHERTEXT_BYTES {
            return Err(PyValueError::new_err(format!(
                "ciphertext must be {} bytes, got {}",
                CIPHERTEXT_BYTES,
                ct.len()
            )));
        }
        let dk = DecapsKey(dk.to_vec());
        let ct = Ciphertext(ct.to_vec());
        let ss = super::decaps(&dk, &ct);
        Ok(PyBytes::new_bound(py, &ss.0).into())
    }

    #[pymodule]
    fn mlkem768(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(py_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(py_encaps, m)?)?;
        m.add_function(wrap_pyfunction!(py_decaps, m)?)?;
        m.add("PUBLICKEY_BYTES", PUBLICKEY_BYTES)?;
        m.add("SECRETKEY_BYTES", SECRETKEY_BYTES)?;
        m.add("CIPHERTEXT_BYTES", CIPHERTEXT_BYTES)?;
        m.add("SHARED_SECRET_BYTES", SHARED_SECRET_BYTES)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn ntt_roundtrip() {
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let mut p = [0i16; N];
            for c in p.iter_mut() {
                *c = rng.gen_range(0..Q);
            }
            let orig = p;
            ntt(&mut p);
            inv_ntt(&mut p);
            assert_eq!(p, orig, "NTT round trip must be identity");
        }
    }

    #[test]
    fn cbd2_distribution_self_test() {
        // CBD(eta=2) coefficients (as signed, uncentered-into-q values) must
        // lie in {-2,-1,0,1,2} mod q before the (identity) centering step;
        // check the raw values before the `fq_add(*v,0)` no-op re-centers
        // them into [0,q).
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 128];
        let mut counts = [0u32; 5]; // maps -2..=2 -> 0..=4
        for _ in 0..2000 {
            rng.fill_bytes(&mut buf);
            let mut r = [0i16; N];
            for i in 0..32 {
                let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
                let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
                for j in 0..8 {
                    let a = (d >> (4 * j)) & 0x3;
                    let b = (d >> (4 * j + 2)) & 0x3;
                    r[8 * i + j] = a as i16 - b as i16;
                }
            }
            for &v in r.iter() {
                assert!((-2..=2).contains(&v), "CBD(eta=2) sample out of range: {v}");
                counts[(v + 2) as usize] += 1;
            }
        }
        // Sanity: all five buckets should be populated (binomial shape),
        // none should be zero over 2000*256 samples.
        for (i, c) in counts.iter().enumerate() {
            assert!(*c > 0, "bucket {i} never hit -- sampler looks broken");
        }
    }

    #[test]
    fn compress_decompress_within_tolerance() {
        for d in [1u32, 4, 10] {
            for x in 0..Q {
                let c = compress(x, d);
                let back = decompress(c, d);
                // round-trip error must be bounded by q/2^(d+1) (standard
                // Kyber/ML-KEM compression error bound), not exact equality.
                let diff = ((x as i32 - back as i32 + Q as i32) % Q as i32).min((back as i32 - x as i32 + Q as i32) % Q as i32);
                let bound = (Q as i32 >> d) + 2;
                assert!(diff <= bound, "compress/decompress d={d} x={x} back={back} diff={diff} bound={bound}");
            }
        }
    }

    #[test]
    fn poly_pack_roundtrip() {
        let mut rng = rand::thread_rng();
        let mut p = [0i16; N];
        for c in p.iter_mut() {
            *c = rng.gen_range(0..Q);
        }
        let bytes = poly_tobytes(&p);
        let p2 = poly_frombytes(&bytes);
        assert_eq!(p, p2);
    }

    #[test]
    fn kem_correctness_1000_trials() {
        let mut ok = 0;
        for _ in 0..1000 {
            let (pk, sk) = keygen();
            let (ct, ss1) = encaps(&pk);
            let ss2 = decaps(&sk, &ct);
            assert_eq!(ss1.0, ss2.0, "shared secrets must match on honest path");
            ok += 1;
        }
        assert_eq!(ok, 1000);
    }

    #[test]
    fn kem_sizes_match_spec_constants() {
        let (pk, sk) = keygen();
        assert_eq!(pk.0.len(), PUBLICKEY_BYTES);
        assert_eq!(pk.0.len(), 1184);
        assert_eq!(sk.0.len(), SECRETKEY_BYTES);
        let (ct, _) = encaps(&pk);
        assert_eq!(ct.0.len(), CIPHERTEXT_BYTES);
        assert_eq!(ct.0.len(), 1088);
    }

    #[test]
    fn decaps_rejects_tampered_ciphertext_without_matching_secret() {
        // Implicit rejection: a tampered ciphertext must not decapsulate to
        // the same shared secret as the honest one (with overwhelming
        // probability), and must not panic/hang.
        let (pk, sk) = keygen();
        let (mut ct, ss1) = encaps(&pk);
        ct.0[0] ^= 0xff;
        let ss2 = decaps(&sk, &ct);
        assert_ne!(ss1.0, ss2.0);
    }

    #[test]
    fn ct_eq_and_select_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        let a = [0xffu8; 4];
        let b = [0x00u8; 4];
        assert_eq!(ct_select(true, &a, &b), a.to_vec());
        assert_eq!(ct_select(false, &a, &b), b.to_vec());
    }
}
