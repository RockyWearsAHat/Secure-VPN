// Shared KAT-vector loader for the integration tests in this directory.
// `include!`d directly (not a separate crate) so each test binary gets its
// own copy without needing a `[lib]`-only helper module.

#[allow(dead_code)]
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[allow(dead_code)]
struct KatVectors {
    d: [u8; 32],
    z: [u8; 32],
    ek: Vec<u8>,
    dk: Vec<u8>,
    m: [u8; 32],
    k: [u8; 32],
    c: Vec<u8>,
}

#[allow(dead_code)]
impl KatVectors {
    fn load() -> Self {
        let text = include_str!("kat_vectors.txt");
        let mut fields = std::collections::HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                fields.insert(k.to_string(), v.to_string());
            }
        }
        let get = |name: &str| hex_decode(fields.get(name).unwrap_or_else(|| panic!("missing field {name}")));
        let d_v = get("D");
        let z_v = get("Z");
        let m_v = get("M");
        let k_v = get("K");
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut m = [0u8; 32];
        let mut k = [0u8; 32];
        d.copy_from_slice(&d_v);
        z.copy_from_slice(&z_v);
        m.copy_from_slice(&m_v);
        k.copy_from_slice(&k_v);
        KatVectors {
            d,
            z,
            ek: get("EK"),
            dk: get("DK"),
            m,
            k,
            c: get("C"),
        }
    }
}
