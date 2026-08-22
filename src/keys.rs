//! RocksDB keys: plaintext type prefix + CityHash128(canonical fields) hex.
//!
//! Canonical fields are lowercase. A cache-hit GET is one `DB::get`.
//! Digest is `crate::hash::hash128` (Google CityHash128, portable).

use crate::hash::hash128_hex;

pub const PCKCERT: &str = "pckcert/";
pub const TCB: &str = "tcb/";
pub const IDENTITY: &str = "identity/";
pub const PCKCRL: &str = "pckcrl/";
pub const ROOTCACRL: &str = "rootcacrl";
pub const CRL: &str = "crl/";
pub const APPRAISAL: &str = "appraisal/";
pub const PREG: &str = "preg/";
/// Per-platform PCK cert pool + known raw TCBs (Intel `platforms` +
/// `pck_cert` + `platform_tcbs` rows collapsed into one record).
pub const PLATFORM: &str = "platform/";

fn join_lower(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

fn make(prefix: &str, parts: &[&str]) -> String {
    format!("{prefix}{}", hash128_hex(join_lower(parts).as_bytes()))
}

pub fn pckcert(qeid: &str, pceid: &str, cpusvn: &str, pcesvn: &str) -> String {
    make(PCKCERT, &[qeid, pceid, cpusvn, pcesvn])
}

pub fn tcb(prod: &str, version: u32, fmspc: &str, update: &str) -> String {
    make(TCB, &[prod, &version.to_string(), fmspc, update])
}

pub fn identity(name: &str, version: u32, update: &str) -> String {
    make(IDENTITY, &[name, &version.to_string(), update])
}

pub fn pckcrl(ca: &str) -> String {
    make(PCKCRL, &[ca])
}

pub fn rootcacrl() -> String {
    ROOTCACRL.to_string()
}

pub fn crl(uri: &str) -> String {
    make(CRL, &[uri])
}

pub fn appraisal(fmspc: &str) -> String {
    make(APPRAISAL, &[fmspc])
}

pub fn preg(qeid: &str, pceid: &str, cpusvn: &str, pcesvn: &str) -> String {
    make(PREG, &[qeid, pceid, cpusvn, pcesvn])
}

pub fn platform(qeid: &str, pceid: &str) -> String {
    make(PLATFORM, &[qeid, pceid])
}

pub fn prod_name(prod_type: u8) -> &'static str {
    if prod_type == 1 {
        "tdx"
    } else {
        "sgx"
    }
}

pub fn identity_name(enclave_id: u8) -> &'static str {
    match enclave_id {
        2 => "qve",
        3 => "tdqe",
        _ => "qe",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash128;

    #[test]
    fn keys_are_stable_and_prefixed() {
        let a = pckcert("AA", "0001", "00", "0001");
        let b = pckcert("aa", "0001", "00", "0001");
        assert_eq!(a, b);
        assert!(a.starts_with("pckcert/"));
        assert_eq!(a.len(), "pckcert/".len() + 32);
        assert_eq!(rootcacrl(), "rootcacrl");
        assert_ne!(hash128(b"abc"), hash128(b"abd"));
    }
}
