//! RocksDB key digest. To change algorithm, replace `hash128` only.

mod city;

/// 128-bit digest of `data`. Currently Google CityHash128 (portable, not CRC).
pub fn hash128(data: &[u8]) -> u128 {
    city::city_hash_128(data)
}

/// Lowercase 32-char hex of `hash128(data)`.
pub fn hash128_hex(data: &[u8]) -> String {
    format!("{:032x}", hash128(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // cityhash-sys 1.0.6 tests/hash_128.rs — CITY_HASH_128_RESULTS[i]
    // is city_hash_128(&[0, 1, …, i-1]). Trust that C++ binding if a
    // community vector disagrees.
    const EMPTY: u128 = 0x3cb540c392e51e293df09dfc64c09a2b;
    const HELLO: u128 = 0x65148f580b45f3476f72e4abb491a74a;
    // Docs.rs cityhash-sys example / RESULTS[5].
    const BYTES_0_4: u128 = 0xe3cb1f3f3ab9643bef3668c150012eec;
    // RESULTS[100] — 100-byte prefix of 0u8..255.
    const BYTES_0_99: u128 = 0x4af6eac6b81177e082940c1b36354e6f;
    // RESULTS[128] / RESULTS[200] exercise the >=128-byte path.
    const BYTES_0_127: u128 = 0xd7e962fbe3832fa2987f34a745925167;
    const BYTES_0_199: u128 = 0x5ecd9df9c773c308041b130aac352f97;

    #[test]
    fn empty_matches_google_cityhash128() {
        assert_eq!(hash128(b""), EMPTY);
        assert_eq!(hash128_hex(b""), format!("{EMPTY:032x}"));
        assert_eq!(hash128_hex(b"").len(), 32);
    }

    #[test]
    fn hello_matches_google_cityhash128() {
        assert_eq!(hash128(b"hello"), HELLO);
        assert_eq!(hash128_hex(b"hello"), "65148f580b45f3476f72e4abb491a74a");
    }

    #[test]
    fn published_cityhash_sys_vectors() {
        assert_eq!(hash128(&[0u8, 1, 2, 3, 4]), BYTES_0_4);
        let n100: Vec<u8> = (0u8..100).collect();
        assert_eq!(hash128(&n100), BYTES_0_99);
        let n128: Vec<u8> = (0u8..128).collect();
        assert_eq!(hash128(&n128), BYTES_0_127);
        let n200: Vec<u8> = (0u8..200).collect();
        assert_eq!(hash128(&n200), BYTES_0_199);
        assert_eq!(hash128_hex(&n100).len(), 32);
        assert_eq!(hash128_hex(&n100), hash128_hex(&n100).to_ascii_lowercase());
    }
}
