// Copyright (c) 2011 Google, Inc. CityHash by Geoff Pike and Jyrki Alakuijala.
// Ported from city.cc CityHash128 (portable, not CRC). MIT license as in
// https://github.com/google/cityhash

//! Portable Google CityHash128 (`city.cc` `CityHash128`, not CRC).
//!
//! `cityhash-sys` 1.0.6 needs nightly (`feature(c_size_t)`), so this is a
//! bit-compatible Rust port of the C++ reference. Swap this module to change
//! the digest; keep [`super::hash128`] as the only entry point.

const K0: u64 = 0xc3a5c85c97cb3127;
const K1: u64 = 0xb492b66fbe98f273;
const K2: u64 = 0x9ae16a3b2f90404f;
const K_MUL: u64 = 0x9ddfea08eb382d69;

#[inline]
fn fetch64(s: &[u8]) -> u64 {
    u64::from_le_bytes(s[..8].try_into().unwrap())
}

#[inline]
fn fetch32(s: &[u8]) -> u64 {
    u32::from_le_bytes(s[..4].try_into().unwrap()) as u64
}

#[inline]
fn shift_mix(val: u64) -> u64 {
    val ^ (val >> 47)
}

/// Hash128to64 / HashLen16(u, v) — Murmur-inspired.
#[inline]
fn hash_len16(u: u64, v: u64) -> u64 {
    let mut a = (u ^ v).wrapping_mul(K_MUL);
    a ^= a >> 47;
    let mut b = (v ^ a).wrapping_mul(K_MUL);
    b ^= b >> 47;
    b.wrapping_mul(K_MUL)
}

#[inline]
fn hash_len16_mul(u: u64, v: u64, mul: u64) -> u64 {
    let mut a = (u ^ v).wrapping_mul(mul);
    a ^= a >> 47;
    let mut b = (v ^ a).wrapping_mul(mul);
    b ^= b >> 47;
    b.wrapping_mul(mul)
}

fn hash_len0to16(s: &[u8]) -> u64 {
    let len = s.len() as u64;
    if s.len() >= 8 {
        let mul = K2.wrapping_add(len.wrapping_mul(2));
        let a = fetch64(s).wrapping_add(K2);
        let b = fetch64(&s[s.len() - 8..]);
        let c = b.rotate_right(37).wrapping_mul(mul).wrapping_add(a);
        let d = a.rotate_right(25).wrapping_add(b).wrapping_mul(mul);
        return hash_len16_mul(c, d, mul);
    }
    if s.len() >= 4 {
        let mul = K2.wrapping_add(len.wrapping_mul(2));
        let a = fetch32(s);
        return hash_len16_mul(len.wrapping_add(a << 3), fetch32(&s[s.len() - 4..]), mul);
    }
    if !s.is_empty() {
        let a = s[0] as u32;
        let b = s[s.len() >> 1] as u32;
        let c = s[s.len() - 1] as u32;
        let y = a.wrapping_add(b << 8) as u64;
        let z = (s.len() as u32).wrapping_add(c << 2) as u64;
        return shift_mix(y.wrapping_mul(K2) ^ z.wrapping_mul(K0)).wrapping_mul(K2);
    }
    K2
}

fn weak_hash_len32_with_seeds(w: u64, x: u64, y: u64, z: u64, mut a: u64, mut b: u64) -> (u64, u64) {
    a = a.wrapping_add(w);
    b = b.wrapping_add(a).wrapping_add(z).rotate_right(21);
    let c = a;
    a = a.wrapping_add(x).wrapping_add(y);
    b = b.wrapping_add(a.rotate_right(44));
    (a.wrapping_add(z), b.wrapping_add(c))
}

fn weak_hash32(s: &[u8], a: u64, b: u64) -> (u64, u64) {
    weak_hash_len32_with_seeds(fetch64(s), fetch64(&s[8..]), fetch64(&s[16..]), fetch64(&s[24..]), a, b)
}

/// Pack C++ `uint128` as `(Uint128High64 << 64) | Uint128Low64` (cityhash-sys).
#[inline]
fn pack(low: u64, high: u64) -> u128 {
    ((high as u128) << 64) | (low as u128)
}

fn city_murmur(s: &[u8], seed_low: u64, seed_high: u64) -> u128 {
    let mut a = seed_low;
    let mut b = seed_high;
    let (c, d) = if s.len() <= 16 {
        a = shift_mix(a.wrapping_mul(K1)).wrapping_mul(K1);
        let c = b.wrapping_mul(K1).wrapping_add(hash_len0to16(s));
        let d = shift_mix(a.wrapping_add(if s.len() >= 8 { fetch64(s) } else { c }));
        (c, d)
    } else {
        let mut c = hash_len16(fetch64(&s[s.len() - 8..]).wrapping_add(K1), a);
        let mut d = hash_len16(
            b.wrapping_add(s.len() as u64),
            c.wrapping_add(fetch64(&s[s.len() - 16..])),
        );
        a = a.wrapping_add(d);
        let mut i = 0;
        let mut remaining = s.len();
        while remaining > 16 {
            a ^= shift_mix(fetch64(&s[i..]).wrapping_mul(K1)).wrapping_mul(K1);
            a = a.wrapping_mul(K1);
            b ^= a;
            c ^= shift_mix(fetch64(&s[i + 8..]).wrapping_mul(K1)).wrapping_mul(K1);
            c = c.wrapping_mul(K1);
            d ^= c;
            i += 16;
            remaining -= 16;
        }
        (c, d)
    };
    a = hash_len16(a, c);
    b = hash_len16(d, b);
    pack(a ^ b, hash_len16(b, a))
}

fn city_hash128_with_seed(mut s: &[u8], seed_low: u64, seed_high: u64) -> u128 {
    if s.len() < 128 {
        return city_murmur(s, seed_low, seed_high);
    }

    let mut x = seed_low;
    let mut y = seed_high;
    let mut z = (s.len() as u64).wrapping_mul(K1);
    let mut v0 = (y ^ K1).rotate_right(49).wrapping_mul(K1).wrapping_add(fetch64(s));
    let mut v1 = v0.rotate_right(42).wrapping_mul(K1).wrapping_add(fetch64(&s[8..]));
    let mut w0 = y.wrapping_add(z).rotate_right(35).wrapping_mul(K1).wrapping_add(x);
    let mut w1 = x.wrapping_add(fetch64(&s[88..])).rotate_right(53).wrapping_mul(K1);
    let orig = s;
    let mut remaining = s.len();

    while remaining >= 128 {
        for _ in 0..2 {
            x = x
                .wrapping_add(y)
                .wrapping_add(v0)
                .wrapping_add(fetch64(&s[8..]))
                .rotate_right(37)
                .wrapping_mul(K1);
            y = y
                .wrapping_add(v1)
                .wrapping_add(fetch64(&s[48..]))
                .rotate_right(42)
                .wrapping_mul(K1);
            x ^= w1;
            y = y.wrapping_add(v0).wrapping_add(fetch64(&s[40..]));
            z = z.wrapping_add(w0).rotate_right(33).wrapping_mul(K1);
            let v = weak_hash32(s, v1.wrapping_mul(K1), x.wrapping_add(w0));
            v0 = v.0;
            v1 = v.1;
            let w = weak_hash32(&s[32..], z.wrapping_add(w1), y.wrapping_add(fetch64(&s[16..])));
            w0 = w.0;
            w1 = w.1;
            core::mem::swap(&mut z, &mut x);
            s = &s[64..];
        }
        remaining -= 128;
    }

    x = x.wrapping_add(v0.wrapping_add(z).rotate_right(49).wrapping_mul(K0));
    y = y.wrapping_mul(K0).wrapping_add(w1.rotate_right(37));
    z = z.wrapping_mul(K0).wrapping_add(w0.rotate_right(27));
    w0 = w0.wrapping_mul(9);
    v0 = v0.wrapping_mul(K0);

    let mut tail_done = 0usize;
    while tail_done < remaining {
        tail_done += 32;
        y = x.wrapping_add(y).rotate_right(42).wrapping_mul(K0).wrapping_add(v1);
        w0 = w0.wrapping_add(fetch64(&orig[orig.len() - tail_done + 16..]));
        x = x.wrapping_mul(K0).wrapping_add(w0);
        z = z.wrapping_add(w1).wrapping_add(fetch64(&orig[orig.len() - tail_done..]));
        w1 = w1.wrapping_add(v0);
        let v = weak_hash32(
            &orig[orig.len() - tail_done..],
            v0.wrapping_add(z),
            v1,
        );
        v0 = v.0.wrapping_mul(K0);
        v1 = v.1;
    }

    x = hash_len16(x, v0);
    y = hash_len16(y.wrapping_add(z), w0);
    pack(
        hash_len16(x.wrapping_add(v1), w1).wrapping_add(y),
        hash_len16(x.wrapping_add(w1), y.wrapping_add(v1)),
    )
}

/// Google `CityHash128` (portable).
pub fn city_hash_128(data: &[u8]) -> u128 {
    if data.len() >= 16 {
        city_hash128_with_seed(
            &data[16..],
            fetch64(data),
            fetch64(&data[8..]).wrapping_add(K0),
        )
    } else {
        city_hash128_with_seed(data, K0, K1)
    }
}
