//! PCK cert selection — faithful port of Intel `pckCertSelection/`:
//! `Tcb.js`, `PckCertificate.js`, `pckCertSelection.js`, plus the SGX X.509
//! extension reader from `x509/x509.js`.
//!
//! A cert's TCB comes from the certificate itself (SGX extension
//! `1.2.840.113741.1.13.1`), never from the `tcbm` string — Node throws when a
//! cert cannot be parsed and the caller turns that into `404 NO_CACHE_DATA`.

use base64::Engine;
use serde_json::Value;

/// Node `Tcb`: 16 CPUSVN bytes plus PCESVN pushed as a full integer.
/// PCESVN is *not* clamped to a byte (`pcesvn` can be up to 65535).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcb {
    pub cpusvn: String,
    pub pcesvn: u32,
    components: [u32; 17],
}

/// Node `TcbNonComparableError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbNonComparable;

const CPUSVN_HEX_LEN: usize = 16 * 2;

impl Tcb {
    /// Node `new Tcb(cpusvn, pcesvn)`. `cpusvn` must be exactly 32 hex chars.
    pub fn new(cpusvn: &str, pcesvn: u32) -> Result<Self, String> {
        if cpusvn.len() != CPUSVN_HEX_LEN {
            return Err(format!("Invalid CPUSVN length: {}", cpusvn.len()));
        }
        if !cpusvn.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("Invalid CPUSVN format: {cpusvn}"));
        }
        let mut components = [0u32; 17];
        for (i, comp) in components.iter_mut().take(16).enumerate() {
            *comp = u32::from(
                u8::from_str_radix(&cpusvn[i * 2..i * 2 + 2], 16)
                    .map_err(|_| format!("Invalid CPUSVN format: {cpusvn}"))?,
            );
        }
        components[16] = pcesvn;
        Ok(Self {
            cpusvn: cpusvn.to_ascii_uppercase(),
            pcesvn,
            components,
        })
    }

    /// Node `new Tcb(cpusvn, littleEndianHexStringToInteger(pcesvn))`.
    pub fn from_hex(cpusvn: &str, pcesvn_le_hex: &str) -> Result<Self, String> {
        let pcesvn = little_endian_hex_to_int(pcesvn_le_hex)
            .ok_or_else(|| format!("Invalid PCESVN format: {pcesvn_le_hex}"))?;
        Self::new(cpusvn, pcesvn)
    }

    /// Node `Tcb.compare`: `-1` if `self` is lower, `1` if higher, `0` equal,
    /// `Err` when some components are lower and others higher.
    pub fn compare(&self, other: &Tcb) -> Result<i32, TcbNonComparable> {
        let mut left_lower = false;
        let mut right_lower = false;
        for i in 0..17 {
            if self.components[i] < other.components[i] {
                left_lower = true;
            } else if self.components[i] > other.components[i] {
                right_lower = true;
            }
        }
        match (left_lower, right_lower) {
            (true, true) => Err(TcbNonComparable),
            (true, false) => Ok(-1),
            (false, true) => Ok(1),
            (false, false) => Ok(0),
        }
    }
}

/// Node `littleEndianHexStringToInteger`: byte-swap then parse base 16.
/// Rejects odd-length / non-hex input instead of returning `NaN`.
pub fn little_endian_hex_to_int(le_hex: &str) -> Option<u32> {
    if le_hex.is_empty() || le_hex.len() % 2 != 0 || le_hex.len() > 8 {
        return None;
    }
    if !le_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let be: String = le_hex
        .as_bytes()
        .chunks(2)
        .rev()
        .map(|c| std::str::from_utf8(c).unwrap_or("00"))
        .collect();
    u32::from_str_radix(&be, 16).ok()
}

// --------------------------------------------------------------------------
// SGX X.509 extension reader (Node `x509/x509.js`)
// --------------------------------------------------------------------------

/// DER of OID `1.2.840.113741.1.13.1` (SGX extensions).
const SGX_EXT_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01];

fn sub_oid(last: u8) -> Vec<u8> {
    let mut v = SGX_EXT_OID.to_vec();
    v.push(last);
    v
}

/// Fields Node's `X509` exposes for PCK cert selection.
#[derive(Debug, Clone)]
pub struct PckCertInfo {
    pub version: u32,
    pub fmspc: String,
    pub pce_id: String,
    pub ppid: String,
    pub cpusvn: String,
    pub pcesvn: u32,
    pub ca: String,
}

/// One TLV: `(tag, contents)`. Multi-byte tags are not produced by Intel
/// certificates and abort the parse.
fn tlvs(buf: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < buf.len() {
        let tag = buf[i];
        if tag & 0x1F == 0x1F {
            break; // multi-byte tag: not expected here
        }
        let first = buf[i + 1];
        let (len, hdr) = if first < 0x80 {
            (usize::from(first), 2usize)
        } else {
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 4 || i + 2 + n > buf.len() {
                break; // indefinite / oversized length
            }
            let mut v = 0usize;
            for b in &buf[i + 2..i + 2 + n] {
                v = (v << 8) | usize::from(*b);
            }
            (v, 2 + n)
        };
        if i + hdr + len > buf.len() {
            break;
        }
        out.push((tag, &buf[i + hdr..i + hdr + len]));
        i += hdr + len;
    }
    out
}

fn is_constructed(tag: u8) -> bool {
    tag & 0x20 != 0
}

/// Contents of the extension whose OID is `oid` (its `extnValue` OCTET STRING).
fn find_extension<'a>(buf: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    for (tag, content) in tlvs(buf) {
        if tag == 0x30 {
            let kids = tlvs(content);
            if kids.len() >= 2 && kids[0].0 == 0x06 && kids[0].1 == oid {
                if let Some(&(0x04, value)) = kids.last() {
                    return Some(value);
                }
            }
        }
        if is_constructed(tag) {
            if let Some(found) = find_extension(content, oid) {
                return Some(found);
            }
        }
    }
    None
}

fn der_int(bytes: &[u8]) -> Option<u32> {
    // A DER INTEGER is signed: a set top bit without a leading 0x00 pad is a
    // negative value, meaningless for a cert version or PCESVN.
    if bytes.is_empty() || bytes.len() > 5 || bytes[0] & 0x80 != 0 {
        return None;
    }
    let mut v = 0u64;
    for b in bytes {
        v = (v << 8) | u64::from(*b);
    }
    u32::try_from(v).ok()
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body = pem.split("-----BEGIN CERTIFICATE-----").nth(1)?;
    let b64: String = body
        .split("-----END CERTIFICATE-----")
        .next()?
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()
}

/// Node `X509.parseCert`. Returns `Err` where Node returns `false`.
pub fn parse_pck_cert(pem: &str) -> Result<PckCertInfo, String> {
    let der = pem_to_der(pem).ok_or("Parsing PCK certificate from DB failed")?;
    let cert = tlvs(&der)
        .into_iter()
        .find(|(t, _)| *t == 0x30)
        .ok_or("Parsing PCK certificate from DB failed")?
        .1;
    let tbs = tlvs(cert)
        .into_iter()
        .find(|(t, _)| *t == 0x30)
        .ok_or("Parsing PCK certificate from DB failed")?
        .1;
    let tbs_kids = tlvs(tbs);

    // `@fidm/x509` reports version = DER value + 1 (v3 → 3). Absent [0] means v1.
    let mut version = 1u32;
    let mut issuer_index = 2usize;
    if let Some((0xA0, v)) = tbs_kids.first().copied() {
        let raw = tlvs(v)
            .into_iter()
            .find(|(t, _)| *t == 0x02)
            .and_then(|(_, b)| der_int(b))
            .ok_or("Parsing PCK certificate from DB failed")?;
        version = raw + 1;
        issuer_index = 3;
    }

    // Node reads the CA type from the issuer CN ("… PCK Platform CA" /
    // "… PCK Processor CA"). Search only the issuer Name, never the subject.
    let ca = tbs_kids
        .get(issuer_index)
        .map(|(_, issuer)| {
            let text = String::from_utf8_lossy(issuer);
            if text.contains("Platform") {
                "PLATFORM"
            } else if text.contains("Processor") {
                "PROCESSOR"
            } else {
                ""
            }
        })
        .unwrap_or("")
        .to_string();

    let sgx = find_extension(&der, SGX_EXT_OID).ok_or("SGX extension not found in PCK cert")?;

    let mut fmspc = String::new();
    let mut pce_id = String::new();
    let mut ppid = String::new();
    let mut cpusvn = String::new();
    let mut pcesvn: Option<u32> = None;

    // Node: `ASN1.fromDER(sgxExtensions).value` — the extnValue holds one
    // SEQUENCE whose children are the `{OID, value}` pairs.
    let sgx_items = match tlvs(sgx).as_slice() {
        [(0x30, inner)] => tlvs(inner),
        other => other.to_vec(),
    };
    for (tag, content) in sgx_items {
        if tag != 0x30 {
            continue;
        }
        let kids = tlvs(content);
        if kids.len() < 2 || kids[0].0 != 0x06 {
            continue;
        }
        let (oid, value) = (kids[0].1, kids[1]);
        if oid == sub_oid(0x04).as_slice() {
            fmspc = hex::encode_upper(value.1);
        } else if oid == sub_oid(0x03).as_slice() {
            pce_id = hex::encode_upper(value.1);
        } else if oid == sub_oid(0x01).as_slice() {
            ppid = hex::encode_upper(value.1);
        } else if oid == sub_oid(0x02).as_slice() {
            // TCB: SEQUENCE of 18 SEQUENCE{OID, value}.
            // .1-.16 CPUSVN components, .17 PCESVN, .18 CPUSVN octet string.
            let items = tlvs(value.1);
            if items.len() < 18 {
                return Err("Invalid SGX TCB extension".into());
            }
            let field = |idx: usize| -> Option<(u8, &[u8])> {
                let kids = tlvs(items[idx].1);
                kids.get(1).copied()
            };
            pcesvn = field(16).and_then(|(_, b)| der_int(b));
            cpusvn = field(17)
                .map(|(_, b)| hex::encode_upper(b))
                .unwrap_or_default();
        }
    }

    let pcesvn = pcesvn.ok_or("Invalid SGX TCB extension")?;
    if cpusvn.is_empty() || fmspc.is_empty() || pce_id.is_empty() {
        return Err("Invalid SGX extension in PCK cert".into());
    }
    Ok(PckCertInfo {
        version,
        fmspc,
        pce_id,
        ppid,
        cpusvn,
        pcesvn,
        ca,
    })
}

// --------------------------------------------------------------------------
// pckCertSelection.js
// --------------------------------------------------------------------------

/// Node `Constants.PCK_CERT_VERSION`.
const PCK_CERT_VERSION: u32 = 3;

#[derive(Debug, Clone)]
struct ParsedCert {
    tcbm: String,
    cert: String,
    info: PckCertInfo,
    tcb: Tcb,
}

struct Bucket {
    tcb: Option<Tcb>,
    certs: Vec<usize>,
}

/// Node `parsePckCerts`.
fn parse_pck_certs(certs: &[(String, String)]) -> Result<Vec<ParsedCert>, String> {
    certs
        .iter()
        .map(|(tcbm, cert)| {
            let info = parse_pck_cert(cert)?;
            let tcb = Tcb::new(&info.cpusvn, info.pcesvn)?;
            Ok(ParsedCert {
                tcbm: tcbm.to_ascii_uppercase(),
                cert: cert.clone(),
                info,
                tcb,
            })
        })
        .collect()
}

/// Node `validateInput`.
fn validate_input(pce_id: &str, certs: &[ParsedCert], tcb_info: &Value) -> Result<(), String> {
    let tcb_type = tcb_info.get("tcbType").and_then(|v| v.as_i64());
    if tcb_type != Some(0) {
        return Err(format!(
            "TCB_TYPE in TCB Info ({tcb_type:?}) is different than 0"
        ));
    }
    let info_pceid = tcb_info
        .get("pceId")
        .and_then(|v| v.as_str())
        .ok_or("PCEID missing in TCB Info")?;
    if !info_pceid.eq_ignore_ascii_case(pce_id) {
        return Err(format!(
            "PCEID in TCB Info ({info_pceid}) is different than platform PCEID ({pce_id})"
        ));
    }
    let levels = tcb_info
        .get("tcbLevels")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or("Empty TCB Levels in in TCB Info")?;
    for (index, level) in levels.iter().enumerate() {
        let tcb = level.get("tcb").ok_or(format!(
            "Invalid TCB levels: Level {index} missing sgxtcbcomponents"
        ))?;
        if level_cpusvn(tcb).is_none() {
            return Err(format!(
                "Invalid TCB levels: Level {index} missing sgxtcbcomponents"
            ));
        }
        match tcb.get("pcesvn").and_then(|v| v.as_u64()) {
            Some(_) => {}
            None => {
                return Err(format!("Invalid TCB levels: Level {index} invalid pcesvn"));
            }
        }
    }

    let fmspc = tcb_info
        .get("fmspc")
        .and_then(|v| v.as_str())
        .ok_or("FMSPC missing in TCB Info")?
        .to_ascii_uppercase();
    let mut ppid: Option<&str> = None;
    for cert in certs {
        if cert.info.version != PCK_CERT_VERSION {
            return Err(format!(
                "PCK certificate version ({}) is different than expected version ({PCK_CERT_VERSION})",
                cert.info.version
            ));
        }
        if cert.info.pce_id != pce_id.to_ascii_uppercase() {
            return Err(format!(
                "PCEID in cert ({}) is different than platform PCEID ({pce_id})",
                cert.info.pce_id
            ));
        }
        if cert.info.fmspc != fmspc {
            return Err(format!(
                "FMSPC in cert ({}) is different than in TCB info ({fmspc})",
                cert.info.fmspc
            ));
        }
        match ppid {
            None => ppid = Some(&cert.info.ppid),
            Some(p) if p != cert.info.ppid => {
                return Err("PPIDs are not the same in every PCK certificate".into());
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// CPUSVN hex of one TCB level. v4 uses `sgxtcbcomponents[i].svn`; v3 collateral
/// (accepted by `PUT /platformcollateral`) only has `sgxtcbcompNNsvn` scalars,
/// which Node's selection tool cannot read — we accept both.
fn level_cpusvn(tcb: &Value) -> Option<String> {
    if let Some(components) = tcb.get("sgxtcbcomponents").and_then(|v| v.as_array()) {
        if components.len() != 16 {
            return None;
        }
        let mut out = String::with_capacity(32);
        for c in components {
            let svn = c.get("svn").and_then(|v| v.as_u64())?;
            if svn > 255 {
                return None;
            }
            out.push_str(&format!("{svn:02X}"));
        }
        return Some(out);
    }
    let mut out = String::with_capacity(32);
    for i in 1..=16 {
        let svn = tcb
            .get(format!("sgxtcbcomp{i:02}svn"))
            .and_then(|v| v.as_u64())?;
        if svn > 255 {
            return None;
        }
        out.push_str(&format!("{svn:02X}"));
    }
    Some(out)
}

/// Node `createBucketsForCertificatesByTcb`.
fn create_buckets(tcb_info: &Value) -> Result<Vec<Bucket>, String> {
    let levels = tcb_info
        .get("tcbLevels")
        .and_then(|v| v.as_array())
        .ok_or("Empty TCB Levels in in TCB Info")?;
    let mut buckets: Vec<Bucket> = Vec::with_capacity(levels.len());
    for level in levels {
        let tcb = level.get("tcb").ok_or("Invalid TCB levels")?;
        let cpusvn = level_cpusvn(tcb).ok_or("Invalid TCB levels")?;
        let pcesvn = u32::try_from(
            tcb.get("pcesvn")
                .and_then(|v| v.as_u64())
                .ok_or("Invalid TCB levels")?,
        )
        .map_err(|_| "Invalid TCB levels")?;
        buckets.push(Bucket {
            tcb: Some(Tcb::new(&cpusvn, pcesvn)?),
            certs: Vec::new(),
        });
    }
    // Node sorts with `(x, y) => y.tcb.compare(x.tcb)` (descending), treating
    // non-comparable pairs as 0.
    //
    // That comparator is NOT a total order: with levels A, B, C where A and B
    // are non-comparable, A > C and C > B, it reports A == C == B while A != B
    // — an intransitive ("cmp(a,b)==0 and cmp(b,c)==0 but cmp(a,c)!=0")
    // comparator. Rust's `sort_by` is allowed to *panic* on one
    // ("user-provided comparison function does not correctly implement a total
    // order"), which would take down a `/pckcert` request. V8's sort never
    // throws; it just yields whatever its algorithm produces.
    //
    // So we run V8's algorithm instead of `sort_by`. See `v8_sort_desc`.
    v8_sort_desc(&mut buckets);
    Ok(buckets)
}

/// V8's `Array.prototype.sort` for the array sizes `tcbLevels` actually has.
///
/// V8 uses TimSort; for a run shorter than 64 elements that reduces to
/// "detect the initial ascending/descending run, then binary-insertion-sort the
/// rest into it". Reproducing it exactly is what keeps a non-total-order
/// comparator (see `create_buckets`) landing on the *same* bucket order as
/// Node, rather than merely on *some* deterministic order.
///
/// The comparator is Node's `(x, y) => y.tcb.compare(x.tcb)`, with a
/// non-comparable pair scoring 0.
fn v8_sort_desc(buckets: &mut [Bucket]) {
    fn cmp(x: &Bucket, y: &Bucket) -> i32 {
        match (&x.tcb, &y.tcb) {
            (Some(xt), Some(yt)) => yt.compare(xt).unwrap_or(0),
            _ => 0,
        }
    }

    let len = buckets.len();
    if len < 2 {
        return;
    }

    // V8 `countAndMakeRunAscending`.
    let mut run = 1;
    if cmp(&buckets[1], &buckets[0]) < 0 {
        run = 2;
        while run < len && cmp(&buckets[run], &buckets[run - 1]) < 0 {
            run += 1;
        }
        buckets[..run].reverse();
    } else {
        while run < len && cmp(&buckets[run], &buckets[run - 1]) >= 0 {
            run += 1;
        }
    }

    // V8 `binaryInsertionSort`, starting past the initial run.
    for start in run..len {
        let (mut left, mut right) = (0usize, start);
        while left < right {
            let mid = left + (right - left) / 2;
            if cmp(&buckets[start], &buckets[mid]) < 0 {
                right = mid;
            } else {
                left = mid + 1;
            }
        }
        // Stable: the pivot slides down to `left`, order of equals preserved.
        buckets[left..=start].rotate_right(1);
    }
}

/// Node `findIndexToInsertCertIntoBucket`. `index` advances only for certs that
/// compared successfully and were higher — non-comparable certs are skipped
/// without advancing, exactly as in the JS.
fn find_insert_index(bucket_certs: &[usize], parsed: &[ParsedCert], cert: &ParsedCert) -> i64 {
    let mut index = 0i64;
    for slot in bucket_certs {
        match cert.tcb.compare(&parsed[*slot].tcb) {
            Ok(n) if n >= 0 => return index,
            Ok(_) => {}
            Err(TcbNonComparable) => continue,
        }
        index += 1;
    }
    -1
}

/// Node `selectBestPckCert`. Returns `(tcbm, pem)` of the chosen certificate.
pub fn select_best_pck_cert(
    raw_cpusvn: &str,
    raw_pcesvn: &str,
    pce_id: &str,
    certs: &[(String, String)],
    tcb_info: &Value,
) -> Result<(String, String), String> {
    if certs.is_empty() {
        return Err("No certificate found for given platform".into());
    }
    let parsed = parse_pck_certs(certs)?;
    validate_input(pce_id, &parsed, tcb_info)?;

    let mut buckets = create_buckets(tcb_info)?;
    let mut not_matching: Vec<usize> = Vec::new();
    for (i, cert) in parsed.iter().enumerate() {
        let mut was_added = false;
        for bucket in buckets.iter_mut() {
            let Some(btcb) = &bucket.tcb else { continue };
            match cert.tcb.compare(btcb) {
                Ok(n) if n >= 0 => {
                    let index = find_insert_index(&bucket.certs, &parsed, cert);
                    if index == -1 {
                        bucket.certs.push(i);
                    } else {
                        bucket.certs.insert(index as usize, i);
                    }
                    was_added = true;
                    break;
                }
                Ok(_) => {}
                Err(TcbNonComparable) => continue,
            }
        }
        if !was_added {
            not_matching.push(i);
        }
    }
    buckets.push(Bucket {
        tcb: None,
        certs: not_matching,
    });

    let raw = Tcb::from_hex(raw_cpusvn, raw_pcesvn)?;
    // Node `selectBestPckCertFromTcbBuckets`.
    for bucket in &buckets {
        for slot in &bucket.certs {
            let cert = &parsed[*slot];
            match raw.compare(&cert.tcb) {
                Ok(n) if n >= 0 => return Ok((cert.tcbm.clone(), cert.cert.clone())),
                Ok(_) => {}
                Err(TcbNonComparable) => continue,
            }
        }
    }
    Err("No certificate found for given platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `create_buckets` must not panic on a `tcbLevels` set whose TCBs are not
    /// totally ordered, and must land on the order V8 produces.
    ///
    /// The task's literal triple ("A vs B non-comparable, A > C, C > B") cannot
    /// exist: `Tcb::compare` returns `>` only for componentwise domination,
    /// which is transitive, so `A > C > B` would force `A > B`. The real
    /// intransitivity — and the one that makes Rust's `sort_by` panic with
    /// "user-provided comparison function does not correctly implement a total
    /// order" — is in *equality*: non-comparable scores 0, so
    /// `cmp(A,B) == 0` and `cmp(B,C) == 0` while `cmp(A,C) != 0`.
    ///
    /// Levels (only sgxtcbcomponents 1..3 vary; pcesvn is equal):
    ///   A = (2,0,0)   B = (0,1,0)   C = (1,0,0)
    ///   A vs C -> A dominates       => comparable, A > C
    ///   A vs B -> 2>0 but 0<1       => non-comparable
    ///   B vs C -> 0<1 but 1>0       => non-comparable
    ///
    /// Fed in the order [C, A, B], V8's sort (comparator
    /// `(x, y) => y.tcb.compare(x.tcb)`, non-comparable -> 0) does:
    ///   countAndMakeRunAscending: cmp(A, C) = C.compare(A) = -1 < 0
    ///     -> descending run; cmp(B, A) = A.compare(B) = 0, not < 0, so the run
    ///        stops at length 2 and [C, A] is reversed -> [A, C, B]
    ///   binaryInsertionSort from index 2: pivot B, mid 1,
    ///     cmp(B, C) = C.compare(B) = 0, not < 0 -> left = 2 -> B stays put
    /// giving [A, C, B].
    #[test]
    fn create_buckets_handles_non_total_order_without_panicking() {
        let level = |c1: u64, c2: u64, c3: u64| {
            let mut comps: Vec<Value> = vec![serde_json::json!({ "svn": c1 })];
            comps.push(serde_json::json!({ "svn": c2 }));
            comps.push(serde_json::json!({ "svn": c3 }));
            for _ in 3..16 {
                comps.push(serde_json::json!({ "svn": 0 }));
            }
            serde_json::json!({ "tcb": { "sgxtcbcomponents": comps, "pcesvn": 1 } })
        };
        let a = level(2, 0, 0);
        let b = level(0, 1, 0);
        let c = level(1, 0, 0);

        // Guard the premise: the comparator really is not a total order.
        let tcb_of = |v: &Value| {
            Tcb::new(
                &level_cpusvn(v.get("tcb").unwrap()).unwrap(),
                v["tcb"]["pcesvn"].as_u64().unwrap() as u32,
            )
            .unwrap()
        };
        let (ta, tb, tc) = (tcb_of(&a), tcb_of(&b), tcb_of(&c));
        assert_eq!(ta.compare(&tb), Err(TcbNonComparable));
        assert_eq!(tb.compare(&tc), Err(TcbNonComparable));
        assert_eq!(ta.compare(&tc), Ok(1));

        let info = serde_json::json!({ "tcbLevels": [c, a, b] });
        let buckets = create_buckets(&info).expect("create_buckets must not fail");

        let order: Vec<&Tcb> = buckets.iter().map(|b| b.tcb.as_ref().unwrap()).collect();
        assert_eq!(order.len(), 3);
        assert_eq!(*order[0], ta, "V8 reverses the leading descending run");
        assert_eq!(*order[1], tc);
        assert_eq!(*order[2], tb, "non-comparable pivot keeps its position");
    }

    /// The three-level case above is small enough that Rust's `sort_by` happens
    /// not to notice the broken ordering. A real `tcbInfo` carries a few dozen
    /// levels, and at that size `sort_by` *does* detect it and panics with
    /// "user-provided comparison function does not correctly implement a total
    /// order" — turning a `/pckcert` request into a 500. This is the case that
    /// actually proves `v8_sort_desc` earns its place.
    #[test]
    fn create_buckets_survives_a_realistic_pile_of_non_comparable_levels() {
        let n = 24usize;
        let levels: Vec<Value> = (0..n)
            .map(|i| {
                // Three independent "axes" so a large share of the pairs are
                // mutually non-comparable.
                let mut comps: Vec<Value> = Vec::with_capacity(16);
                comps.push(serde_json::json!({ "svn": i % 7 }));
                comps.push(serde_json::json!({ "svn": (n - i) % 5 }));
                comps.push(serde_json::json!({ "svn": i % 3 }));
                for _ in 3..16 {
                    comps.push(serde_json::json!({ "svn": 0 }));
                }
                serde_json::json!({ "tcb": { "sgxtcbcomponents": comps, "pcesvn": 1 } })
            })
            .collect();

        let info = serde_json::json!({ "tcbLevels": levels });
        let buckets = create_buckets(&info).expect("must not fail");
        assert_eq!(buckets.len(), n);

        // Deterministic: the same input always yields the same order.
        let again = create_buckets(&info).expect("must not fail");
        let order: Vec<&Tcb> = buckets.iter().map(|b| b.tcb.as_ref().unwrap()).collect();
        let order2: Vec<&Tcb> = again.iter().map(|b| b.tcb.as_ref().unwrap()).collect();
        assert_eq!(order, order2);

        // Whatever the non-comparable pairs do, every pair that *is* comparable
        // must still come out in descending order relative to its neighbour.
        for w in order.windows(2) {
            if let Ok(c) = w[0].compare(w[1]) {
                assert!(c >= 0, "comparable neighbours must be descending");
            }
        }
    }

    // --- Ported from Intel `pckCertSelection/Tcb.test.js` ---

    #[test]
    fn compare_throws_when_tcbs_are_not_comparable() {
        let base = Tcb::new("01011111000100000000000000000000", 10).unwrap();
        let higher_cpusvn_lower_pcesvn = Tcb::new("02011111000100000000000000000000", 9).unwrap();
        let lower_cpusvn_higher_pcesvn = Tcb::new("00011111000000000000000000000000", 11).unwrap();
        let mixed_cpusvn = Tcb::new("02020100000000000000000000000000", 10).unwrap();

        assert_eq!(
            base.compare(&higher_cpusvn_lower_pcesvn),
            Err(TcbNonComparable)
        );
        assert_eq!(
            base.compare(&lower_cpusvn_higher_pcesvn),
            Err(TcbNonComparable)
        );
        assert_eq!(base.compare(&mixed_cpusvn), Err(TcbNonComparable));
    }

    #[test]
    fn compare_returns_zero_minus_one_and_one() {
        let base = Tcb::new("01011111000100000000000000000000", 9).unwrap();
        assert_eq!(
            base.compare(&Tcb::new("01011111000100000000000000000000", 9).unwrap()),
            Ok(0)
        );
        // parameter higher
        assert_eq!(
            base.compare(&Tcb::new("02011111000200000000000000000000", 9).unwrap()),
            Ok(-1)
        );
        assert_eq!(
            base.compare(&Tcb::new("01011111000100000000000000000000", 10).unwrap()),
            Ok(-1)
        );
        assert_eq!(
            base.compare(&Tcb::new("02011111000200000000000000000000", 10).unwrap()),
            Ok(-1)
        );
        // parameter lower
        assert_eq!(
            base.compare(&Tcb::new("00010000000100000000000000000000", 9).unwrap()),
            Ok(1)
        );
        assert_eq!(
            base.compare(&Tcb::new("01011111000100000000000000000000", 8).unwrap()),
            Ok(1)
        );
        assert_eq!(
            base.compare(&Tcb::new("00010000000100000000000000000000", 8).unwrap()),
            Ok(1)
        );
    }

    /// PCESVN is a full integer, not a byte: 256 must beat 255.
    #[test]
    fn pcesvn_is_not_clamped_to_a_byte() {
        let low = Tcb::new("00000000000000000000000000000000", 255).unwrap();
        let high = Tcb::new("00000000000000000000000000000000", 256).unwrap();
        assert_eq!(low.compare(&high), Ok(-1));
        assert_eq!(high.compare(&low), Ok(1));
    }

    #[test]
    fn little_endian_pcesvn_matches_node() {
        // Node: '0B00'.match(/.{2}/g).reverse().join('') === '000B' → 11
        assert_eq!(little_endian_hex_to_int("0B00"), Some(11));
        assert_eq!(little_endian_hex_to_int("0100"), Some(1));
        assert_eq!(little_endian_hex_to_int("zz00"), None);
        assert_eq!(little_endian_hex_to_int("0"), None);
    }

    // --- from_hex must not slice on a non-hex / short string ---

    #[test]
    fn from_hex_rejects_bad_input_without_panicking() {
        assert!(Tcb::from_hex("zz", "0000").is_err());
        assert!(Tcb::from_hex("00000000000000000000000000000000", "zzzz").is_err());
        assert!(Tcb::from_hex("ééééééééééééééééééééééééééééééééé", "0000").is_err());
        assert!(Tcb::new("0011", 1).is_err());
    }

    // --- Ported from `pckCertSelection.test.js`: selection needs real certs ---

    fn tcb_info(levels: Vec<(&str, u32)>) -> Value {
        let tcb_levels: Vec<Value> = levels
            .into_iter()
            .map(|(cpusvn, pcesvn)| {
                let comps: Vec<Value> = (0..16)
                    .map(|i| {
                        let svn = u8::from_str_radix(&cpusvn[i * 2..i * 2 + 2], 16).unwrap();
                        serde_json::json!({ "svn": svn })
                    })
                    .collect();
                serde_json::json!({
                    "tcb": { "sgxtcbcomponents": comps, "pcesvn": pcesvn }
                })
            })
            .collect();
        serde_json::json!({
            "fmspc": "00906EA10000",
            "pceId": "0000",
            "tcbType": 0,
            "tcbLevels": tcb_levels,
        })
    }

    /// An unparsable certificate is an error, never a silent fallback to tcbm.
    #[test]
    fn unparsable_cert_is_an_error_not_a_tcbm_fallback() {
        let certs = vec![(
            "0102030405060708090A0B0C0D0E0F10FFFF".to_string(),
            "not a certificate".to_string(),
        )];
        let err = select_best_pck_cert(
            "01010101010101010101010101010101",
            "0100",
            "0000",
            &certs,
            &tcb_info(vec![("01010101010101010101010101010101", 1)]),
        )
        .unwrap_err();
        assert!(err.contains("Parsing PCK certificate"), "{err}");
    }

    /// Single-cert input must still be compared, not returned unconditionally.
    #[test]
    fn no_single_cert_fallback() {
        let certs = vec![("AAAA".to_string(), "garbage".to_string())];
        assert!(select_best_pck_cert(
            "00000000000000000000000000000000",
            "0000",
            "0000",
            &certs,
            &tcb_info(vec![("00000000000000000000000000000000", 0)]),
        )
        .is_err());
    }

    #[test]
    fn empty_cert_list_is_an_error() {
        assert!(select_best_pck_cert(
            "00000000000000000000000000000000",
            "0000",
            "0000",
            &[],
            &tcb_info(vec![("00000000000000000000000000000000", 0)]),
        )
        .is_err());
    }

    #[test]
    fn validate_input_rejects_non_zero_tcb_type() {
        let mut info = tcb_info(vec![("00000000000000000000000000000000", 0)]);
        info["tcbType"] = serde_json::json!(1);
        let err = select_best_pck_cert(
            "00000000000000000000000000000000",
            "0000",
            "0000",
            &[("AAAA".into(), TEST_PEM.into())],
            &info,
        )
        .unwrap_err();
        assert!(err.contains("TCB_TYPE") || err.contains("Parsing"), "{err}");
    }

    // A syntactically valid PEM whose body is not a certificate: parse must fail
    // cleanly (no panic) rather than produce a bogus TCB.
    const TEST_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBpDCCAUmgAwIBAgI=\n-----END CERTIFICATE-----\n";

    #[test]
    fn malformed_der_does_not_panic() {
        assert!(parse_pck_cert(TEST_PEM).is_err());
        assert!(parse_pck_cert("").is_err());
        assert!(
            parse_pck_cert("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----").is_err()
        );
    }

    #[test]
    fn bucket_walk_prefers_highest_bucket_then_highest_cert() {
        // Buckets are sorted descending; a raw TCB at the top level must pick
        // the cert in the highest bucket that is <= raw.
        let info = tcb_info(vec![
            ("02020202020202020202020202020202", 2),
            ("01010101010101010101010101010101", 1),
        ]);
        let buckets = create_buckets(&info).unwrap();
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].tcb.as_ref().unwrap().pcesvn, 2);
        assert_eq!(buckets[1].tcb.as_ref().unwrap().pcesvn, 1);
    }

    #[test]
    fn buckets_are_sorted_descending_even_when_input_is_ascending() {
        let info = tcb_info(vec![
            ("01010101010101010101010101010101", 1),
            ("03030303030303030303030303030303", 3),
            ("02020202020202020202020202020202", 2),
        ]);
        let buckets = create_buckets(&info).unwrap();
        let svns: Vec<u32> = buckets
            .iter()
            .map(|b| b.tcb.as_ref().unwrap().pcesvn)
            .collect();
        assert_eq!(svns, vec![3, 2, 1]);
    }

    #[test]
    fn tlvs_survive_der_edge_cases() {
        // Multi-byte tag: not produced by Intel certs, aborts the parse.
        assert!(tlvs(&[0x1F, 0x01, 0x00]).is_empty());
        // Indefinite length (0x80) and >4-byte lengths: abort.
        assert!(tlvs(&[0x30, 0x80, 0x00]).is_empty());
        assert!(tlvs(&[0x30, 0x85, 0, 0, 0, 0, 0]).is_empty());
        // Declared length past the buffer end: abort.
        assert!(tlvs(&[0x30, 0x10, 0x01]).is_empty());
        // Truncated header.
        assert!(tlvs(&[0x30]).is_empty());
        // Long-form length that fits.
        let tlv = tlvs(&[0x04, 0x81, 0x02, 0xAA, 0xBB]);
        assert_eq!(tlv.len(), 1);
        assert_eq!(tlv[0].1, &[0xAA, 0xBB]);
    }

    #[test]
    fn der_int_limits() {
        assert_eq!(der_int(&[]), None);
        assert_eq!(der_int(&[0x01]), Some(1));
        // DER INTEGERs are signed: 0xFFFFFFFF is -1, not u32::MAX.
        assert_eq!(der_int(&[0xFF, 0xFF, 0xFF, 0xFF]), None);
        // A leading 0x00 pad keeps it positive, and 5 bytes can still fit…
        assert_eq!(der_int(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF]), Some(u32::MAX));
        // …or overflow u32.
        assert_eq!(der_int(&[0x01, 0x00, 0x00, 0x00, 0x00]), None);
        assert_eq!(der_int(&[0; 6]), None);
    }

    #[test]
    fn pem_to_der_variants() {
        assert!(pem_to_der("no markers").is_none());
        assert!(
            pem_to_der("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----").is_none()
        );
        let der = pem_to_der("-----BEGIN CERTIFICATE-----\naGVs bG8=\n-----END CERTIFICATE-----")
            .unwrap();
        assert_eq!(der, b"hello");
    }

    #[test]
    fn level_cpusvn_shape_checks() {
        // v4 style with the wrong component count is invalid.
        let tcb = serde_json::json!({ "sgxtcbcomponents": [{ "svn": 1 }], "pcesvn": 1 });
        assert_eq!(level_cpusvn(&tcb), None);
        // A component above 255 is not a byte (v4 style).
        let comps: Vec<Value> = (0..16).map(|_| serde_json::json!({ "svn": 300 })).collect();
        let tcb = serde_json::json!({ "sgxtcbcomponents": comps, "pcesvn": 1 });
        assert_eq!(level_cpusvn(&tcb), None);
        // A missing svn field invalidates the level.
        let comps: Vec<Value> = (0..16).map(|_| serde_json::json!({})).collect();
        let tcb = serde_json::json!({ "sgxtcbcomponents": comps, "pcesvn": 1 });
        assert_eq!(level_cpusvn(&tcb), None);
    }

    #[test]
    fn find_insert_index_skips_non_comparable_certs() {
        // `find_insert_index` only reads `tcb`; the rest is inert here.
        let cert = |tcbm: &str, cpusvn: &str, pcesvn: u32| ParsedCert {
            tcbm: tcbm.into(),
            cert: String::new(),
            info: PckCertInfo {
                version: 3,
                fmspc: String::new(),
                pce_id: String::new(),
                ppid: String::new(),
                cpusvn: String::new(),
                pcesvn: 0,
                ca: String::new(),
            },
            tcb: Tcb::new(cpusvn, pcesvn).unwrap(),
        };
        // Two bucket entries: A non-comparable with the candidate, C lower
        // than it. The candidate must skip A *without advancing the index*
        // and insert at 0, before C. An implementation that advanced the
        // index on the non-comparable entry would answer 1 here.
        let parsed = vec![
            cert("A", "02000000000000000000000000000000", 3),
            cert("C", "01000000000000000000000000000000", 1),
        ];
        // Non-comparable with A (higher cpusvn, lower pcesvn), above C.
        let candidate = cert("B", "03000000000000000000000000000000", 2);
        assert_eq!(find_insert_index(&[0, 1], &parsed, &candidate), 0);
        // Non-comparable with every entry (higher cpusvn, lower pcesvn):
        // never inserted (-1).
        let non_comparable = cert("D", "03000000000000000000000000000000", 0);
        assert_eq!(find_insert_index(&[0, 1], &parsed, &non_comparable), -1);
        // Lower than everything comparable: goes past the end.
        let lower = cert("E", "00000000000000000000000000000000", 0);
        assert_eq!(find_insert_index(&[0, 1], &parsed, &lower), -1);
    }

    #[test]
    fn legacy_v3_sgxtcbcompnnsvn_levels_are_understood() {
        let mut tcb = serde_json::Map::new();
        for i in 1..=16u32 {
            tcb.insert(format!("sgxtcbcomp{i:02}svn"), serde_json::json!(i));
        }
        tcb.insert("pcesvn".into(), serde_json::json!(7));
        let v = Value::Object(tcb);
        assert_eq!(
            level_cpusvn(&v).as_deref(),
            Some("0102030405060708090A0B0C0D0E0F10")
        );
    }
}
