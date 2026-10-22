//! NVIDIA OCSP request/response helpers for the collateral cache.
//!
//! Cache keys hash the DER `requestList`; `requestExtensions` are not part of
//! the key, so requests with different OCSP nonces share one entry. This
//! matches NVIDIA's Trust Outpost relying-party policy, which accepts a cached
//! response whose responder nonce differs; freshness is proven by the GPU
//! attestation evidence nonce. Expiry follows the signed `nextUpdate` (capped by a configured max TTL); responses without
//! `nextUpdate` use `thisUpdate + default_ttl`, matching the NVIDIA verifier.

use crate::error::{self, PccsError};
use chrono::{DateTime, NaiveDateTime};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponseValidity {
    this_update: i64,
    next_update: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

/// id-pkix-ocsp-basic, 1.3.6.1.5.5.7.48.1.1.
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

pub struct OcspRequest {
    /// Hex SHA-256 of the DER requestList.
    pub cache_key: String,
}

pub fn parse_request(request: &[u8]) -> Result<OcspRequest, PccsError> {
    let outer = parse_single(request, 0x30)?;
    let mut outer_fields = outer.value;
    let tbs = take_expected(&mut outer_fields, 0x30)?;

    let mut tbs_fields = tbs.value;
    while !tbs_fields.is_empty() {
        let field = take_tlv(&mut tbs_fields)?;
        match field.tag {
            // version and requestorName
            0xa0 | 0xa1 => continue,
            // requestList is the first untagged SEQUENCE in TBSRequest.
            0x30 => {
                validate_request_list(field.value)?;
                // Only the optional requestExtensions [2] may follow.
                if !tbs_fields.is_empty() {
                    let extensions = take_expected(&mut tbs_fields, 0xa2)?;
                    validate_extensions(parse_single(extensions.value, 0x30)?.value)?;
                }
                if !tbs_fields.is_empty() {
                    return Err(error::INVALID_REQ);
                }
                let cache_key = hex::encode(Sha256::digest(field.raw));
                return Ok(OcspRequest { cache_key });
            }
            _ => return Err(error::INVALID_REQ),
        }
    }
    Err(error::INVALID_REQ)
}

/// Earliest cache deadline for a successful BasicOCSPResponse.
pub fn response_cache_expiry(
    response: &[u8],
    now: i64,
    max_ttl_seconds: u64,
    default_ttl_seconds: u64,
) -> Result<u64, PccsError> {
    let validity = response_validity(response)?;
    let default_ttl = i64::try_from(default_ttl_seconds).map_err(|_| error::INTERNAL_ERROR)?;
    let max_ttl = i64::try_from(max_ttl_seconds).map_err(|_| error::INTERNAL_ERROR)?;
    let mut expires_at = now.checked_add(max_ttl).ok_or(error::INTERNAL_ERROR)?;
    for item in validity {
        // Do not cache a response which claims to have been produced in the
        // future. The guest performs the authoritative freshness check.
        if item.this_update > now {
            return Err(error::INVALID_REQ);
        }
        let signed_expiry =
            item.next_update.unwrap_or_else(|| item.this_update.saturating_add(default_ttl));
        expires_at = expires_at.min(signed_expiry);
    }
    if expires_at <= now {
        return Err(error::INVALID_REQ);
    }
    u64::try_from(expires_at).map_err(|_| error::INTERNAL_ERROR)
}

/// Walk `Extensions` (SEQUENCE OF Extension { extnID, critical?, extnValue })
/// and reject a malformed list. The extensions are not part of the cache key.
fn validate_extensions(mut extensions: &[u8]) -> Result<(), PccsError> {
    while !extensions.is_empty() {
        let extension = take_expected(&mut extensions, 0x30)?;
        let mut fields = extension.value;
        take_expected(&mut fields, 0x06)?;
        if peek_tag(fields) == Some(0x01) {
            take_expected(&mut fields, 0x01)?;
        }
        take_expected(&mut fields, 0x04)?;
        if !fields.is_empty() {
            return Err(error::INVALID_REQ);
        }
    }
    Ok(())
}

fn validate_request_list(mut request_list: &[u8]) -> Result<(), PccsError> {
    if request_list.is_empty() {
        return Err(error::INVALID_REQ);
    }
    while !request_list.is_empty() {
        let request = take_expected(&mut request_list, 0x30)?;
        let mut fields = request.value;
        take_expected(&mut fields, 0x30)?;
        // A SingleRequest extension is allowed, but no other trailing fields.
        if !fields.is_empty() {
            take_expected(&mut fields, 0xa0)?;
        }
        if !fields.is_empty() {
            return Err(error::INVALID_REQ);
        }
    }
    Ok(())
}

fn response_validity(response: &[u8]) -> Result<Vec<ResponseValidity>, PccsError> {
    let outer = parse_single(response, 0x30)?;
    let mut fields = outer.value;
    let status = take_expected(&mut fields, 0x0a)?;
    if status.value != [0] {
        return Err(error::INVALID_REQ);
    }
    let response_bytes = take_expected(&mut fields, 0xa0)?;
    let response_bytes = parse_single(response_bytes.value, 0x30)?;
    let mut fields = response_bytes.value;
    let response_type = take_expected(&mut fields, 0x06)?;
    if response_type.value != OID_OCSP_BASIC {
        return Err(error::INVALID_REQ);
    }
    let basic_der = take_expected(&mut fields, 0x04)?;

    let basic = parse_single(basic_der.value, 0x30)?;
    let mut fields = basic.value;
    let response_data = take_expected(&mut fields, 0x30)?;
    // signatureAlgorithm and signature are mandatory; certs [0] is optional.
    take_expected(&mut fields, 0x30)?;
    take_expected(&mut fields, 0x03)?;
    if !fields.is_empty() {
        let certs = take_expected(&mut fields, 0xa0)?;
        parse_single(certs.value, 0x30)?;
    }
    if !fields.is_empty() {
        return Err(error::INVALID_REQ);
    }
    let mut fields = response_data.value;

    // Optional version.
    if peek_tag(fields) == Some(0xa0) {
        take_expected(&mut fields, 0xa0)?;
    }
    // responderID is CHOICE [1] Name / [2] KeyHash.
    let responder_id = take_tlv(&mut fields)?;
    let responder_id_tag = responder_id.tag & 0x1f;
    if responder_id.tag & 0xc0 != 0x80 || !matches!(responder_id_tag, 1 | 2) {
        return Err(error::INVALID_REQ);
    }
    take_expected(&mut fields, 0x18)?;
    let responses = take_expected(&mut fields, 0x30)?;

    let mut single_responses = responses.value;
    let mut validity = Vec::new();
    while !single_responses.is_empty() {
        let single = take_expected(&mut single_responses, 0x30)?;
        let mut fields = single.value;
        take_expected(&mut fields, 0x30)?;
        let cert_status = take_tlv(&mut fields)?;
        if cert_status.tag & 0xc0 != 0x80 {
            return Err(error::INVALID_REQ);
        }
        let this_update = take_expected(&mut fields, 0x18)?;
        let this_update = parse_generalized_time(this_update.value)?;
        let next_update = if peek_tag(fields) == Some(0xa0) {
            let explicit = take_expected(&mut fields, 0xa0)?;
            let value = parse_single(explicit.value, 0x18)?;
            Some(parse_generalized_time(value.value)?)
        } else {
            None
        };
        // singleExtensions may follow nextUpdate.
        if !fields.is_empty() {
            take_expected(&mut fields, 0xa1)?;
        }
        if !fields.is_empty() {
            return Err(error::INVALID_REQ);
        }
        validity.push(ResponseValidity { this_update, next_update });
    }
    if validity.is_empty() {
        return Err(error::INVALID_REQ);
    }
    Ok(validity)
}

fn parse_generalized_time(value: &[u8]) -> Result<i64, PccsError> {
    let value = std::str::from_utf8(value).map_err(|_| error::INVALID_REQ)?;
    for format in ["%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S%.fZ"] {
        if let Ok(time) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(time.and_utc().timestamp());
        }
    }
    for format in ["%Y%m%d%H%M%S%z", "%Y%m%d%H%M%S%.f%z"] {
        if let Ok(time) = DateTime::parse_from_str(value, format) {
            return Ok(time.timestamp());
        }
    }
    Err(error::INVALID_REQ)
}

fn parse_single(input: &[u8], expected_tag: u8) -> Result<Tlv<'_>, PccsError> {
    let mut input_ref = input;
    let tlv = take_expected(&mut input_ref, expected_tag)?;
    if !input_ref.is_empty() {
        return Err(error::INVALID_REQ);
    }
    Ok(tlv)
}

fn peek_tag(input: &[u8]) -> Option<u8> {
    input.first().copied()
}

fn take_expected<'a>(input: &mut &'a [u8], expected_tag: u8) -> Result<Tlv<'a>, PccsError> {
    let tlv = take_tlv(input)?;
    if tlv.tag != expected_tag {
        return Err(error::INVALID_REQ);
    }
    Ok(tlv)
}

fn take_tlv<'a>(input: &mut &'a [u8]) -> Result<Tlv<'a>, PccsError> {
    let original = *input;
    if original.len() < 2 {
        return Err(error::INVALID_REQ);
    }
    let tag = original[0];
    if tag & 0x1f == 0x1f {
        return Err(error::INVALID_REQ);
    }
    let first_len = original[1];
    let (header_len, value_len) = if first_len & 0x80 == 0 {
        (2usize, usize::from(first_len))
    } else {
        let count = usize::from(first_len & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || original.len() < 2 + count {
            return Err(error::INVALID_REQ);
        }
        if original[2] == 0 {
            return Err(error::INVALID_REQ);
        }
        let mut value_len = 0usize;
        for byte in &original[2..2 + count] {
            value_len = value_len
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(error::INVALID_REQ)?;
        }
        if value_len < 128 {
            return Err(error::INVALID_REQ);
        }
        (2 + count, value_len)
    };
    let total_len = header_len.checked_add(value_len).ok_or(error::INVALID_REQ)?;
    if original.len() < total_len {
        return Err(error::INVALID_REQ);
    }
    let raw = &original[..total_len];
    let value = &raw[header_len..];
    *input = &original[total_len..];
    Ok(Tlv { tag, value, raw })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// id-pkix-ocsp-nonce, 1.3.6.1.5.5.7.48.1.2.
    const OID_OCSP_NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap();
            result.push(0x80 | (bytes.len() - first) as u8);
            result.extend_from_slice(&bytes[first..]);
        }
        result.extend_from_slice(value);
        result
    }

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    fn extension(oid: &[u8], value: &[u8]) -> Vec<u8> {
        sequence(&[der(0x06, oid), der(0x04, value)])
    }

    /// RFC 8954 nonce extension: id-pkix-ocsp-nonce, extnValue wrapping the
    /// DER OCTET STRING nonce.
    fn nonce_extension(nonce: u8) -> Vec<u8> {
        extension(OID_OCSP_NONCE, &der(0x04, &[nonce; 16]))
    }

    fn request_with(extensions: &[Vec<u8>]) -> Vec<u8> {
        let algorithm = sequence(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a])]);
        let cert_id =
            sequence(&[algorithm, der(0x04, &[1; 20]), der(0x04, &[2; 20]), der(0x02, &[3])]);
        let request = sequence(&[cert_id]);
        let list = sequence(&[request]);
        if extensions.is_empty() {
            return sequence(&[sequence(&[list])]);
        }
        sequence(&[sequence(&[list, der(0xa2, &sequence(extensions))])])
    }

    fn response(this_update: &str, next_update: Option<&str>) -> Vec<u8> {
        let signature = vec![sequence(&[der(0x06, &[0x2a, 0x03])]), der(0x03, &[0])];
        response_with(this_update, next_update, OID_OCSP_BASIC, &signature)
    }

    /// `after_data` is everything BasicOCSPResponse holds after ResponseData.
    fn response_with(
        this_update: &str,
        next_update: Option<&str>,
        response_type: &[u8],
        after_data: &[Vec<u8>],
    ) -> Vec<u8> {
        let cert_id = sequence(&[der(0x02, &[1])]);
        let mut single = vec![cert_id, der(0x80, &[]), der(0x18, this_update.as_bytes())];
        if let Some(next_update) = next_update {
            single.push(der(0xa0, &der(0x18, next_update.as_bytes())));
        }
        let responses = sequence(&[sequence(&single)]);
        let response_data =
            sequence(&[der(0x82, &[7; 20]), der(0x18, b"20260716120000Z"), responses]);
        let mut basic = vec![response_data];
        basic.extend_from_slice(after_data);
        let basic = sequence(&basic);
        let response_bytes = sequence(&[der(0x06, response_type), der(0x04, &basic)]);
        sequence(&[der(0x0a, &[0]), der(0xa0, &response_bytes)])
    }

    #[test]
    fn request_extensions_are_not_part_of_the_key() {
        let plain = parse_request(&request_with(&[])).unwrap();
        let nonced = parse_request(&request_with(&[nonce_extension(1)])).unwrap();
        assert_eq!(nonced.cache_key, plain.cache_key);
        let other = parse_request(&request_with(&[nonce_extension(2)])).unwrap();
        assert_eq!(other.cache_key, plain.cache_key);
        // id-pkix-ocsp-response (acceptable responses) alongside a nonce.
        let acceptable = extension(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04], &[]);
        let both = parse_request(&request_with(&[acceptable, nonce_extension(2)])).unwrap();
        assert_eq!(both.cache_key, plain.cache_key);
        // An Extension without extnValue is malformed.
        let broken = sequence(&[der(0x06, OID_OCSP_NONCE)]);
        assert!(parse_request(&request_with(&[broken])).is_err());
    }

    #[test]
    fn cache_key_rejects_malformed_requests() {
        assert!(parse_request(&[0x30, 0x01, 0]).is_err());
    }

    fn request_with_tail(tail: &[Vec<u8>]) -> Vec<u8> {
        let algorithm = sequence(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a])]);
        let cert_id =
            sequence(&[algorithm, der(0x04, &[1; 20]), der(0x04, &[2; 20]), der(0x02, &[3])]);
        let list = sequence(&[sequence(&[cert_id])]);
        let mut tbs = vec![list];
        tbs.extend_from_slice(tail);
        sequence(&[sequence(&tbs)])
    }

    #[test]
    fn cache_key_rejects_fields_after_request_list() {
        let extensions = der(0xa2, &sequence(&[nonce_extension(1)]));
        assert!(parse_request(&request_with_tail(&[])).is_ok());
        assert!(parse_request(&request_with_tail(&[extensions.clone()])).is_ok());
        // An unknown field, junk after the extensions, and a non-SEQUENCE [2].
        assert!(parse_request(&request_with_tail(&[der(0xa3, &[])])).is_err());
        assert!(parse_request(&request_with_tail(&[extensions, der(0x05, &[])])).is_err());
        assert!(parse_request(&request_with_tail(&[der(0xa2, &der(0x04, &[1]))])).is_err());
    }

    #[test]
    fn expiry_honors_next_update_and_max_ttl() {
        let now = 1_784_202_600; // 2026-07-16T11:50:00Z
        let response = response("20260716114500Z", Some("20260716123000Z"));
        assert_eq!(response_cache_expiry(&response, now, 86_400, 3_600).unwrap(), 1_784_205_000);
        assert_eq!(response_cache_expiry(&response, now, 600, 3_600).unwrap(), (now + 600) as u64);
    }

    #[test]
    fn expiry_without_next_update_uses_default_ttl() {
        let now = 1_784_202_600;
        let response = response("20260716114500Z", None);
        assert_eq!(response_cache_expiry(&response, now, 86_400, 3_600).unwrap(), 1_784_205_900);
    }

    #[test]
    fn only_basic_ocsp_responses_are_cacheable() {
        let now = 1_784_202_600;
        let signature = vec![sequence(&[der(0x06, &[0x2a, 0x03])]), der(0x03, &[0])];
        let next = Some("20260716123000Z");
        let basic = response_with("20260716114500Z", next, OID_OCSP_BASIC, &signature);
        assert!(response_cache_expiry(&basic, now, 86_400, 3_600).is_ok());
        // id-pkix-ocsp-nonce in place of id-pkix-ocsp-basic.
        let other_oid = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
        let other = response_with("20260716114500Z", next, &other_oid, &signature);
        assert!(response_cache_expiry(&other, now, 86_400, 3_600).is_err());
    }

    #[test]
    fn truncated_basic_response_is_not_cacheable() {
        let now = 1_784_202_600;
        let next = Some("20260716123000Z");
        let algorithm = sequence(&[der(0x06, &[0x2a, 0x03])]);
        let signature = der(0x03, &[0]);
        let certs = der(0xa0, &sequence(&[sequence(&[der(0x02, &[1])])]));
        let cacheable = |after: &[Vec<u8>]| {
            let response = response_with("20260716114500Z", next, OID_OCSP_BASIC, after);
            response_cache_expiry(&response, now, 86_400, 3_600).is_ok()
        };
        assert!(cacheable(&[algorithm.clone(), signature.clone()]));
        assert!(cacheable(&[algorithm.clone(), signature.clone(), certs.clone()]));
        assert!(!cacheable(&[]));
        assert!(!cacheable(&[algorithm.clone()]));
        assert!(!cacheable(&[algorithm.clone(), signature.clone(), certs, der(0x05, &[])]));
        assert!(!cacheable(&[algorithm, signature, der(0xa0, &der(0x02, &[1]))]));
    }

    #[test]
    fn expired_response_is_not_cacheable() {
        let response = response("20260716100000Z", Some("20260716110000Z"));
        assert!(response_cache_expiry(&response, 1_784_202_600, 86_400, 3_600).is_err());
    }
}
