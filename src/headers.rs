//! Intel PCS / PCCS response header names (exact Node `constants/index.js` strings).

pub const REQUEST_ID: &str = "Request-ID";
pub const WARNING: &str = "Warning";
pub const USER_TOKEN: &str = "user-token";
pub const ADMIN_TOKEN: &str = "admin-token";
pub const PLATFORM_COUNT: &str = "platform-count";

pub const SGX_TCBM: &str = "SGX-TCBm";
pub const SGX_FMSPC: &str = "SGX-FMSPC";
pub const SGX_PCK_CERTIFICATE_CA_TYPE: &str = "SGX-PCK-Certificate-CA-Type";
pub const SGX_PCK_CERTIFICATE_ISSUER_CHAIN: &str = "SGX-PCK-Certificate-Issuer-Chain";
pub const TCB_INFO_ISSUER_CHAIN: &str = "TCB-Info-Issuer-Chain";
pub const SGX_TCB_INFO_ISSUER_CHAIN: &str = "SGX-TCB-Info-Issuer-Chain";
pub const SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN: &str = "SGX-Enclave-Identity-Issuer-Chain";
pub const SGX_PCK_CRL_ISSUER_CHAIN: &str = "SGX-PCK-CRL-Issuer-Chain";

pub const CONTENT_TYPE_PEM: &str = "application/x-pem-file";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_CRL: &str = "application/pkix-crl";

/// Node `v3EolWarning.js` Warning header value.
pub const V3_EOL_WARNING: &str = r#"299 - "PCS API version 3 is no longer available. Cached collateral downloaded from API version 3 is deprecated, will not be refreshed, and may expire. Please migrate to API version 4.""#;

pub fn tcb_issuer_chain_name(version: u32) -> &'static str {
    if version == 3 {
        SGX_TCB_INFO_ISSUER_CHAIN
    } else {
        TCB_INFO_ISSUER_CHAIN
    }
}
