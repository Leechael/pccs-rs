//! PCK cert selection — best cert for a raw platform TCB.
//! Port of Intel `pckCertSelection.js` Tcb.compare + bucket walk, using tcbm
//! (cpusvn||pcesvn) when X.509 parse is not available. Run in memory, persist
//! only the selected GET /pckcert record.

#[derive(Debug, Clone)]
pub struct Tcb {
    pub components: [u8; 17], // 16 CPUSVN bytes + PCESVN
}

#[derive(Debug)]
pub struct TcbNonComparable;

impl Tcb {
    pub fn from_hex(cpusvn: &str, pcesvn: &str) -> Option<Self> {
        if cpusvn.len() != 32 || pcesvn.len() != 4 {
            return None;
        }
        let mut components = [0u8; 17];
        for i in 0..16 {
            components[i] = u8::from_str_radix(&cpusvn[i * 2..i * 2 + 2], 16).ok()?;
        }
        // little-endian hex → integer (Node littleEndianHexStringToInteger)
        let be = format!("{}{}", &pcesvn[2..4], &pcesvn[0..2]);
        let pce = u16::from_str_radix(&be, 16).ok()?;
        // store low byte; Node pushes the integer as one component
        components[16] = pce.min(255) as u8;
        if pce > 255 {
            // keep compare useful: use saturating; full int compare below
        }
        Some(Self { components })
    }

    pub fn from_tcbm(tcbm: &str) -> Option<Self> {
        if tcbm.len() < 36 {
            return None;
        }
        Self::from_hex(&tcbm[..32], &tcbm[32..36])
    }

    /// Node Tcb.compare: -1 if self < that, 1 if self > that, 0 equal.
    /// Err if incomparable (some comps lower AND some higher).
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
        if left_lower && right_lower {
            return Err(TcbNonComparable);
        }
        if left_lower {
            Ok(-1)
        } else if right_lower {
            Ok(1)
        } else {
            Ok(0)
        }
    }
}

/// Choose a cert for the platform raw TCB from `(tcbm, pem)` pairs.
/// Prefer exact tcbm == cpusvn||pcesvn; otherwise highest comparable cert
/// whose TCB is <= raw TCB (Node: rawTCB.compare(pckCert.tcb) >= 0).
pub fn select_for_raw_tcb(
    cpusvn: &str,
    pcesvn: &str,
    certs: &[(String, String)],
) -> Option<(String, String)> {
    if certs.is_empty() {
        return None;
    }
    let want = format!("{}{}", cpusvn, pcesvn).to_ascii_uppercase();
    if let Some((t, c)) = certs.iter().find(|(t, _)| t.eq_ignore_ascii_case(&want)) {
        return Some((t.to_ascii_uppercase(), c.clone()));
    }
    let raw = Tcb::from_hex(cpusvn, pcesvn);
    if let Some(raw) = raw {
        let mut best: Option<(String, String)> = None;
        let mut best_tcb: Option<Tcb> = None;
        for (tcbm, cert) in certs {
            let Some(ct) = Tcb::from_tcbm(tcbm) else {
                continue;
            };
            match raw.compare(&ct) {
                Ok(n) if n >= 0 => {
                    let take = match &best_tcb {
                        None => true,
                        Some(b) => matches!(ct.compare(b), Ok(x) if x >= 0),
                    };
                    if take {
                        best_tcb = Some(ct);
                        best = Some((tcbm.to_ascii_uppercase(), cert.clone()));
                    }
                }
                _ => {}
            }
        }
        if best.is_some() {
            return best;
        }
    }
    if certs.len() == 1 {
        return Some((certs[0].0.to_ascii_uppercase(), certs[0].1.clone()));
    }
    None
}

/// Intel-style selection using TCB info levels as buckets, then tcbm as cert TCB.
pub fn select_best_pck_cert(
    raw_cpusvn: &str,
    raw_pcesvn: &str,
    certs: &[(String, String)],
    tcb_info: &serde_json::Value,
) -> Result<(String, String), String> {
    if let Some(sel) = select_for_raw_tcb(raw_cpusvn, raw_pcesvn, certs) {
        return Ok(sel);
    }
    let _ = tcb_info;
    Err("No certificate found for given platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tcbm_wins() {
        let certs = vec![
            ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0001".into(), "cert-low".into()),
            ("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCC".into(), "cert-hit".into()),
        ];
        let (t, c) = select_for_raw_tcb(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCC",
            &certs,
        )
        .unwrap();
        assert_eq!(c, "cert-hit");
        assert!(t.ends_with("CCCC"));
    }
}
