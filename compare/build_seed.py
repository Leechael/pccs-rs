#!/usr/bin/env python3
"""Build a shared cache-hit seed from Phala PCCS fixtures + a real sample PCK cert."""
import json
import os
from pathlib import Path
from urllib.parse import unquote

ROOT = Path("/workspace/pccs-rs/compare")
PHALA_TCB = Path("/tmp/phala-tcb.json")
PHALA_TCB_HDR = Path("/tmp/phala-tcb.hdr")
PHALA_QE = Path("/tmp/phala-qe.json")
PHALA_QE_HDR = Path("/tmp/phala-qe.hdr")

QEID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
CPUSVN = "0B0D0202FF010C000000000000000000"
PCESVN = "000D"
PCEID = "0000"
FMSPC = "00A067110000"
TCBM = CPUSVN + PCESVN

# Real Intel SGX PCK leaf + Processor CA + Root from dcap-qvl sample (fmspc 00A067110000).
PCK_LEAF = """-----BEGIN CERTIFICATE-----
MIIEjTCCBDSgAwIBAgIVAIG3dzK3YemOubljpKvR5bm/XdjWMAoGCCqGSM49BAMC
MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMzA5MjAyMTUzNDNaFw0zMDA5MjAyMTUz
NDNaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG
A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
kgmE7N3D+RspyaCZ2YoDTLDCuh5pnvAu4crPn2uAGujq9tOgwU8/y7jttShCB603
U6r+h9ayOk2nZ9jewk25lqOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY
PHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRz
ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjQvcGNrY3JsP2Nh
PXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFIW4KX263PRxYJah2Cfj
AlrcvAC9MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhN
AQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ0E7AbU5tktyQ0K089e4t3zCCAWQG
CiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgELMBAGCyqGSIb4TQENAQIC
AgELMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgECMBEGCyqGSIb4
TQENAQIFAgIA/zAQBgsqhkiG+E0BDQECBgIBATAQBgsqhkiG+E0BDQECBwIBADAQ
BgsqhkiG+E0BDQECCAIBADAQBgsqhkiG+E0BDQECCQIBADAQBgsqhkiG+E0BDQEC
CgIBADAQBgsqhkiG+E0BDQECCwIBADAQBgsqhkiG+E0BDQECDAIBADAQBgsqhkiG
+E0BDQECDQIBADAQBgsqhkiG+E0BDQECDgIBADAQBgsqhkiG+E0BDQECDwIBADAQ
BgsqhkiG+E0BDQECEAIBADAQBgsqhkiG+E0BDQECEQIBDTAfBgsqhkiG+E0BDQEC
EgQQCwsCAv8BAAAAAAAAAAAAADAQBgoqhkiG+E0BDQEDBAIAADAUBgoqhkiG+E0B
DQEEBAYAoGcRAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNHADBEAiBm
SMZEtlQEjnZgGa192W3ArnZ3iyY6ckM/sTsXxCRmJgIgLf20tZHNw3a1b31JDSOW
E6wesxoAmTeqJGRqZl621qI=
-----END CERTIFICATE-----
"""

PCK_INTMD = """-----BEGIN CERTIFICATE-----
MIICmDCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC
MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHExIzAh
BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl
bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB
MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg
tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i
HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww
UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl
cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFNDo
qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMAoGCCqGSM49BAMCA0gAMEUCIQCJgTbtVqOyZ1m3jqiAXM6QYa6r5sWS
4y/G7y8uIJGxdwIgRqPvBSKzzQagBLQq5s5A70pdoiaRJ8z/0uDz4NgV91k=
-----END CERTIFICATE-----
"""

PCK_ROOT = """-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
"""


def header_value(path: Path, name: str) -> str:
    raw = path.read_text(errors="replace")
    key = name.lower() + ":"
    lines = raw.splitlines()
    out = []
    capturing = False
    for line in lines:
        if line.lower().startswith(key):
            capturing = True
            out.append(line.split(":", 1)[1].strip())
            continue
        if capturing:
            if line.startswith(" ") or line.startswith("\t"):
                out.append(line.strip())
            else:
                break
    return unquote("".join(out))


def main():
    tcb = json.loads(PHALA_TCB.read_text())
    qe = json.loads(PHALA_QE.read_text())
    tcb_chain = header_value(PHALA_TCB_HDR, "tcb-info-issuer-chain")
    qe_chain = header_value(PHALA_QE_HDR, "sgx-enclave-identity-issuer-chain")
    pck_chain = PCK_INTMD.strip() + "\n" + PCK_ROOT.strip() + "\n"

    seed = {
        "pckcerts": [
            {
                "qeid": QEID,
                "cpusvn": CPUSVN,
                "pcesvn": PCESVN,
                "pceid": PCEID,
                "tcbm": TCBM,
                "fmspc": FMSPC,
                "ca": "processor",
                "issuer_chain": pck_chain,
                "cert": PCK_LEAF,
            }
        ],
        "platforms": [
            {
                "qe_id": QEID,
                "pce_id": PCEID,
                "cpu_svn": CPUSVN,
                "pce_svn": PCESVN,
                "enc_ppid": "",
                "platform_manifest": "",
                "fmspc": FMSPC,
                "ca": "processor",
            }
        ],
        "tcbinfo": [
            {
                "prod_type": "sgx",
                "fmspc": FMSPC,
                "version": 4,
                "update_type": "STANDARD",
                "issuer_chain": tcb_chain,
                "tcbinfo": tcb,
            }
        ],
        "identities": [
            {
                "enclave_id": 1,
                "name": "qe",
                "version": 4,
                "update_type": "STANDARD",
                "issuer_chain": qe_chain,
                "identity": qe,
            }
        ],
    }
    out = ROOT / "seed.json"
    out.write_text(json.dumps(seed, indent=2))
    print(f"wrote {out} bytes={out.stat().st_size}")
    meta = ROOT / "query_params.json"
    meta.write_text(
        json.dumps(
            {
                "qeid": QEID,
                "cpusvn": CPUSVN,
                "pcesvn": PCESVN,
                "pceid": PCEID,
                "fmspc": FMSPC,
                "tcbm": TCBM,
            },
            indent=2,
        )
    )
    # also dump certs for sqlite seed
    (ROOT / "pck_leaf.pem").write_text(PCK_LEAF)
    (ROOT / "pck_intmd.pem").write_text(PCK_INTMD)
    (ROOT / "pck_root.pem").write_text(PCK_ROOT)


if __name__ == "__main__":
    main()
