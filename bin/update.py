import typing
from dataclasses import dataclass
from datetime import datetime, UTC, timedelta

import urllib3
import csv

# Update this manually in case CCADB switch issuer / chain of trust.
# DigiCertGlobalRootCA.pem
CCADB_TRUST_ANCHOR = """-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
"""

CCADB_UPSTREAM_CSV = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"

PYTHON_SRC_HEADER = "import ssl\n\nCCADB_BUNDLE: str = \"\"\""
PYTHON_SRC_FOOTER = """def root_der_certificates() -> list[bytes]:
    certificates: list[bytes] = []

    line_ending = "\\n"
    boundary = "-----END CERTIFICATE-----" + line_ending

    for chunk in CCADB_BUNDLE.split(boundary):
        if chunk:
            start_marker = chunk.find("-----BEGIN CERTIFICATE-----" + line_ending)

            if start_marker == -1:
                break

            pem_reconstructed = "".join([chunk[start_marker:], boundary])

            certificates.append(
                ssl.PEM_cert_to_DER_cert(pem_reconstructed)
            )

    return certificates


def certificate_revocation_lists_der() -> list[bytes]:
    return []
"""

@dataclass
class CertificateRecord:
    owner: str
    certificate_issuer_organization: str
    certificate_issuer_organizational_unit: str
    common_name_or_certificate_name: str
    certificate_serial_number: str
    sha256_fingerprint: str
    subject_spki_sha256: str
    valid_from_gmt: str
    valid_to_gmt: str
    public_key_algorithm: str
    signature_hash_algorithm: str
    trust_bits: str
    distrust_for_tls_after_date: str
    distrust_for_smime_after_date: str
    ev_policy_oids: str
    approval_bug: str
    nss_release_when_first_included: str
    firefox_release_when_first_included: str
    test_website_valid: str
    test_website_expired: str
    test_website_revoked: str
    mozilla_applied_constraints: str
    company_website: str
    geographic_focus: str
    certificate_policy_cp: str
    certification_practice_statement_cps: str
    certificate_practice_policy_statement_cp_cps: str
    standard_audit: str
    netsec_audit: str
    tls_br_audit: str
    tls_evg_audit: str
    smime_br_audit: str
    audit_firm: str
    standard_audit_type: str
    standard_audit_statement_dt: str
    pem_info: str


def decode_stream_to_unicode(response: urllib3.HTTPResponse) -> typing.Iterator[str]:
    for data in response:
        yield data.decode()


def parse_ccadb_csv(response: urllib3.HTTPResponse) -> typing.Iterator[CertificateRecord]:
    for row in csv.DictReader(decode_stream_to_unicode(response)):
        yield CertificateRecord(
            owner=row["Owner"],
            certificate_issuer_organization=row["Certificate Issuer Organization"],
            certificate_issuer_organizational_unit=row["Certificate Issuer Organizational Unit"],
            common_name_or_certificate_name=row["Common Name or Certificate Name"],
            certificate_serial_number=row["Certificate Serial Number"],
            sha256_fingerprint=row["SHA-256 Fingerprint"],
            subject_spki_sha256=row["Subject + SPKI SHA256"],
            valid_from_gmt=row["Valid From [GMT]"],
            valid_to_gmt=row["Valid To [GMT]"],
            public_key_algorithm=row["Public Key Algorithm"],
            signature_hash_algorithm=row["Signature Hash Algorithm"],
            trust_bits=row["Trust Bits"],
            distrust_for_tls_after_date=row["Distrust for TLS After Date"],
            distrust_for_smime_after_date=row["Distrust for S/MIME After Date"],
            ev_policy_oids=row["EV Policy OID(s)"],
            approval_bug=row["Approval Bug"],
            nss_release_when_first_included=row["NSS Release When First Included"],
            firefox_release_when_first_included=row["Firefox Release When First Included"],
            test_website_valid=row["Test Website - Valid"],
            test_website_expired=row["Test Website - Expired"],
            test_website_revoked=row["Test Website - Revoked"],
            mozilla_applied_constraints=row["Mozilla Applied Constraints"],
            company_website=row["Company Website"],
            geographic_focus=row["Geographic Focus"],
            certificate_policy_cp=row["Certificate Policy (CP)"],
            certification_practice_statement_cps=row["Certification Practice Statement (CPS)"],
            certificate_practice_policy_statement_cp_cps=row["Certificate Practice & Policy Statement (CP/CPS)"],
            standard_audit=row["Standard Audit"],
            netsec_audit=row["NetSec Audit"],
            tls_br_audit=row["TLS BR Audit"],
            tls_evg_audit=row["TLS EVG Audit"],
            smime_br_audit=row["S/MIME BR Audit"],
            audit_firm=row["Audit Firm"],
            standard_audit_type=row["Standard Audit Type"],
            standard_audit_statement_dt=row["Standard Audit Statement Dt"],
            pem_info=row["PEM Info"],
        )


if __name__ == "__main__":

    to_be_inserted_ca: list[CertificateRecord] = []

    expired_count = 0
    not_yet_valid_count = 0
    unsuitable_trust_bit_count = 0
    manually_untrusted_count = 0

    with urllib3.PoolManager(ca_cert_data=CCADB_TRUST_ANCHOR) as pm:
        resp = pm.urlopen(
            "GET",
            CCADB_UPSTREAM_CSV,
            redirect=False,
            retries=False,
            preload_content=False
        )

        assert resp.status == 200
        assert "text/csv" in resp.headers["content-type"]

        current_date = datetime.now(tz=UTC)

        for ca in parse_ccadb_csv(resp):

            # CHECKS
            # 1) Eligible for websites (server auth)
            # 2) Within dates (i.e. not expired, currently valid)
            # 3) Not invalid for TLS soon

            print(f"> Assert if '{ca.common_name_or_certificate_name}' can be inserted in trust store")

            if "websites" not in ca.trust_bits.lower():
                unsuitable_trust_bit_count += 1
                print("\t>! Not trusted for SERVER AUTH")
                continue

            valid_from = datetime.fromisoformat(f"{ca.valid_from_gmt.replace('.', '-')}T00:00:00+00:00")
            valid_to = datetime.fromisoformat(f"{ca.valid_to_gmt.replace('.', '-')}T00:00:00+00:00")

            if valid_from > current_date:
                not_yet_valid_count += 1
                print("\t>! Not yet valid")
                continue

            if current_date > valid_to:
                expired_count += 1
                print("\t>! Not longer valid")
                continue

            if ca.distrust_for_tls_after_date:
                no_longer_tls_acceptable_after = datetime.fromisoformat(f"{ca.distrust_for_tls_after_date.replace('.', '-')}T00:00:00+00:00")

                # there is a grace period of 398 days
                # This grace period allows extant certificates issued before the distrust date to
                # remain valid for their lifetime.
                no_longer_tls_acceptable_after += timedelta(days=398)

                if current_date > no_longer_tls_acceptable_after:
                    manually_untrusted_count += 1
                    print("\t>! Manually untrusted for TLS")
                    continue

            print("\t> OK")
            to_be_inserted_ca.append(ca)

    with open("../wassima/_os/_embed.py", "w") as fp:

        fp.write(
            PYTHON_SRC_HEADER
        )

        for ca in to_be_inserted_ca:

            fp.write(
                f"# Owner: {ca.owner}\n# Organization: {ca.certificate_issuer_organization}\n# Common Name: {ca.common_name_or_certificate_name}\n# SHA-256: {ca.sha256_fingerprint}\n"
            )

            fp.write(ca.pem_info[1:-1].replace("\\n", "\n"))
            fp.write("\n\n")

        fp.write("\"\"\"\n\n")

        fp.write(
            PYTHON_SRC_FOOTER
        )

    print(f"> {len(to_be_inserted_ca)} Trust Anchors Saved!")
    print(f"> {expired_count} expired CAs")
    print(f"> {not_yet_valid_count} not yet valid CAs")
    print(f"> {manually_untrusted_count} manually untrusted for TLS CAs")
    print(f"> {unsuitable_trust_bit_count} unsuitable for server auth CAs")
