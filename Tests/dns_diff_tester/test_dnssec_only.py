# dns_diff_tester/test_dnssec_only.py
import os
import sys
import time
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import requests

TARGET_URL = os.getenv("TARGET_DOH")
if not TARGET_URL:
    print("[ERROR] TARGET_DOH environment variable is not set.")
    print("Usage: TARGET_DOH=\"https://your-dns-endpoint/dns-query\" ./run_dnssec_test.sh")
    sys.exit(1)

GOOGLE_URL = "https://dns.google/dns-query"
CLOUDFLARE_URL = "https://cloudflare-dns.com/dns-query"
QUERY_TIMEOUT = float(os.getenv("TIMEOUT", "6.0"))

DNSSEC_TEST_GROUPS = {
    "CentralNic Sub-Delegations (Algorithm 7 / SHA-1 DS)": [
        "uk.com",
        "eu.com",
        "us.com",
        "co.com",
        "de.com",
        "uk.net",
    ],
    "Educational, Government & ccTLD Signed Domains": [
        "cmu.edu",
        "pitt.edu",
        "sec.gov",
        "fcc.gov",
        "d-net.pro",
        "jra.go.jp",
        "mhlw.go.jp",
    ],
    "Unsigned / Non-Existent TLDs (Should NOT be AD=1)": [
        "_wildcard_.ph",
        "hdhub4u.med",
        "isaidub.ceo",
    ],
    "Control Verified Signed Baselines": [
        "canva.com",
        "fedoraproject.org",
        "huggingface.co",
        "tmdb.org",
    ],
}

def query_doh(session, endpoint, wire_data):
    start = time.perf_counter()
    try:
        resp = session.post(
            endpoint,
            data=wire_data,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
            timeout=QUERY_TIMEOUT,
        )
        lat = round((time.perf_counter() - start) * 1000, 1)
        if resp.status_code != 200:
            return None, f"HTTP_{resp.status_code}", lat
        msg = dns.message.from_wire(resp.content)
        return msg, None, lat
    except requests.exceptions.Timeout:
        lat = round((time.perf_counter() - start) * 1000, 1)
        return None, "TIMEOUT", lat
    except Exception as e:
        lat = round((time.perf_counter() - start) * 1000, 1)
        return None, f"ERR_{type(e).__name__}", lat

def inspect_response(msg, err, lat):
    if err:
        return {"status": "ERROR", "error": err, "rcode": "ERR", "ad": False, "answers": [], "lat": lat}
    rcode = dns.rcode.to_text(msg.rcode())
    ad = bool(msg.flags & dns.flags.AD)
    answers = []
    for rrset in msg.answer:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for rdata in rrset:
                answers.append(rdata.to_text().strip())
    answers.sort()
    return {"status": "OK", "error": None, "rcode": rcode, "ad": ad, "answers": answers, "lat": lat}

def main():
    print("=" * 80)
    print(f"DNSSEC VALIDATION RETEST: {TARGET_URL}")
    print("=" * 80)

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    total = 0
    passed = 0
    failed = 0

    for group_name, domain_list in DNSSEC_TEST_GROUPS.items():
        print(f"\n--- {group_name} ---")
        print(f"{'DOMAIN':<24} | {'TARGET (AD/RCODE)':<20} | {'GOOGLE (AD)':<12} | {'CF (AD)':<12} | {'RESULT'}")
        print("-" * 80)

        for domain in domain_list:
            total += 1
            try:
                ascii_domain = domain.encode("idna").decode("ascii")
                q_msg = dns.message.make_query(ascii_domain, dns.rdatatype.A, want_dnssec=True)
                wire = q_msg.to_wire()
            except Exception as e:
                print(f"{domain:<24} | IDN Encode Error: {e}")
                continue

            t_msg, t_err, t_lat = query_doh(session, TARGET_URL, wire)
            g_msg, g_err, g_lat = query_doh(session, GOOGLE_URL, wire)
            c_msg, c_err, c_lat = query_doh(session, CLOUDFLARE_URL, wire)

            t = inspect_response(t_msg, t_err, t_lat)
            g = inspect_response(g_msg, g_err, g_lat)
            c = inspect_response(c_msg, c_err, c_lat)

            # Determine expected AD state based on reference consensus
            ref_ad = None
            if g["status"] == "OK" and c["status"] == "OK" and g["ad"] == c["ad"]:
                ref_ad = g["ad"]
            elif g["status"] == "OK":
                ref_ad = g["ad"]
            elif c["status"] == "OK":
                ref_ad = c["ad"]

            target_repr = f"AD={str(t['ad']):<5} {t['rcode']:<8}" if t["status"] == "OK" else f"{t['error']:<14}"
            google_repr = f"AD={str(g['ad']):<5}" if g["status"] == "OK" else f"{g['error']:<10}"
            cf_repr = f"AD={str(c['ad']):<5}" if c["status"] == "OK" else f"{c['error']:<10}"

            # Evaluation
            if t["status"] == "ERROR":
                result = "[TARGET ERROR]"
                failed += 1
            elif ref_ad is not None:
                if t["ad"] == ref_ad:
                    if t["ad"]:
                        result = "[PASS - SECURE]"
                    else:
                        result = "[PASS - INSECURE]"
                    passed += 1
                else:
                    if ref_ad and not t["ad"]:
                        result = "[FAIL - AD MISSING]"
                    else:
                        result = "[FAIL - AD UNEXPECTED]"
                    failed += 1
            else:
                if t["ad"] == g["ad"] or t["ad"] == c["ad"]:
                    result = "[PASS - MATCHES ONE REF]"
                    passed += 1
                else:
                    result = "[FAIL - AD SPLIT DIFF]"
                    failed += 1

            print(f"{domain:<24} | {target_repr:<20} | {google_repr:<12} | {cf_repr:<12} | {result}")
            time.sleep(0.05)

    print("\n" + "=" * 80)
    print(f"DNSSEC RETEST SUMMARY: {passed}/{total} Passed ({failed} Failed)")
    print("=" * 80)

if __name__ == "__main__":
    main()
