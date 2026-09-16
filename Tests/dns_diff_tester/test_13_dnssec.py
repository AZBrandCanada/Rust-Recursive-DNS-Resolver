# dns_diff_tester/test_13_dnssec.py
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

# Exactly the 13 DNSSEC domains from your log
EXACT_13_DOMAINS = [
    # 10 that previously had DNSSEC_AD_MISSING (Refs had AD=1, Target had AD=0)
    ("uk.com", "AD_MISSING", True),
    ("eu.com", "AD_MISSING", True),
    ("us.com", "AD_MISSING", True),
    ("jra.go.jp", "AD_MISSING", True),
    ("cmu.edu", "AD_MISSING", True),
    ("co.com", "AD_MISSING", True),
    ("de.com", "AD_MISSING", True),
    ("uk.net", "AD_MISSING", True),
    ("d-net.pro", "AD_MISSING", True),
    ("mhlw.go.jp", "AD_MISSING", True),
    # 3 that previously had DNSSEC_AD_UNEXPECTED (Refs had AD=0, Target had AD=1)
    ("_wildcard_.ph", "AD_UNEXPECTED", False),
    ("hdhub4u.med", "AD_UNEXPECTED", False),
    ("isaidub.ceo", "AD_UNEXPECTED", False),
]

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
        return {"status": "ERROR", "error": err, "rcode": "ERR", "ad": False, "lat": lat}
    rcode = dns.rcode.to_text(msg.rcode())
    ad = bool(msg.flags & dns.flags.AD)
    return {"status": "OK", "error": None, "rcode": rcode, "ad": ad, "lat": lat}

def main():
    print("=" * 82)
    print(f"TESTING EXACT 13 DNSSEC LOGGED DOMAINS")
    print(f"Target: {TARGET_URL}")
    print("=" * 82)
    print(f"{'#':<3} | {'DOMAIN':<18} | {'TARGET':<14} | {'GOOGLE':<10} | {'CF':<10} | {'STATUS'}")
    print("-" * 82)

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    fixed = 0
    failing = 0

    for idx, (domain, prev_issue, expected_ad) in enumerate(EXACT_13_DOMAINS, 1):
        try:
            ascii_domain = domain.encode("idna").decode("ascii")
            q_msg = dns.message.make_query(ascii_domain, dns.rdatatype.A, want_dnssec=True)
            wire = q_msg.to_wire()
        except Exception as e:
            print(f"{idx:<3} | {domain:<18} | Encode Error: {e}")
            continue

        t_msg, t_err, t_lat = query_doh(session, TARGET_URL, wire)
        g_msg, g_err, g_lat = query_doh(session, GOOGLE_URL, wire)
        c_msg, c_err, c_lat = query_doh(session, CLOUDFLARE_URL, wire)

        t = inspect_response(t_msg, t_err, t_lat)
        g = inspect_response(g_msg, g_err, g_lat)
        c = inspect_response(c_msg, c_err, c_lat)

        t_str = f"AD={str(t['ad']):<5} {t['rcode']}" if t["status"] == "OK" else t["error"]
        g_str = f"AD={str(g['ad']):<5}" if g["status"] == "OK" else g["error"]
        c_str = f"AD={str(c['ad']):<5}" if c["status"] == "OK" else c["error"]

        # Check if Target matches reference consensus
        ref_ad = None
        if g["status"] == "OK" and c["status"] == "OK" and g["ad"] == c["ad"]:
            ref_ad = g["ad"]
        elif g["status"] == "OK":
            ref_ad = g["ad"]
        elif c["status"] == "OK":
            ref_ad = c["ad"]

        if t["status"] == "ERROR":
            status = "[ERROR]"
            failing += 1
        elif ref_ad is not None and t["ad"] == ref_ad:
            status = "[FIXED / PASS]"
            fixed += 1
        elif ref_ad is not None and t["ad"] != ref_ad:
            status = "[STILL FAILING]"
            failing += 1
        else:
            if t["ad"] == g["ad"] or t["ad"] == c["ad"]:
                status = "[MATCHES ONE REF]"
                fixed += 1
            else:
                status = "[STILL FAILING]"
                failing += 1

        print(f"{idx:<3} | {domain:<18} | {t_str:<14} | {g_str:<10} | {c_str:<10} | {status}")
        time.sleep(0.05)

    print("-" * 82)
    print(f"RESULTS: {fixed}/13 Passed | {failing}/13 Failing")
    print("=" * 82)

if __name__ == "__main__":
    main()
