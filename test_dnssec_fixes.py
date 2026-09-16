#!/usr/bin/env python3
# dns_diff_tester/test_dnssec_fixes.py
#
# Comprehensive DNSSEC regression test covering every domain that was
# diagnosed and fixed during the algorithm-7 / TBS / case-sensitivity /
# SOA-escape / ENT / NSEC3-opt-out debugging sessions.
#
# Usage:
#   TARGET_DOH="https://doh-de.azbrand.ca/dns-query" ./test_dnssec_fixes.py
#
# Exits 0 if all domains match Google/Cloudflare consensus, non-zero otherwise.

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
    print('  Usage: TARGET_DOH="https://your-dns-endpoint/dns-query" ./test_dnssec_fixes.py')
    sys.exit(2)

GOOGLE_URL = "https://dns.google/dns-query"
CLOUDFLARE_URL = "https://cloudflare-dns.com/dns-query"
QUERY_TIMEOUT = float(os.getenv("TIMEOUT", "6.0"))

# (domain, qtype, expected_ad, bug_description)
# expected_ad: True if DNSSEC Secure, False if Insecure.
# The test compares target AD against Google/CF consensus, and also
# flags a mismatch if the consensus itself is split.
DOMAINS = [
    # ---- Group A: algorithm 7 (RSASHA1-NSEC3-SHA1) legacy zones ----
    ("uk.com",          "A", True,  "alg7+1024bit RSA + TBS truncation"),
    ("eu.com",          "A", True,  "alg7+1024bit RSA + TBS truncation"),
    ("us.com",          "A", True,  "alg7+1024bit RSA + TBS truncation"),
    ("co.com",          "A", True,  "alg7+1024bit RSA + TBS truncation"),
    ("de.com",          "A", True,  "alg7+1024bit RSA + TBS truncation"),
    ("uk.net",          "A", True,  "alg7+1024bit RSA + TBS truncation"),

    # ---- Group B: uppercase owner names (RFC 4034 §6.2 lowercase) ----
    ("cmu.edu",         "A", True,  "uppercase CMU.EDU. + mixed DNSKEY case"),

    # ---- Group C: empty non-terminals (go.jp) ----
    ("jra.go.jp",       "A", True,  "go.jp empty non-terminal"),
    ("mhlw.go.jp",      "A", True,  "go.jp empty non-terminal"),

    # ---- Group D: NSEC3 opt-out (wildcard and NXDOMAIN) ----
    ("_wildcard_.ph",   "A", False, "NSEC3 opt-out wildcard"),
    ("hdhub4u.med",     "A", False, "NSEC3 opt-out NXDOMAIN"),
    ("isaidub.ceo",     "A", False, "NSEC3 opt-out NXDOMAIN"),

    # ---- Group E: 1M-sweep DNSSEC diffs (case-insensitivity) ----
    ("ollama.com",      "A", True,  "case-insensitive owner filter"),
    ("kartra.com",      "A", True,  "case-insensitive owner filter"),
    ("adamant.net",     "A", True,  "stale binary / DNSKEY RRSIG preservation"),

    # ---- Group F: .mil SOA with escaped dots ----
    ("apps.mil",        "A", True,  "SOA rname with escaped dots"),
    ("spaceforce.mil",  "A", True,  "SOA rname with escaped dots"),
    ("dfas.mil",        "A", True,  "SOA rname with escaped dots"),
    ("eb.mil",          "A", True,  "SOA rname with escaped dots"),
    ("pentagon.mil",    "A", True,  "SOA rname with escaped dots"),
    ("dod.mil",         "A", True,  "SOA rname with escaped dots"),
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
        return None, "TIMEOUT", round((time.perf_counter() - start) * 1000, 1)
    except Exception as e:
        return None, f"ERR_{type(e).__name__}", round((time.perf_counter() - start) * 1000, 1)

def inspect(msg, err, lat):
    if err:
        return {"status": "ERROR", "error": err, "rcode": None, "ad": False, "lat": lat}
    rcode = dns.rcode.to_text(msg.rcode())
    ad = bool(msg.flags & dns.flags.AD)
    return {"status": "OK", "error": None, "rcode": rcode, "ad": ad, "lat": lat}

def main():
    print("=" * 108)
    print("DNSSEC REGRESSION TEST — every domain fixed this session")
    print(f"Target: {TARGET_URL}")
    print("=" * 108)
    print(f"{'#':>3} | {'DOMAIN':<18} | {'QTYPE':<5} | {'TARGET':<20} | {'GOOGLE':<10} | {'CF':<10} | STATUS  | BUG")
    print("-" * 108)

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    passed = 0
    failed = 0
    errors = 0
    failures = []

    for idx, (domain, qtype, expected_ad, bug) in enumerate(DOMAINS, 1):
        try:
            ascii_domain = domain.encode("idna").decode("ascii")
            q_msg = dns.message.make_query(
                ascii_domain,
                dns.rdatatype.from_text(qtype),
                want_dnssec=True,
            )
            wire = q_msg.to_wire()
        except Exception as e:
            print(f"{idx:>3} | {domain:<18} | {qtype:<5} | ENCODE ERROR: {e}")
            errors += 1
            failures.append(domain)
            continue

        t_msg, t_err, t_lat = query_doh(session, TARGET_URL, wire)
        g_msg, g_err, g_lat = query_doh(session, GOOGLE_URL, wire)
        c_msg, c_err, c_lat = query_doh(session, CLOUDFLARE_URL, wire)

        t = inspect(t_msg, t_err, t_lat)
        g = inspect(g_msg, g_err, g_lat)
        c = inspect(c_msg, c_err, c_lat)

        t_str = f"AD={str(t['ad']):<5} {t['rcode'] or t['error']}"
        g_str = f"AD={str(g['ad']):<5}" if g["status"] == "OK" else g["error"]
        c_str = f"AD={str(c['ad']):<5}" if c["status"] == "OK" else c["error"]

        # Determine reference consensus.
        ref_ad = None
        if g["status"] == "OK" and c["status"] == "OK":
            if g["ad"] == c["ad"]:
                ref_ad = g["ad"]
            else:
                ref_ad = None  # refs split, not a reliable oracle
        elif g["status"] == "OK":
            ref_ad = g["ad"]
        elif c["status"] == "OK":
            ref_ad = c["ad"]

        if t["status"] == "ERROR":
            status = "[ERROR]"
            errors += 1
            failures.append(domain)
        elif ref_ad is None and t["status"] == "OK":
            # Refs split; fall back to expected_ad from our records.
            if t["ad"] == expected_ad:
                status = "[PASS?]"
                passed += 1
            else:
                status = "[SPLIT]"
                failed += 1
                failures.append(domain)
        elif t["ad"] == ref_ad:
            status = "[PASS]"
            passed += 1
        else:
            status = "[FAIL]"
            failed += 1
            failures.append(domain)

        print(
            f"{idx:>3} | {domain:<18} | {qtype:<5} | {t_str:<20} | "
            f"{g_str:<10} | {c_str:<10} | {status:<7} | {bug}"
        )
        time.sleep(0.05)

    print("-" * 108)
    total = len(DOMAINS)
    print(f"RESULTS: {passed}/{total} passed | {failed} failed | {errors} errors")
    if failures:
        print("Failures:")
        for d in failures:
            print(f"  - {d}")
    print("=" * 108)

    sys.exit(0 if (failed == 0 and errors == 0) else 1)

if __name__ == "__main__":
    main()
