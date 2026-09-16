# dns_diff_tester/analyze.py
import json
import os
import sys
from collections import Counter

LOG_FILE = "diff_log.jsonl"

def main():
    target_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE

    if not os.path.exists(target_file):
        print(f"[ERROR] Log file not found: {target_file}")
        sys.exit(1)

    severities = Counter()
    categories = Counter()
    target_errors = Counter()

    target_lats = []
    google_lats = []
    cf_lats = []

    ad_target_true = 0
    ad_google_true = 0
    ad_cf_true = 0

    total_records = 0
    dnssec_active = False

    with open(target_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue

            total_records += 1
            sev = entry.get("severity", "UNKNOWN")
            cat = entry.get("category", "UNKNOWN")

            if entry.get("want_dnssec"):
                dnssec_active = True

            severities[sev] += 1
            categories[cat] += 1

            target_err = entry.get("target", {}).get("error")
            if target_err:
                target_errors[target_err] += 1

            ad_flags = entry.get("ad_flags", {})
            if ad_flags.get("target"):
                ad_target_true += 1
            if ad_flags.get("google"):
                ad_google_true += 1
            if ad_flags.get("cloudflare"):
                ad_cf_true += 1

            lats = entry.get("latency_ms", {})
            if "target" in lats and lats["target"] is not None:
                target_lats.append(lats["target"])
            if "google" in lats and lats["google"] is not None:
                google_lats.append(lats["google"])
            if "cloudflare" in lats and lats["cloudflare"] is not None:
                cf_lats.append(lats["cloudflare"])

    print("=" * 65)
    print(f"DIFFERENTIAL TEST ANALYSIS: {target_file}")
    print(f"Total Discrepancies Logged: {total_records}")
    print(f"DNSSEC Mode Enabled:       {dnssec_active}")
    print("=" * 65)

    print("\n[BREAKDOWN BY SEVERITY]")
    for sev, count in severities.most_common():
        pct = (count / total_records) * 100 if total_records else 0
        print(f"  {sev:<10} : {count:>7} ({pct:>5.1f}%)")

    print("\n[TOP 10 DISCREPANCY CATEGORIES]")
    for cat, count in categories.most_common(10):
        pct = (count / total_records) * 100 if total_records else 0
        print(f"  {cat:<48} : {count:>7} ({pct:>5.1f}%)")

    if dnssec_active:
        print("\n[DNSSEC AD=1 (AUTHENTIC DATA) DETECTED IN DISCREPANCIES]")
        print(f"  Target Resolver  : {ad_target_true:>7}")
        print(f"  Google DoH       : {ad_google_true:>7}")
        print(f"  Cloudflare DoH   : {ad_cf_true:>7}")

    if target_errors:
        print("\n[TARGET RESOLVER ERROR BREAKDOWN]")
        for err, count in target_errors.most_common():
            print(f"  {err:<20} : {count:>7}")

    print("\n[LATENCY COMPARISON ON DISCREPANCIES (AVG)]")
    if target_lats:
        print(f"  Target Resolver  : {sum(target_lats)/len(target_lats):>7.2f} ms")
    if google_lats:
        print(f"  Google DoH       : {sum(google_lats)/len(google_lats):>7.2f} ms")
    if cf_lats:
        print(f"  Cloudflare DoH   : {sum(cf_lats)/len(cf_lats):>7.2f} ms")

    print("=" * 65)

if __name__ == "__main__":
    main()
