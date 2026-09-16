import concurrent.futures
import csv
import io
import json
import os
import signal
import sys
import threading
import time
import zipfile

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import requests

TARGET_URL = os.getenv("TARGET_DOH")
if not TARGET_URL:
    print("[ERROR] TARGET_DOH environment variable is not set.")
    print("Usage: TARGET_DOH=\"https://your-dns-endpoint/dns-query\" ./run.sh")
    sys.exit(1)

GOOGLE_URL = "https://dns.google/dns-query"
CLOUDFLARE_URL = "https://cloudflare-dns.com/dns-query"

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_CSV = "tranco.csv"
CHECKPOINT_FILE = "checkpoint.txt"
DIFF_LOG_JSONL = "diff_log.jsonl"
DIFF_LOG_TXT = "diff_log.txt"

QUERY_TIMEOUT = float(os.getenv("TIMEOUT", "5.0"))
DELAY_BETWEEN_DOMAINS = float(os.getenv("DELAY", "0"))
WANT_DNSSEC = os.getenv("WANT_DNSSEC", "0").strip().lower() in ("1", "true", "yes", "on")
CONCURRENCY = int(os.getenv("CONCURRENCY", "10"))

stop_requested = False

def sigint_handler(sig, frame):
    global stop_requested
    print("\n[INFO] Graceful shutdown requested. Finishing current domains...")
    stop_requested = True

signal.signal(signal.SIGINT, sigint_handler)

_thread_local = threading.local()

def get_session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _thread_local.session = s
    return _thread_local.session

def ensure_tranco_list():
    if os.path.exists(TRANCO_CSV):
        return

    print("[INFO] Tranco list not found. Downloading top-1m.csv.zip...")
    resp = requests.get(TRANCO_URL, stream=True, timeout=60)
    resp.raise_for_status()

    print("[INFO] Extracting archive...")
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        for name in z.namelist():
            if name.endswith(".csv"):
                with z.open(name) as src, open(TRANCO_CSV, "wb") as dst:
                    dst.write(src.read())
                break
    print(f"[INFO] Extracted Tranco list to {TRANCO_CSV}")

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as f:
                return int(f.read().strip())
        except ValueError:
            return 0
    return 0

def save_checkpoint(index):
    with open(CHECKPOINT_FILE, "w") as f:
        f.write(str(index))

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
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        if resp.status_code != 200:
            return None, f"HTTP_{resp.status_code}", latency_ms
        msg = dns.message.from_wire(resp.content)
        return msg, None, latency_ms
    except requests.exceptions.Timeout:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return None, "TIMEOUT", latency_ms
    except Exception as e:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return None, f"ERR_{type(e).__name__}", latency_ms

def normalize_response(msg, err, latency_ms):
    if err:
        return {
            "status": "ERROR",
            "error": err,
            "rcode": None,
            "answers": [],
            "cnames": [],
            "ad_bit": False,
            "latency_ms": latency_ms,
        }

    rcode_str = dns.rcode.to_text(msg.rcode())
    ad_bit = bool(msg.flags & dns.flags.AD)
    answers = []
    cnames = []

    for rrset in msg.answer:
        for rdata in rrset:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                answers.append(rdata.to_text().strip())
            elif rrset.rdtype == dns.rdatatype.CNAME:
                cnames.append(rdata.to_text().rstrip(".").lower())

    answers.sort()
    cnames.sort()

    return {
        "status": "OK",
        "error": None,
        "rcode": rcode_str,
        "answers": answers,
        "cnames": cnames,
        "ad_bit": ad_bit,
        "latency_ms": latency_ms,
    }

def records_strictly_equal(resp1, resp2):
    if resp1["status"] != "OK" or resp2["status"] != "OK":
        return False
    if resp1["rcode"] != resp2["rcode"]:
        return False
    if resp1["answers"] != resp2["answers"]:
        return False
    if resp1["cnames"] != resp2["cnames"]:
        return False
    return True

def dnssec_ad_equal(resp1, resp2):
    return resp1.get("ad_bit") == resp2.get("ad_bit")

def evaluate_domain(current_index, rank, domain):
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
        query_msg = dns.message.make_query(
            ascii_domain,
            dns.rdatatype.A,
            want_dnssec=WANT_DNSSEC,
        )
        wire_data = query_msg.to_wire()
    except Exception:
        return current_index, rank, domain, None

    session = get_session()
    t_msg, t_err, t_lat = query_doh(session, TARGET_URL, wire_data)
    g_msg, g_err, g_lat = query_doh(session, GOOGLE_URL, wire_data)
    c_msg, c_err, c_lat = query_doh(session, CLOUDFLARE_URL, wire_data)

    t_norm = normalize_response(t_msg, t_err, t_lat)
    g_norm = normalize_response(g_msg, g_err, g_lat)
    c_norm = normalize_response(c_msg, c_err, c_lat)

    return current_index, rank, domain, (t_norm, g_norm, c_norm, t_lat, g_lat, c_lat)

def main():
    ensure_tranco_list()
    start_index = load_checkpoint()

    print(f"[CONFIG] Target DoH:       {TARGET_URL}")
    print(f"[CONFIG] Google DoH:       {GOOGLE_URL}")
    print(f"[CONFIG] Cloudflare DoH:   {CLOUDFLARE_URL}")
    print(f"[CONFIG] DNSSEC Active:    {WANT_DNSSEC} (DO=1 query flag & AD bit verification)")
    print(f"[CONFIG] Concurrency:      {CONCURRENCY}")
    print(f"[CONFIG] Resuming at:      Domain index #{start_index + 1}")

    total_tested = 0
    passed = 0
    dnssec_validated = 0
    dnssec_diffs = 0
    consensus_diffs = 0
    split_diffs = 0
    target_errors = 0
    reference_failures = 0
    all_three_errors = 0

    with open(TRANCO_CSV, "r", encoding="utf-8") as f_in, \
         open(DIFF_LOG_JSONL, "a", encoding="utf-8") as f_json, \
         open(DIFF_LOG_TXT, "a", encoding="utf-8") as f_txt:

        reader = csv.reader(f_in)

        futures = set()
        active_indices = set()
        last_submitted_index = start_index - 1

        def handle_result(result):
            nonlocal total_tested, passed, dnssec_validated, dnssec_diffs
            nonlocal consensus_diffs, split_diffs, target_errors, reference_failures, all_three_errors

            current_index, rank, domain, eval_data = result
            active_indices.discard(current_index)

            if eval_data is None:
                return

            t_norm, g_norm, c_norm, t_lat, g_lat, c_lat = eval_data
            total_tested += 1

            log_discrepancy = False
            severity = "INFO"
            category = ""
            tag = ""

            # 1. Total network drop across all three endpoints
            if t_norm["status"] == "ERROR" and g_norm["status"] == "ERROR" and c_norm["status"] == "ERROR":
                all_three_errors += 1
                severity = "INFO"
                category = "ALL_THREE_ERROR"
                tag = "NETWORK_BLIP"
                log_discrepancy = True

            # 2. Target resolver failure (reference resolver succeeded)
            elif t_norm["status"] == "ERROR":
                target_errors += 1
                severity = "HIGH"
                category = f"TARGET_ERROR_{t_norm['error']}"
                tag = "TARGET_FAIL"
                log_discrepancy = True

            # 3. Both reference resolvers failed, but target answered
            elif g_norm["status"] == "ERROR" and c_norm["status"] == "ERROR":
                reference_failures += 1
                severity = "INFO"
                category = "REFERENCE_FAILURE_BOTH"
                tag = "REF_FAILURE"
                log_discrepancy = True

            # 4. Comparative evaluation
            else:
                valid_refs = []
                if g_norm["status"] == "OK":
                    valid_refs.append(("Google", g_norm))
                if c_norm["status"] == "OK":
                    valid_refs.append(("Cloudflare", c_norm))

                matches_any_ans = any(records_strictly_equal(t_norm, ref[1]) for ref in valid_refs)

                if WANT_DNSSEC:
                    matches_any_full = any(
                        records_strictly_equal(t_norm, ref[1]) and dnssec_ad_equal(t_norm, ref[1])
                        for ref in valid_refs
                    )
                else:
                    matches_any_full = matches_any_ans

                if matches_any_full:
                    passed += 1
                    if t_norm["ad_bit"]:
                        dnssec_validated += 1
                else:
                    log_discrepancy = True

                    # Record matched, but DNSSEC AD bit differed
                    if matches_any_ans and WANT_DNSSEC:
                        dnssec_diffs += 1
                        tag = "DNSSEC_DIFF"
                        if len(valid_refs) == 2 and dnssec_ad_equal(g_norm, c_norm):
                            ref_ad = g_norm["ad_bit"]
                            if ref_ad and not t_norm["ad_bit"]:
                                severity = "HIGH"
                                category = "DNSSEC_AD_MISSING (Refs=Secure AD=1, Target=Insecure AD=0)"
                            elif not ref_ad and t_norm["ad_bit"]:
                                severity = "MEDIUM"
                                category = "DNSSEC_AD_UNEXPECTED (Refs=Insecure AD=0, Target=Secure AD=1)"
                            else:
                                severity = "MEDIUM"
                                category = "DNSSEC_AD_MISMATCH"
                        else:
                            severity = "LOW"
                            category = f"DNSSEC_REF_SPLIT_AD (Target={t_norm['ad_bit']}, G={g_norm['ad_bit']}, CF={c_norm['ad_bit']})"

                    # Record data differed
                    else:
                        if len(valid_refs) == 2:
                            references_agree = records_strictly_equal(g_norm, c_norm)
                            if references_agree:
                                consensus_diffs += 1
                                severity = "HIGH"
                                tag = "CONSENSUS_DIFF"
                                if t_norm["rcode"] != g_norm["rcode"]:
                                    category = f"CONSENSUS_RCODE_DIFF (Target={t_norm['rcode']} vs Ref={g_norm['rcode']})"
                                elif not t_norm["answers"] and g_norm["answers"]:
                                    category = "CONSENSUS_EMPTY_ANSWER"
                                else:
                                    category = "CONSENSUS_ANSWER_DIFF"
                            else:
                                split_diffs += 1
                                tag = "SPLIT_DIFF"
                                if t_norm["rcode"] != "NOERROR":
                                    severity = "MEDIUM"
                                    category = f"REF_SPLIT_TARGET_RCODE_{t_norm['rcode']}"
                                else:
                                    severity = "LOW"
                                    category = "REFERENCE_SPLIT_TARGET_UNIQUE_IP"
                        else:
                            consensus_diffs += 1
                            severity = "MEDIUM"
                            tag = "SINGLE_REF_DIFF"
                            survivor_name = valid_refs[0][0]
                            category = f"DIFF_AGAINST_ONLY_SURVIVING_REF ({survivor_name})"

            if log_discrepancy:
                log_entry = {
                    "index": current_index + 1,
                    "rank": rank,
                    "domain": domain,
                    "severity": severity,
                    "category": category,
                    "want_dnssec": WANT_DNSSEC,
                    "latency_ms": {
                        "target": t_lat,
                        "google": g_lat,
                        "cloudflare": c_lat,
                    },
                    "ad_flags": {
                        "target": t_norm["ad_bit"],
                        "google": g_norm["ad_bit"],
                        "cloudflare": c_norm["ad_bit"],
                    },
                    "target": t_norm,
                    "google": g_norm,
                    "cloudflare": c_norm,
                    "timestamp": int(time.time()),
                }

                f_json.write(json.dumps(log_entry) + "\n")
                f_json.flush()

                human_msg = (
                    f"[{current_index + 1}] {domain} -> [{severity}] {category}\n"
                    f"  Target:     RCODE={t_norm['rcode']} ANS={t_norm['answers']} CNAME={t_norm['cnames']} AD={t_norm['ad_bit']} LAT={t_lat}ms ERR={t_norm['error']}\n"
                    f"  Google:     RCODE={g_norm['rcode']} ANS={g_norm['answers']} CNAME={g_norm['cnames']} AD={g_norm['ad_bit']} LAT={g_lat}ms ERR={g_norm['error']}\n"
                    f"  Cloudflare: RCODE={c_norm['rcode']} ANS={c_norm['answers']} CNAME={c_norm['cnames']} AD={c_norm['ad_bit']} LAT={c_lat}ms ERR={c_norm['error']}\n"
                    f"{'-' * 75}\n"
                )
                f_txt.write(human_msg)
                f_txt.flush()

                print(f"[{tag}] #{current_index + 1} {domain}: {category} (Target: {t_lat}ms)")

            if total_tested % 100 == 0:
                safe_checkpoint = min(active_indices) if active_indices else last_submitted_index + 1
                save_checkpoint(safe_checkpoint)
                dnssec_stat = f"DNSSEC Validated: {dnssec_validated} | DNSSEC Diff: {dnssec_diffs} | " if WANT_DNSSEC else ""
                print(
                    f"[PROGRESS] Checked: {total_tested} | "
                    f"Passed: {passed} | "
                    f"{dnssec_stat}"
                    f"Consensus Diffs: {consensus_diffs} | "
                    f"Split Diffs: {split_diffs} | "
                    f"Target Errs: {target_errors}"
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            for current_index, row in enumerate(reader):
                if current_index < start_index:
                    continue

                if stop_requested:
                    break

                if not row or len(row) < 2:
                    continue

                rank, domain = row[0].strip(), row[1].strip()

                fut = executor.submit(evaluate_domain, current_index, rank, domain)
                futures.add(fut)
                active_indices.add(current_index)
                last_submitted_index = current_index

                if DELAY_BETWEEN_DOMAINS > 0:
                    time.sleep(DELAY_BETWEEN_DOMAINS)

                while len(futures) >= CONCURRENCY * 2:
                    done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                    for f in done:
                        futures.remove(f)
                        handle_result(f.result())

            while futures:
                done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                for f in done:
                    futures.remove(f)
                    handle_result(f.result())

        safe_checkpoint = min(active_indices) if active_indices else last_submitted_index + 1
        save_checkpoint(safe_checkpoint)

        if stop_requested:
            print(f"[INFO] Saved checkpoint at domain index #{safe_checkpoint}. Safe to exit.")
            sys.exit(0)

        print(f"\n[DONE] Finished testing {total_tested} domains.")
        print(
            f"Passed: {passed} | "
            f"DNSSEC Validated: {dnssec_validated} | "
            f"DNSSEC Diffs: {dnssec_diffs} | "
            f"Consensus Diffs: {consensus_diffs} | "
            f"Split Diffs: {split_diffs} | "
            f"Target Errors: {target_errors} | "
            f"Reference Failures: {reference_failures} | "
            f"Network Drops: {all_three_errors}"
        )

if __name__ == "__main__":
    main()
