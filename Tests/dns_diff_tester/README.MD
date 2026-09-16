Commands to Run
1. Standard Run with Custom Target
code
Bash
cd dns_diff_tester
TARGET_DOH="https://example.com/dns-query" ./run.sh
2. Run with DNSSEC Validation Active
code
Bash
cd dns_diff_tester
TARGET_DOH="https://example.com/dns-query" WANT_DNSSEC=1 ./run.sh
3. Or Export in Your Shell Session (Avoids typing it repeatedly)
code
Bash
cd dns_diff_tester
export TARGET_DOH="https://example.com/dns-query"
export WANT_DNSSEC=1

./run.sh