# Unified Recursive DNS Server

A high-performance, lightweight, multi-protocol **iterative recursive DNS resolver written in Rust**, with an optional **geo-aware authoritative GSLB layer** for steering clients to the optimal backend node.

The server provides standard DNS over **UDP/TCP**, **DNS-over-TLS (DoT)**, **DNS-over-QUIC (DoQ)**, **DNS-over-HTTPS (DoH)** (HTTP/1.1 and HTTP/2), and **DNS-over-HTTP/3 (DoH3)** (QUIC) while resolving domains directly through the DNS hierarchy—from the root servers to authoritative nameservers—without forwarding queries to third-party recursive resolvers such as Google Public DNS, Cloudflare, or Quad9.

The resolver combines a client-independent canonical cache with full DNSSEC validation, authenticated positive and negative responses, DNSKEY/DS trust chains, NSEC/NSEC3 denial proofs, CNAME/DNAME processing, RFC 1982 DNSSEC time arithmetic, ML-DSA-44 DNSSEC verification, stale-answer handling, rate limiting, anti-amplification defenses, and SSRF-resistant iterative resolution.

Optionally, the same process can act as a small authoritative nameserver for a configured set of GSLB names (e.g. `dns.example.com`) and return region-appropriate backend addresses to each client. This is described in **Geo-Aware DNS Steering** below.
![Unified DNS Banner](Photo/DNS.jpeg)

---

## Architecture

All inbound transports share a single resolution pipeline. Transport-specific protocol handling occurs at the edge; recursive resolution, DNSSEC validation, caching, and client response construction are centralized.

A key architectural property is the strict separation between **canonical resolver state** and **client-specific wire representation**.

The cache stores validated DNS data and its explicit DNSSEC security state. It does **not** store client-specific flags such as transaction IDs, RD/CD/AD state, or DO-dependent wire representations.

When GSLB is enabled, a second major architectural property is that **authoritative GSLB answers never enter the recursive cache**. The GSLB decision is computed per-request from in-memory state, and the same qname can return different answers to different clients without poisoning any shared cache.

```text
       UDP :53 ─────┐
       TCP :53 ─────┤
  DoT TCP :853 ─────┤
  DoQ UDP :853 ─────┤
  DoH TCP :443 ─────┤
 DoH3 UDP :443 ─────┤
      DoH :3053 ────┘
                     │
                     ▼
          Inbound Transport & Framing
          ───────────────────────────
          • DNS UDP/TCP
          • RFC 7766 TCP framing
          • RFC 7858 DoT (ALPN: dot)
          • RFC 9250 DoQ (DNS over QUIC, ALPN: doq)
          • RFC 8484 DoH (HTTP/1.1 & HTTP/2)
          • RFC 9114 / RFC 9000 DoH3 (HTTP/3 over QUIC, ALPN: h3)
          • 65,535-byte UDP receive buffer
                     │
                     ▼
          Request Parsing & Controls
          ──────────────────────────
          • Single-question enforcement
          • EDNS Client Subnet extraction
          • Subnet token bucket
          • UDP duplicate-domain RRL
          • ANY query handling
                     │
                     ▼
          ┌────────────────────────────┐
          │  qname ∈ GSLB names?       │
          └──────┬──────────────┬──────┘
                 │ yes          │ no
                 ▼              ▼
       Geo-Authoritative    Answer Cache Lookup
       Steering             ───────────────────
       ────────────         • {qname}:{qtype}:IN
       • per-request        • Fresh / Stale / Expired
       • GeoIP + ECS        • Bounded by moka W-TinyLFU
       • health scoring            │
       • single A/AAAA     MISS ───┴─── HIT
       • never cached              │
                 │                 ▼
                 │       Single-Flight Gate
                 │       ───────────────────
                 │       • Coalesces concurrent
                 │         identical misses
                 │                 │
                 │                 ▼
                 │       Iterative Recursive Resolution
                 │       ──────────────────────────────
                 │       • Root-zone / delegation cache
                 │       • Root → TLD → authoritative
                 │       • Bailiwick validation
                 │       • CNAME/DNAME traversal
                 │       • IPv4-prioritized NS racing
                 │                 │
                 │                 ▼
                 │         DNSSEC Validation
                 │         ─────────────────
                 │         • DS/DNSKEY chains
                 │         • RRSIG validation
                 │         • NSEC/NSEC3 proofs
                 │         • ML-DSA-44
                 │                 │
                 │          ┌──────┴──────┐
                 │          ▼             ▼
                 │  Canonical Data   DnssecStatus
                 │          └──────┬──────┘
                 │                 ▼
                 │            CacheEntry
                 │                 │
                 │                 ▼
                 │       Client Response Construction
                 │                 │
                 └─────────────────┤
                                   ▼
                          Final DNS Response
```

### Canonical Cache Model

Each cache entry contains:

* Canonical validated DNS response data
* Effective cache TTL
* Cache timestamps
* Explicit `DnssecStatus`
* Positive / Negative classification

Client-specific properties are generated only when serving the response.

This avoids maintaining separate DO=0 and DO=1 caches and prevents one client's DNS flags from leaking into another client's response.

### Cache Layer Overview

The resolver maintains several logically separate caches, each with its own lifecycle and trust model:

| Layer | Key | TTL source | Purpose |
| --- | --- | --- | --- |
| Answer cache | `{qname}:{qtype}:IN` | min(RR TTL, RRSIG remaining validity) | Canonical validated responses |
| Negative cache | `{qname}:{qtype}:IN` (tagged `Negative`) | SOA MINTTL bounded | Authenticated NXDOMAIN / NODATA |
| Delegation cache | zone name | NS / glue TTL, capped | Learned and root-zone-sourced delegations |
| DNSSEC key cache | zone name | min(DNSKEY TTL, parent DS TTL) | Authenticated zone keys |
| DNSSEC signedness cache | zone name | DS proof TTL | Proven-signed / proven-unsigned zones |
| Root zone | TLD name (pre-populated) | Zone file TTL, capped | Root zone lifecycle |
| Hit tracker | `{qname}:{qtype}:IN` | n/a | Popularity for prefetch decisions |
| GSLB state | node name | n/a | Health + last RTT, per-node |

These layers have independent expiration and invalidation behavior. A root zone update does not flush the answer cache. A TTL expiry on an individual delegation does not trigger a root zone refresh. A GSLB health transition does not invalidate any cached recursive answer.

---

# Features

## Multi-Protocol Transport

### Concurrent DNS, DoT, DoQ, DoH, and DoH3

The server concurrently supports:

* Plain DNS over UDP (port 53)
* Plain DNS over TCP (port 53)
* DNS-over-TLS on TCP port 853
* DNS-over-QUIC on UDP port 853
* DNS-over-HTTPS (HTTP/1.1 and HTTP/2) on TCP port 443
* DNS-over-HTTP/3 (HTTP/3 over QUIC) on UDP port 443
* Reverse-proxy DoH backend mode

All transports eventually enter the same recursive resolution and validation engine.

### RFC 9250 DoQ (DNS-over-QUIC)

The resolver implements full RFC 9250 DNS-over-QUIC support:

* Binds to UDP port 853 with ALPN `doq`
* Processes individual queries over client-initiated bidirectional QUIC streams
* Employs 2-octet length prefix framing per RFC 9250 §4.2
* Returns RFC 9250 application reset codes (`0x2` for `DOQ_PROTOCOL_ERROR`, `0x4` for `DOQ_EXCESSIVE_LOAD`)
* Eliminates Head-of-Line (HoL) blocking and supports 0-RTT connection resumption

### RFC 8484 DoH (HTTP/1.1 & HTTP/2)

The DoH implementation supports standard RFC 8484 request forms:

* `GET` with a base64url-encoded `dns` parameter
* `POST` with an `application/dns-message` body

HTTP request validation distinguishes protocol errors from DNS resolution errors:

* Missing `dns` parameter → `400 Bad Request`
* Empty `dns` parameter → `400 Bad Request`
* Malformed DNS wire message → `400 Bad Request`
* Missing/invalid POST `Content-Type` → `415 Unsupported Media Type`
* Incompatible `Accept` header → `406 Not Acceptable`
* Rate-limited request → `429 Too Many Requests`
* Valid DNS query producing `SERVFAIL` → `200 OK` with DNS wire response

The DoH router also exposes operational endpoints:

* `GET /health` — lightweight liveness probe
* `GET /metrics` — JSON snapshot of cache, single-flight, prefetch, and root zone state

### RFC 9114 / RFC 9000 DoH3 (DNS-over-HTTP/3)

The server implements native HTTP/3 transport over QUIC:

* Binds to UDP port 443 with ALPN `h3`
* Eliminates transport-layer Head-of-Line (HoL) blocking across multiplexed DNS queries
* Supports 0-RTT session resumption and connection migration across client network transitions
* Advertises HTTP/3 availability via `Alt-Svc: h3=":443"; ma=86400`
* Shares the exact same request validation, canonical caching, and DNSSEC pipeline as DoH
* Serves `/dns-query`, `/health`, and `/metrics`

### DNS TCP and DoT Framing

TCP and DoT use standard two-byte DNS message length framing.

The maximum DNS message payload is **65,535 bytes**, the largest value representable by the DNS two-byte length field.

The server supports:

* Persistent connections
* Multiple queries per connection
* TCP pipelining
* TLS connections with ALPN `dot`
* 10-second idle timeout
* 5-second active I/O timeout
* Clean handling of EOF and socket failures

### UDP Receive Handling

The application receive buffer is sized to **65,535 bytes**, preventing application-level truncation of otherwise valid UDP datagrams.

The resolver separately enforces an operational **4,096-byte maximum inbound UDP query size**, rejecting unusually large requests before recursive processing.

### Reverse-Proxy Mode

DoH can operate without local TLS using:

```text
DOH_NO_TLS=1
```

This allows Nginx, Caddy, Envoy, or another reverse proxy to terminate HTTPS/H3 while forwarding HTTP traffic to the resolver backend.

### Development Certificates

When configured TLS certificate files are unavailable, the server can generate a self-signed development certificate automatically.

On Unix systems, generated private keys are protected with restrictive `0600` permissions.

### Unprivileged Port Fallback

When privileged ports cannot be bound (e.g., running without root or `CAP_NET_BIND_SERVICE`), the server automatically falls back to:

| Service | Transport | Privileged Port | Fallback Port | Environment Variable |
| ------- | :-------: | --------------: | ------------: | -------------------- |
| DNS     | UDP / TCP |              53 |          5053 | `DNS_PORT`           |
| DoT     |    TCP    |             853 |          8853 | `DOT_PORT`           |
| DoQ     |    UDP    |             853 |          8853 | `DOQ_PORT`           |
| DoH     |    TCP    |             443 |          8443 | `DOH_PORT`           |
| DoH3    |    UDP    |             443 |          8443 | `DOH3_PORT`          |

### Bounded Concurrency

Tokio semaphores limit concurrent work to reduce resource exhaustion:

* Plain UDP: 2,048 permits
* Plain TCP: 512 permits
* DoT (TCP): 512 permits
* DoQ (QUIC/UDP): 512 permits
* DoH (TCP): 512 permits
* DoH3 (QUIC/UDP): 512 permits

---

# Iterative Recursive Resolution

## Direct Root-to-Authoritative Resolution

The resolver does not forward requests to public recursive DNS services.

Resolution begins at the IANA root server system, or at the closest cached delegation discovered during a previous query:

```text
Root
  │
  ▼
TLD
  │
  ▼
Authoritative nameservers
  │
  ▼
Final RRset
```

The resolver independently follows referrals until the requested data or authenticated denial proof is obtained.

## Delegation Cache

Every delegation discovered during recursion is cached separately from answer data. A single resolution of `www.example.com` populates:

```text
com.         → .com gTLD servers
example.com. → example.com authoritative servers
```

Subsequent queries for `mail.example.com`, `api.example.com`, or any other name inside `example.com` reuse the cached delegation and query the correct authoritative servers directly, without re-walking the root or `com` delegation.

The delegation cache performs a **closest-ancestor lookup**: for a query for `a.b.c.example.com`, it searches for cached delegations at `b.c.example.com`, `c.example.com`, `example.com`, `com`, and `.`, in that order, and uses the most specific match.

This is what prevents the resolver from querying the root servers once per user domain. In steady state, root server traffic is vanishingly small relative to total query volume.

## Root Zone Support

The resolver can optionally load the IANA root zone file and pre-populate the delegation cache with all TLD delegations at startup. With the root zone loaded, the very first query for any `.com` domain begins directly at the `.com` gTLD servers instead of the network root servers.

The root zone has its own lifecycle, independent of the answer and delegation caches:

* Loaded from a local JSON cache, if present and fresh
* Otherwise loaded from a local text file (`root.zone`)
* Otherwise downloaded in the background from IANA at startup
* Periodically re-downloaded in-process on a configurable schedule
* Atomically swapped into the delegation cache without touching dynamically-learned delegations

Root-zone-sourced delegations are tagged with `DelegationSource::RootZone` in the delegation cache. This allows the root zone manager to update them without discarding delegations learned during normal resolution.

Root zone entries have their own TTL cap (7 days) distinct from the delegation cache TTL cap (48 hours). A stale root zone does not prevent the resolver from operating; if the cached root zone is unusable, resolution falls back to live root server queries transparently.

## Dual-Stack Nameserver Racing

Authoritative nameserver addresses are collected from both IPv4 and IPv6 records.

Candidates are:

1. Validated against the resolver's safe-address policy
2. Ordered with IPv4 prioritized
3. Queried concurrently in batches of three

IPv4 prioritization reduces failures on systems without functional IPv6 routing while retaining IPv6 support.

## CNAME Chain Traversal

When an authoritative response contains multiple CNAME hops, the resolver follows the chain directly within the response whenever possible.

This avoids unnecessary network requests when the authoritative server has already supplied subsequent links in the chain.

## DNAME Synthesis

The resolver implements RFC 6672 DNAME processing.

When a DNAME redirects a queried name, the resolver:

1. Performs canonical suffix substitution
2. Synthesizes the required CNAME when necessary
3. Preserves the DNAME's TTL
4. Validates the resulting chain
5. Returns `YXDOMAIN` when the synthesized name exceeds the DNS maximum name length

## DNSSEC Material Preservation

When CNAME or DNAME responses are merged across resolution stages, the resolver preserves the DNSSEC material required to validate each step, including relevant:

* RRSIG
* NSEC
* NSEC3
* DNSKEY

records.

This prevents response-merging logic from accidentally discarding cryptographic evidence needed by the validator.

## Strict Authoritative Acceptance

Authoritative responses are not accepted merely because they contain an `AA` flag.

Empty authoritative responses must contain meaningful terminal information such as an SOA or valid delegation state. Otherwise, the resolver rejects the response as making no authoritative progress.

## Referral and Bailiwick Validation

Delegation responses are checked for coherent NS information and safe glue.

Glue addresses are accepted directly only when they satisfy the resolver's bailiwick requirements.

Out-of-bailiwick nameserver addresses are resolved independently rather than trusted as arbitrary address hints.

This mitigates cache poisoning attacks involving forged or out-of-bailiwick glue.

## Upstream Response Failover

Authoritative nameservers are treated independently.

Transient or unusable responses such as:

* `SERVFAIL`
* `REFUSED`
* `FORMERR`
* `NOTIMP`

can cause the resolver to fail over to other nameserver candidates rather than immediately abandoning the resolution.

## EDNS Compatibility Fallback

The resolver requests EDNS0 with a 1,232-byte payload size.

When an authoritative server demonstrates broken EDNS behavior—for example through malformed OPT handling or an EDNS-related `FORMERR`—the resolver can retry using plain RFC 1035 DNS.

## TCP Fallback

Responses with `TC=1` are retried over TCP.

TCP connection, write, length-read, and payload-read operations are collectively bounded by a whole-transaction timeout to prevent stalled authoritative servers from consuming resources indefinitely.

## Upstream DNSSEC Queries

Iterative upstream queries are issued with:

```text
RD=0
CD=1
```

The resolver performs DNSSEC validation itself rather than requesting upstream recursive validation.

Setting `CD=1` prevents an upstream validating resolver from interfering with the resolver's own validation decisions.

## Recursion Bounds

The resolver limits recursive work through multiple independent bounds:

* Maximum recursion depth: `16`
* Maximum resolution steps: `16`
* Maximum CNAME/DNAME redirection hops: `16`

Cycle detection prevents repeated traversal of the same resolution state.

## Parent-Zone DS Resolution

DS records are queried from the **parent zone**, not from the child zone.

This follows the DNSSEC delegation model and prevents a child from being treated as authoritative for its own delegation proof.

---

# DNSSEC Validation

The resolver implements DNSSEC validation from the root trust anchor downward.

```text
Root Trust Anchor
       │
       ▼
Root DNSKEY
       │
       ▼
Parent DS
       │
       ▼
Child DNSKEY
       │
       ▼
Child RRSIG
       │
       ▼
Authenticated RRset
```

Validation covers both positive and negative DNS responses.

## Root Trust Anchors

The resolver includes the current root trust anchors:

* Root KSK-2017, Key Tag `20326`
* Root KSK-2024, Key Tag `38696`

Root and intermediate authentication failures are treated as validation failures.

With:

```text
DNSSEC_ENFORCE=1
```

broken DNSSEC validation results in `SERVFAIL`.

With:

```text
DNSSEC_ENFORCE=0
```

validation failures do not produce an authenticated (`AD=1`) response.

> Root trust anchors are embedded in the resolver and must be updated when the IANA DNSSEC root trust-anchor set changes.

## DNSSEC Security States

Every validated cache entry records an explicit security state:

```text
Secure
InsecureUnsigned
InsecureUnknown
Bogus
```

This state is preserved independently from the response wire representation.

## DNSKEY and DS Trust Chains

The validator walks the trust chain from the root toward the target zone.

For each signed delegation it:

1. Resolves the parent DS
2. Validates the DS RRset
3. Resolves the child DNSKEY RRset
4. Matches the DS against the child DNSKEY
5. Validates the DNSKEY RRset
6. Uses authenticated zone keys to validate subsequent RRsets

Authenticated child DNSKEY cache lifetime is bounded by:

```text
min(child DNSKEY TTL, parent DS TTL)
```

This prevents an authenticated DNSKEY from remaining trusted longer than the delegation information that authenticated it.

## KSK/ZSK Trust Model

The validator distinguishes between:

* Keys used to authenticate the DNSKEY RRset
* Zone keys used to authenticate ordinary zone data

The DNSKEY `Zone Key` flag is enforced when selecting keys for ordinary RRset validation.

## RRSIG Time Validation

DNSSEC signature inception and expiration timestamps are treated as 32-bit DNS serial numbers.

RFC 1982 serial-number arithmetic is used instead of naive integer comparison, including across the DNSSEC timestamp rollover boundary.

## Canonical DNSSEC Serialization

DNSSEC verification uses canonical DNS wire serialization.

Owner names and signer names are normalized appropriately before constructing signed data, and RRset members are sorted according to canonical RDATA ordering before digest verification.

The canonical TBS construction is implemented directly rather than relying on the protocol library's built-in serializer, which contains known correctness issues in the current dependency version.

Names with embedded escape sequences (such as SOA `rname` fields containing escaped dots) are handled by iterating raw label bytes rather than re-parsing the ASCII presentation form.

## Authenticated Negative Responses

Negative responses are validated cryptographically rather than trusting `NXDOMAIN` or empty answers by themselves.

The validator supports:

* NODATA
* NXDOMAIN
* Wildcard NODATA
* Wildcard NXDOMAIN
* Authenticated DS nonexistence

### Authenticated SOA

For authoritative negative responses, the SOA RRset is validated against the zone's DNSKEYs before the negative response can be considered `Secure`.

### NSEC

NSEC validation verifies the appropriate denial relationships, including:

* Exact-name existence
* Type bitmap absence
* Wildcard conditions
* NXDOMAIN coverage

### NSEC3

NSEC3 validation implements the closest-provable-encloser model and validates:

* NSEC3 hash ordering
* Closest encloser
* Next-closer coverage
* Wildcard denial
* NODATA conditions
* NXDOMAIN conditions

### NSEC3 Opt-Out

Opt-Out records are treated conservatively.

An Opt-Out proof can establish an insecure delegation for an appropriate **DS query**, but it is not accepted as generic proof that arbitrary records do not exist inside a signed zone.

When an opt-out NSEC3 covers the next-closer name for a non-DS query, the response is treated as Insecure rather than Secure, and `AD` is not set.

### NSEC3 Iteration Limits

NSEC3 records exceeding the configured safe iteration threshold are rejected rather than processed indefinitely.

The implementation follows the operational guidance of RFC 9276 and rejects NSEC3 records advertising more than 150 iterations.

## DS Nonexistence Downgrade Protection

An empty DS response is not automatically interpreted as proof that a delegation is insecure.

The resolver requires authenticated parent-zone denial evidence before treating DS nonexistence as an insecure delegation.

This prevents unauthenticated DS omission from being interpreted as a legitimate downgrade from DNSSEC validation.

---

# Post-Quantum DNSSEC

The resolver supports **ML-DSA-44 / DNSSEC Algorithm 18** in addition to conventional DNSSEC algorithms.

ML-DSA-44 verification is implemented through the RustCrypto `ml-dsa` backend rather than relying exclusively on protocol-library support.

The implementation follows:

* NIST FIPS 204
* DNSSEC Algorithm 18 specifications

ML-DSA-44 signatures and public keys are substantially larger than conventional DNSSEC signatures, so Algorithm 18 responses frequently exceed the 1,232-byte EDNS payload target.

The resolver automatically falls back to TCP when an authoritative server truncates such responses.

---

# Cryptographic Verification Backends

The DNSSEC engine uses multiple verification backends.

### Classical Cryptography

The optimized `ring` backend handles supported:

* RSA/SHA-256
* RSA/SHA-512
* ECDSA P-256/SHA-256
* ECDSA P-384/SHA-384
* Ed25519

RSA keys are bounded to the supported 2,048–8,192-bit range.

### Legacy RSA/SHA-1

Algorithm 5 (RSASHA1) and Algorithm 7 (RSASHA1-NSEC3-SHA1) are still deployed across a significant portion of the DNSSEC tree, most notably the CentralNic-operated legacy `.com`-style zones (`uk.com`, `eu.com`, `us.com`, `co.com`, `de.com`, `uk.net`) and several university and government zones (`cmu.edu`, `*.go.jp`, `*.mil`).

These zones frequently publish 1,024-bit RSA ZSKs, which fall below the `ring` backend's minimum modulus floor. The resolver includes a pure-Rust RSA/SHA-1 verification path specifically to handle these keys.

### Post-Quantum Cryptography

The RustCrypto `ml-dsa` backend handles:

* ML-DSA-44
* DNSSEC Algorithm 18

### Native Protocol Fallback

Remaining supported DNSSEC algorithms are delegated to the native `hickory-proto` verification implementation where appropriate.

---

# Cryptographic Resource Limits

DNSSEC validation is subject to a per-query cryptographic work budget.

```text
PER_VALIDATION_MAX_SIG_CHECKS = 24
```

The same validation budget is carried across the validation process rather than independently resetting for each stage.

The budget applies across:

* Positive RRset validation
* Negative proof validation
* DS validation
* DNSKEY validation
* DNSKEY self-signatures
* Other signature verification stages

This limits algorithmic CPU consumption from deliberately complex DNSSEC responses and mitigates KeyTrap-style denial-of-service attacks.

---

# Caching Engine

The cache is designed around canonical DNS state rather than client-specific DNS responses.

Cache keys are:

```text
{qname}:{qtype}:IN
```

Each cache entry contains:

```text
Canonical DNS response
Effective TTL
Cache timestamps
DnssecStatus
EntryKind (Positive or Negative)
```

There is no separate DO=0/DO=1 cache.

## Bounded Capacity and Eviction

The answer cache is bounded by `CACHE_MAX_ENTRIES` (default 500,000). Admission and eviction use W-TinyLFU, which is designed for the heavily skewed access patterns typical of DNS traffic: a small number of popular names receive the majority of queries, and a naive LRU evicts hot records in favor of a burst of cold ones.

The cache is sharded internally. Reads are lock-free and unrelated keys do not contend.

Negative entries share the same cache and are tagged `EntryKind::Negative`, allowing per-class metrics and future per-class eviction policies.

## Single-Flight Coalescing

The miss path is wrapped in a per-key single-flight gate.

When N clients concurrently request the same uncached `{qname}:{qtype}`, exactly one of them becomes the leader and performs the recursive resolution; the other N-1 wait on the leader's result and receive an identical response when it completes.

The gate is keyed by `{qname}:{qtype}:IN`. Unrelated queries remain fully parallel. The cache-level read is not held behind any global lock.

Background stale revalidation uses a separate, narrower gate so a stale revalidation of one record does not block a live miss on a different record.

## Background Prefetch

Cache entries are prefetched in the background when they are both **hot** and **nearing expiration**.

The prefetch loop runs on a fixed tick. Each tick it prunes idle keys from the hit tracker, then iterates the tracker (not the whole cache) and considers each key for refresh. A key is eligible when:

* Its cache entry is still Fresh
* Its remaining TTL is below `CACHE_PREFETCH_THRESHOLD_PCT` of the original TTL
* It has accumulated at least `CACHE_PREFETCH_MIN_HITS` hits
* It is not inside the exponential backoff window after a prior failed refresh

Eligible keys are refreshed through the same single-flight gate as a live miss, so a query arriving during prefetch coalesces with it. A random subset of eligible keys is accepted per tick, and each refresh is delayed by a short random jitter, to avoid synchronized refresh storms after a restart or cache warmup.

Failed prefetches are subject to exponential backoff. A failed prefetch never invalidates the still-valid cached entry: the entry continues to be served until it genuinely expires, at which point normal stale-serving policy applies.

## DNSSEC-Aware Effective TTL

For `Secure` data, the effective cache lifetime is bounded by the remaining validity of the RRSIGs required to authenticate the cached data.

Conceptually:

```text
effective_ttl =
    min(normal_min_ttl,
        remaining_required_rrsig_validity)
```

RRSIG expiration is calculated using RFC 1982 serial arithmetic.

This ensures authenticated data cannot remain `Fresh` beyond the validity of the signatures authenticating it.

## Dynamic TTL Aging

Cached DNS record TTLs are aged when responses are served:

```text
remaining_ttl = max(effective_ttl - age, 0)
```

The cryptographic `Original TTL` contained inside RRSIG RDATA is never modified.

EDNS OPT records are excluded from ordinary DNS TTL aging.

## Cache Freshness

Each cache entry has one of three runtime freshness states.

### Fresh

```text
age < effective TTL
```

The response is served immediately with dynamically aged record TTLs.

### Stale

```text
effective TTL <= age < effective TTL + MAX_STALE_SECS
```

The response can be served under RFC 8767 stale-answer handling.

Stale responses receive a positive **30-second wire TTL** and trigger asynchronous background revalidation.

Stale DNSSEC responses always clear:

```text
AD=0
```

### Expired

```text
age >= effective TTL + MAX_STALE_SECS
```

The cached response is no longer served.

The resolver performs synchronous recursive resolution instead.

If resolution fails, the resolver returns `SERVFAIL` rather than resurrecting an expired response.

## Client-Specific Response Construction

The canonical cache is converted into a client-specific DNS response only at request time.

The response builder:

1. Ages client-visible TTLs
2. Retrieves the stored DNSSEC security state
3. Determines whether `AD` can be set
4. Applies the client's DO/CD/AD signaling
5. Filters DNSSEC records when appropriate
6. Injects the client transaction ID
7. Echoes appropriate request flags
8. Constructs the client EDNS response
9. Applies response-size policy

For a `Secure` response, `AD=1` requires:

* Validated `DnssecStatus::Secure`
* Fresh cache data
* Appropriate client DNSSEC signaling
* `CD=0`

Stale responses never receive `AD=1`.

## Test Mode

Caching can be disabled at runtime via:

```text
CACHE_ENABLED=0
```

When disabled:

* Cache reads are skipped
* Cache writes are skipped
* Single-flight remains active, so concurrent identical misses still coalesce

This allows behavioral comparison between "resolver with cache" and "resolver without cache" without changing the binary.

## Persistent Cache Hygiene

Cache entries are persisted periodically and on clean shutdown.

Persistence uses an atomic temporary-file write followed by rename.

At startup:

* Entries missing explicit `dnssec_status` are discarded
* Expired entries are discarded
* Entries outside the allowable stale window are discarded
* Valid entries are restored without assuming an unverified DNSSEC state

This deliberately avoids silently assigning a security state to legacy cache data.

## Tranco Pre-Warming

Optional startup pre-warming can populate the cache using the Tranco Top 1M list.

Pre-warmed responses pass through normal recursive resolution and DNSSEC validation.

Secure responses use the same DNSSEC-aware effective TTL calculation as ordinary cache entries.

---

# Geo-Aware DNS Steering (GSLB)

The resolver can act as a small authoritative GSLB for a configured set of names (typically one per service endpoint, e.g. `dns.example.com`). When a query arrives for one of these names, the resolver selects a backend node based on the client's apparent location and the node's measured health, then returns a **single** A or AAAA record with that node's address.

## Placement in the Request Path

The GSLB check runs **before** the recursive cache lookup:

```
incoming query
      │
      ▼
  parse + validate
      │
      ▼
  rate limit
      │
      ▼
  ┌─────────────────────────────────┐
  │  qname ∈ GEO_AUTHORITATIVE_NAMES │
  └────┬─────────────────────┬───────┘
       │ yes                 │ no
       ▼                     ▼
  GSLB authoritative     recursive cache
  (per-request decision) (shared cache)
       │                     │
       ▼                     ▼
  single A/AAAA         canonical response
```

This guarantees that per-client decisions never enter the shared recursive cache, and that two clients with different geographic origins can receive different answers for the same qname without either poisoning the other. The GSLB path is entirely separate from the recursive resolver: it does not use the delegation cache, the DNSSEC validator, or the answer cache.

When the GSLB is disabled, the resolver behaves exactly as before for all names.

## Node Configuration

Nodes are configured entirely through environment variables. The configuration format supports an unbounded number of nodes; adding `NODE4_*`, `NODE5_*`, etc. requires no code changes.

Per-node variables use the form `NODE<N>_<FIELD>` where `<N>` starts at 1 and increments without gaps:

| Field | Required | Description |
| --- | --- | --- |
| `NODE<N>_NAME` | yes | Unique node identifier, used in logs and metrics |
| `NODE<N>_IPV4` | one of IPv4/IPv6 | IPv4 address returned to A queries |
| `NODE<N>_IPV6` | one of IPv4/IPv6 | IPv6 address returned to AAAA queries |
| `NODE<N>_LOCATION` | no | Human-readable region tag (informational only) |
| `NODE<N>_LAT` | recommended | Latitude for geographic scoring |
| `NODE<N>_LON` | recommended | Longitude for geographic scoring |
| `NODE<N>_ENABLED` | no (default `true`) | Set to `false` to disable a node without removing its configuration |

The parser walks `NODE1_*`, `NODE2_*`, … until it finds an unset `NODE<N>_NAME`. There is no upper bound.

Example configuration for three nodes:

```ini
Environment=NODE1_NAME=asia-1
Environment=NODE1_IPV4=101.212.112.112
Environment=NODE1_LOCATION=asia
Environment=NODE1_LAT=1.3521
Environment=NODE1_LON=103.8198
Environment=NODE1_ENABLED=true

Environment=NODE2_NAME=europe-1
Environment=NODE2_IPV4=191.221.231.111
Environment=NODE2_LOCATION=europe
Environment=NODE2_LAT=52.5200
Environment=NODE2_LON=13.4050
Environment=NODE2_ENABLED=true

Environment=NODE3_NAME=usa-1
Environment=NODE3_IPV4=191.221.102.212
Environment=NODE3_LOCATION=north_america
Environment=NODE3_LAT=40.7128
Environment=NODE3_LON=-74.0060
Environment=NODE3_ENABLED=true
```

Nodes without a configured IPv6 address are automatically excluded from AAAA selection. If no node has IPv6, AAAA queries for the GSLB name return **NODATA** (NOERROR with an empty answer), which is the correct response for a name that has no AAAA records.

## Client Location Determination

The client's location is derived from, in order of preference:

1. **EDNS Client Subnet (ECS)** — when the upstream resolver (Google, Cloudflare, etc.) includes an ECS option, the subnet's network address is used as the GeoIP lookup key. This is the accurate case: the public resolver is telling us where the actual client is.
2. **Raw source IP** — when ECS is absent, the connection's source address is used. This is accurate when the client speaks directly to the resolver (DoH to your own endpoint, or plain DNS from a stub), and inaccurate when the query comes through a third-party recursive resolver (the source IP is the resolver's own egress address).

The ECS subnet is masked to the advertised prefix length before being used, so full client precision is never stored.

The GeoIP lookup uses a local MaxMind GeoLite2-City database (`GEOIP_DATABASE`, default `GeoLite2-City.mmdb` in the working directory). Only the country code and latitude/longitude are read from the database; no other fields are queried.

If the GeoIP lookup fails (missing database, unknown IP, private address), the client is treated as "unknown location" and scoring degenerates to non-geographic inputs (health and any available latency). This does not cause an error; the request is served with whatever information is available.

## Selection Algorithm

Each eligible node receives a weighted score:

```
score = 0.5 * geo_score + 0.3 * latency_score + 0.2 * health_score
```

Where each component is in `[0.0, 1.0]`:

| Component | 1.0 at | 0.5 at | Notes |
| --- | --- | --- | --- |
| `geo_score` | 0 km | 5000 km | Haversine distance from client to node |
| `latency_score` | 0 ms | 100 ms | Last successful health-check RTT |
| `health_score` | healthy | degraded | Static per state |

Unhealthy nodes are excluded entirely. Nodes missing geo or latency data receive a neutral `0.5` for that component, which makes the formula degrade gracefully to whichever components are available. On a cold start (no health data yet), the formula reduces to nearly pure geographic steering, which is the desired behavior.

The scores are computed per request and never cached. This keeps the decision fresh as client location or node health changes.

## Health Checking

Every enabled node is probed independently on `GEO_HEALTH_INTERVAL` (default 30 seconds). The probe is a minimal UDP DNS query (`example.com A`) sent to the node's configured address on port 53. Success is measured as a valid DNS response within 3 seconds; the RTT is recorded and fed into the scoring formula.

Health state transitions use a three-state machine with hysteresis:

```
Unknown ──2 successes──► Healthy ──3 failures──► Degraded ──5 failures──► Unhealthy
   │                        ▲                                              │
   └─── 3 failures ──► Unhealthy                                            │
                            │                                              │
                            └──────────────── 2 successes ─────────────────┘
```

Health checks are bounded to a maximum of three concurrent probes. Only the node addresses parsed from `NODE<N>_IPV4` and `NODE<N>_IPV6` are ever probed; no hostname from query data is used as a health-check target. This closes the obvious SSRF vector.

If a node has both IPv4 and IPv6 configured, only the IPv4 address is probed. IPv6-only nodes are probed over IPv6.

## Delegating a GSLB Name

The resolver answers a GSLB name authoritatively only if that name is delegated to it in DNS. This section describes how to set up that delegation correctly.

### Prerequisites

- A parent zone you control (`example.com` in the examples below)
- At least one node address reachable over port 53 from the public internet
- Ability to add NS records and glue A/AAAA records in the parent zone's DNS panel

The parent zone may be DNSSEC-signed. The delegated child zone is not signed (see the **DNSSEC Status** subsection below).

### Choosing Nameserver Hostnames

The classic pitfall is choosing nameserver hostnames for the delegated zone. Two patterns are common:

**Nested (works, but requires glue):**
```
dns.example.com.      NS  ns1.dns.example.com.
dns.example.com.      NS  ns2.dns.example.com.
ns1.dns.example.com.  A   1.2.3.4
ns2.dns.example.com.  A   5.6.7.8
```

**Flat (recommended):**
```
dns.example.com.      NS  ns1.example.com.
dns.example.com.      NS  ns2.example.com.
ns1.example.com.      A   1.2.3.4
ns2.example.com.      A   5.6.7.8
```

The **flat pattern is strongly preferred**. In the nested pattern, `ns1.dns.example.com` lives inside the delegated zone itself, so resolvers must be given its address as **glue** in the referral from the parent. Many DNS providers do not emit glue reliably, and some resolvers will fail or loop while trying to resolve the nameserver address independently. The flat pattern avoids this entirely: `ns1.example.com` lives in the parent zone, so its A record is regular data and no glue is required.

### Setup in Cloudflare

Assuming the delegated name is `dns.example.com` and the three nodes are the ones configured above:

**Step 1 — Add glue A records for the nameserver hostnames.**

In the DNS panel for `example.com`:

```
Type: A     Name: ns1     Value: 101.212.112.112     Proxy: OFF
Type: A     Name: ns2     Value: 191.221.231.111   Proxy: OFF
Type: A     Name: ns3     Value: 191.221.102.212   Proxy: OFF
```

The **Proxy toggle must be off** (grey cloud). Orange-cloud proxying would terminate the DNS request at Cloudflare, defeating the entire GSLB purpose.

**Step 2 — Delete any existing A records for the delegated name itself.**

If the zone has records such as:

```
dns.example.com    A    1.2.3.4
dns.example.com    A    5.6.7.8
```

delete them. They will be shadowed by the NS records anyway, but leaving them causes confusing warnings and makes the zone harder to reason about.

**Step 3 — Add the NS delegation records.**

```
Type: NS     Name: dns     Value: ns1.example.com
Type: NS     Name: dns     Value: ns2.example.com
Type: NS     Name: dns     Value: ns3.example.com
```

In Cloudflare's UI, `Name: dns` is shorthand for `dns.example.com.`. The `Value` field takes the fully-qualified hostname.

**Step 4 — Do NOT add a DS record.**

If the parent zone is DNSSEC-signed and you add a DS record for the child, DNSSEC-validating resolvers will expect the child to be signed and will reject its unsigned answers. Without a DS record, the child is treated as an **insecure delegation**, which is the correct state until DNSSEC signing for the child zone is implemented (a planned follow-up phase).

### The "Shadowed Records" Warning

After adding the NS records, your DNS provider will likely show a warning like:

> This NS record shadows 3 existing records. As a result, the shadowed records will no longer resolve publicly.

This is **expected and correct**. When a name has an NS record, that name becomes a **zone cut**: the parent zone stops serving any other records at that name, and the child zone becomes authoritative instead. The A records that were previously at `dns.example.com` are now shadowed by the NS delegation, which is exactly what is desired.

Click "View shadowed records" to confirm they are the A records you intended to delete, then delete them explicitly.

### Propagation

Once the NS delegation is in place:

1. Resolvers holding a cached A record for `dns.example.com` will keep using it until the TTL expires (typically 300 seconds).
2. Resolvers holding a cached NS record for `example.com` will keep using it until its TTL expires (typically 86400 seconds, or one day).
3. New queries follow the delegation to your nodes.

During initial deployment, you can force faster propagation by testing with public resolvers you have not used recently, or by using `+trace` to walk the delegation manually from a clean state.

### Verification

From any machine:

```bash
# Direct trace shows the full delegation path
dig dns.example.com A +trace
```

Expected final section:

```
dns.example.com. 300 IN NS ns1.example.com.
dns.example.com. 300 IN NS ns2.example.com.
dns.example.com. 300 IN NS ns3.example.com.
;; Received 606 bytes from 108.162.194.87#53(suzanne.ns.cloudflare.com) in 2 ms

dns.example.com. 30  IN A  101.212.112.112
;; Received 59 bytes from ns1.example.com in 193 ms
```

The last two lines are the key: the answer comes from one of your nodes (as indicated by the `from` field), not from the parent zone's nameservers, and it contains exactly one A record.

From clients in different regions:

```bash
# Each should return a single IP appropriate to that client's region
dig dns.example.com A @1.1.1.1 +short
dig dns.example.com A @8.8.8.8 +short
```

Public resolvers that send EDNS Client Subnet will give the correct regional answer. Public resolvers that do not send ECS will give an answer based on the resolver's own egress location, which may differ from the client's.

### Logging

Every GSLB decision emits a single structured log line:

```
[GEO_ROUTING] decision client_region=DE selected_node=europe-1 qtype=A
    score=0.97 distance_km=301 rtt_ms=0.14 health=healthy
```

Fields:

| Field | Description |
| --- | --- |
| `client_region` | ISO-3166 country code from GeoIP, or `??` if unknown |
| `selected_node` | The chosen node name |
| `qtype` | The query type that triggered the decision |
| `score` | The winning node's composite score |
| `distance_km` | Haversine distance from client to node, if computable |
| `rtt_ms` | Last measured health-check RTT to the selected node |
| `health` | Selected node's current health state |

## DNSSEC Status of the GSLB Name

The GSLB name is currently delegated but not signed:

- The parent zone (`example.com`) may be DNSSEC-signed
- No DS record is published for `dns.example.com`
- The child zone is unsigned

This produces an **insecure delegation** in DNSSEC terms. Validating resolvers accept the answers without setting the AD bit, and without failing validation. The DNS responses are correct; they are simply not cryptographically authenticated.

Signing the child zone (KSK/ZSK generation, RRSIG generation at answer time, DNSKEY publication, DS record at the registrar) is planned as a follow-up phase. Until then, **do not publish a DS record**, as that would cause validating resolvers to reject the unsigned answers.

## Limitations

- **Per-client steering relies on ECS or direct source IP.** Queries arriving through a public resolver that does not send ECS will be steered based on that resolver's own egress location, not the client's. This is inherent to GSLB behind any third-party resolver.
- **Public resolver caching delays re-steering.** A public resolver may cache the answer for the full TTL (30 seconds by default). If a client's best node changes, the resolver will not see the new answer until the TTL expires. Lowering `GEO_ROUTING_TTL` reduces this window at the cost of higher query volume.
- **Health checks are best-effort.** A node that is reachable but severely degraded (e.g. returning slow responses) will be marked Degraded, not Unhealthy, and may still receive some traffic.
- **No cross-node state sharing yet.** Each node's GSLB decision is based solely on its own health data. A node with a broken route to another node may still steer clients to that node. A future phase will add an authenticated peer heartbeat between nodes.

---

# Root Zone Lifecycle

When `ROOT_ZONE_FILE` is configured (or a `root.zone` file exists in the working directory), the resolver manages a local root zone with its own lifecycle.

## Startup Sequence

At startup the resolver attempts, in order:

1. **JSON cache** — if a `root_zone.json` file exists, it is loaded and used immediately. JSON is pre-parsed, so startup is near-instant.
2. **Text file** — if the JSON cache is absent or invalid, the resolver parses `root.zone` from disk.
3. **Background download** — if neither is present, the resolver starts immediately and downloads the root zone in the background. Queries arriving before the download completes fall back to live root server queries.

The resolver never blocks startup on a network fetch.

## Refresh Loop

Once loaded, the root zone is refreshed periodically by an in-process task on a configurable schedule (`ROOT_ZONE_REFRESH_HOURS`, default 168 hours = weekly).

A successful refresh:

1. Parses the newly downloaded zone file
2. Validates the parse produced a plausible result (a minimum delegation count is required)
3. Atomically replaces all `DelegationSource::RootZone` entries in the delegation cache
4. Writes the new text file and JSON cache to disk
5. Updates the root zone status

Dynamically-learned delegations are never touched by a refresh. Only root-zone-sourced entries are updated.

## Atomicity and Failure Handling

If a refresh fails at any stage — network, parse, validation, write — the previous known-good root zone remains in place and in use. The failure is recorded in the status and subject to backoff.

If the root zone file becomes too old (`ROOT_ZONE_MAX_AGE_DAYS`, default 30), the status is marked `TooOld` and the resolver falls back to live root server queries. The root zone is not deleted; a subsequent successful refresh restores validity.

## Status and Metrics

Root zone state is exposed via `/metrics`:

```json
"root_zone": {
    "state": "Valid",
    "serial": 2024092000,
    "loaded_at": 1758100000,
    "tld_count": 1487,
    "file_age_days": 0,
    "source_path": "root.zone",
    "source_url": "https://www.internic.net/domain/root.zone",
    "last_refresh_attempt": 1758100000,
    "last_refresh_success": 1758100000,
    "consecutive_failures": 0
}
```

Possible `state` values:

| State | Meaning |
| --- | --- |
| `Valid` | Loaded and within the fresh age window |
| `StaleButUsable` | Loaded, but older than half the max age |
| `TooOld` | Loaded, but older than the max age; resolver falls back to root servers |
| `Missing` | No root zone file configured or loadable |

## Root Zone vs. Delegation Cache

The root zone and the delegation cache are separate layers.

The root zone contains the root's delegation information. The delegation cache contains both dynamically-learned delegations and root-zone-sourced ones, distinguished by their `DelegationSource` tag.

A root zone update does not flush the answer cache. A TTL expiry on an individual delegation does not trigger a root zone refresh. They have independent expiration mechanisms.

---

# Operational Monitoring

The `/metrics` endpoint returns a JSON snapshot of cache, single-flight, prefetch, and root zone state. It is served by both DoH and DoH3.

```bash
curl -sk https://dns.example.com/metrics | python3 -m json.tool
```

Example response:

```json
{
  "cache": {
    "entries": 110,
    "evictions": 0,
    "hit_ratio": 0.5565,
    "hits": 192,
    "insertions": 81,
    "misses": 153,
    "stale_served": 89
  },
  "negative_cache": {
    "hits": 22,
    "insertions": 11
  },
  "prefetch": {
    "attempts": 3,
    "failure": 0,
    "success": 3
  },
  "root_zone": {
    "state": "Valid",
    "serial": 2024092000,
    "loaded_at": 1758100000,
    "tld_count": 1487,
    "file_age_days": 0,
    "source_path": "root.zone",
    "source_url": "https://www.internic.net/domain/root.zone",
    "last_refresh_attempt": 1758100000,
    "last_refresh_success": 1758100000,
    "consecutive_failures": 0
  },
  "singleflight": {
    "coalesced": 94,
    "in_flight": 0,
    "leaders": 59
  }
}
```

The `/metrics` endpoint is not authenticated. If your DoH deployment is public, consider restricting access at the reverse proxy, either by source IP allowlist or by only exposing the endpoint on a loopback port.

The `/health` endpoint returns a minimal liveness payload:

```json
{ "status": "healthy", "cached_records": 110 }
```

---

# Resolver Hardening

## SSRF Protection

Nameserver addresses obtained through delegation and glue are validated before being used for outbound connections.

The resolver rejects unsafe address ranges including:

### IPv4

* Private networks
* Loopback
* Link-local
* Carrier-grade NAT
* Benchmark/testing ranges
* Multicast
* Unspecified
* Other prohibited special-use ranges

### IPv6

* Loopback
* Link-local
* Unique Local Addresses
* Multicast
* Unspecified
* IPv4-mapped unsafe addresses

Cloud metadata addresses such as `169.254.169.254` are therefore not accepted as recursive upstream targets.

This prevents malicious DNS delegation data from turning the recursive resolver into an SSRF primitive.

The GSLB health checker applies the same restriction: only node addresses explicitly configured through `NODE<N>_IPV4` and `NODE<N>_IPV6` are ever probed.

## Reverse-Proxy Header Protection

Headers such as:

```text
CF-Connecting-IP
X-Real-IP
X-Forwarded-For
```

are trusted only when the immediate connection originates from loopback.

Remote clients cannot simply inject proxy headers to impersonate another source address.

---

# Rate Limiting and Abuse Protection

## Subnet Token Bucket

Traffic is aggregated by:

* IPv4 `/24`
* IPv6 `/64`

Token acquisition uses atomic compare-and-update operations to avoid negative token balances under concurrent load.

## Transport Isolation

Connection-oriented transports—TCP, DoT, DoQ, DoH, and DoH3—use the subnet token bucket without UDP duplicate-domain penalties.

This avoids incorrectly penalizing legitimate pipelined or multiplexed DNS connections.

## UDP Duplicate-Domain RRL

UDP duplicate queries (plain DNS) are tracked per domain and time epoch.

The policy is:

```text
1st duplicate → allowed
2nd duplicate → TC=1 challenge
3rd+ duplicate → temporary drop
```

The per-second epoch and counter are updated atomically.

This provides an inexpensive response-rate control mechanism without introducing global locks.

## RRL Memory Bound

The duplicate-domain tracking table is capped at:

```text
65,536 entries
```

When capacity is reached, new domains fall back to normal token-bucket processing rather than causing global UDP traffic to be dropped.

## ANY Queries

UDP `ANY` queries are dropped immediately to reduce their usefulness as amplification vectors.

---

# Environment Variables

## Core

| Variable                    |            Default | Description                                                                  |
| --------------------------- | -----------------: | ---------------------------------------------------------------------------- |
| `HOST`                      |          `0.0.0.0` | Bind address for all listeners                                               |
| `DNS_PORT`                  |               `53` | Plain DNS port (UDP and TCP); falls back to `5053` when unprivileged         |
| `DOT_PORT`                  |              `853` | DNS-over-TLS port (TCP); falls back to `8853` when unprivileged               |
| `DOQ_PORT`                  |              `853` | DNS-over-QUIC port (UDP); falls back to `8853` when unprivileged              |
| `DOH_PORT`                  |              `443` | DNS-over-HTTPS (HTTP/1.1 & HTTP/2) port (TCP); falls back to `8443`           |
| `DOH3_PORT`                 |              `443` | DNS-over-HTTP/3 (QUIC) port (UDP); falls back to `8443`                       |
| `DOH_NO_TLS`                |                `0` | Set to `1` when TLS is terminated upstream by a reverse proxy                |
| `DNSSEC_ENFORCE`            |                `1` | Return `SERVFAIL` when DNSSEC validation fails                               |
| `MAX_STALE_SECS`            |              `300` | Maximum stale-serving window                                                 |
| `RATE_LIMIT_BURST`          |              `300` | Token-bucket burst capacity per client subnet                                |
| `RATE_LIMIT_PER_SEC`        |               `60` | Token-bucket refill rate per second                                          |
| `CERT_PATH`                 |    `fullchain.pem` | TLS certificate chain                                                        |
| `KEY_PATH`                  |      `privkey.pem` | TLS private key                                                              |
| `RUST_LOG`                  |             `info` | Tracing filter                                                               |

## Cache

| Variable                    |            Default | Description                                                                  |
| --------------------------- | -----------------: | ---------------------------------------------------------------------------- |
| `CACHE_FILE`                |       `cache.json` | Persistent cache path; relative paths resolve against the working directory  |
| `CACHE_ENABLED`             |                `1` | Set to `0` to disable answer-cache reads and writes                          |
| `CACHE_MAX_ENTRIES`         |          `500000` | Maximum number of cached answer/negative entries                             |
| `CACHE_PREFETCH`            |                `1` | Enable or disable background prefetch of hot records                         |
| `CACHE_PREFETCH_THRESHOLD_PCT` |            `15` | Prefetch threshold as a percentage of original TTL                          |
| `CACHE_PREFETCH_MIN_HITS`   |                `5` | Minimum hits before a record is eligible for prefetch                        |
| `HIT_TRACKER_MAX_ENTRIES`   |         `100000` | Maximum keys tracked for popularity scoring                                  |

## Pre-Warming

| Variable                    |            Default | Description                                                                  |
| --------------------------- | -----------------: | ---------------------------------------------------------------------------- |
| `WARM_LIMIT`                |                `0` | Number of Tranco domains to pre-warm; `0` disables pre-warming               |
| `WARM_CONCURRENCY`          |                `6` | Maximum concurrent pre-warming operations                                    |
| `TRANCO_FILE`               | `tranco_list.txt` | Tranco list cache path; relative paths resolve against the working directory |

## Root Zone

| Variable                    |            Default | Description                                                                  |
| --------------------------- | -----------------: | ---------------------------------------------------------------------------- |
| `ROOT_ZONE_FILE`            |        `root.zone` | Local root zone text file; relative paths resolve against working directory  |
| `ROOT_ZONE_CACHE`           |   `root_zone.json` | Pre-parsed JSON cache; derived from `ROOT_ZONE_FILE` if unset                |
| `ROOT_ZONE_URL`             | `https://www.internic.net/domain/root.zone` | Source URL for root zone downloads |
| `ROOT_ZONE_MAX_AGE_DAYS`    |               `30` | Age after which the root zone is considered too old                          |
| `ROOT_ZONE_REFRESH_HOURS`   |             `168` | In-process root zone refresh interval                                        |

## Geo-Aware GSLB

| Variable                    |            Default | Description                                                                  |
| --------------------------- | -----------------: | ---------------------------------------------------------------------------- |
| `GEO_ROUTING_ENABLED`       |                `0` | Set to `1` to enable the GSLB layer                                          |
| `GEO_AUTHORITATIVE_NAMES`   |          *(unset)* | Comma-separated list of names this resolver is authoritative for             |
| `GEOIP_DATABASE`            |          *(unset)* | Path to MaxMind GeoLite2-City `.mmdb` database                               |
| `GEO_ROUTING_TTL`           |               `30` | TTL of the returned A/AAAA record                                            |
| `GEO_HEALTH_INTERVAL`       |               `30` | Seconds between health probes per node                                       |
| `GEO_HYSTERESIS_PCT`        |               `15` | Minimum score delta required to switch nodes (reserved)                      |
| `GEO_DEFAULT_NODE`          |          *(unset)* | Node name used when no eligible node exists (fallback)                       |
| `NODE<N>_NAME`              |          *(unset)* | Unique node identifier; unset `NODE<N>_NAME` terminates the list             |
| `NODE<N>_IPV4`              |          *(unset)* | IPv4 address returned to A queries                                           |
| `NODE<N>_IPV6`              |          *(unset)* | IPv6 address returned to AAAA queries                                        |
| `NODE<N>_LOCATION`          |          *(unset)* | Human-readable region tag (informational)                                    |
| `NODE<N>_LAT`               |          *(unset)* | Latitude for geographic scoring                                              |
| `NODE<N>_LON`               |          *(unset)* | Longitude for geographic scoring                                             |
| `NODE<N>_ENABLED`           |             `true` | Set to `false` to disable a node                                             |
| `GEO_IP_FAILOVER_IP`        |             `1 or 2 or 3+ or N ` | Set to `false` to disable a node                               |
---

# Building

The project requires Rust and Cargo.

```bash
cargo build --release
```

The resulting executable is:

```text
./target/release/unified-dns
```

For privileged ports, either run with the appropriate capability or use the configured high-port fallbacks.

For example:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/unified-dns
```

---

# Post-Quantum DNS Response Size

ML-DSA-44 signatures are significantly larger than conventional DNSSEC signatures:

```text
ML-DSA-44 signature: 2,420 bytes
ML-DSA-44 public key: 1,312 bytes
```

Consequently, DNS responses containing Algorithm 18 signatures can exceed the 1,232-byte EDNS payload target recommended for avoiding IP fragmentation.

The resolver handles `TC=1` responses by retrying the query over TCP.

---

# Deployment

## Option A, Standalone Deployment

The resolver terminates DoT, DoQ, DoH (HTTP/1.1 and HTTP/2), and DoH3 (HTTP/3 over QUIC) directly.

Example systemd service with GSLB enabled:

```ini
[Unit]
Description=Unified Recursive DNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=doh
Group=doh
WorkingDirectory=/var/lib/unified-dns
ExecStart=/usr/local/bin/unified-dns

# Listener configuration
Environment="HOST=0.0.0.0"
Environment="DNS_PORT=53"
Environment="DOT_PORT=853"
Environment="DOQ_PORT=853"
Environment="DOH_PORT=443"
Environment="DOH3_PORT=443"
Environment="DOH_NO_TLS=0"

# DNSSEC enforcement
Environment="DNSSEC_ENFORCE=1"

# Rate limits and stale serving
Environment="MAX_STALE_SECS=300"
Environment="RATE_LIMIT_BURST=300"
Environment="RATE_LIMIT_PER_SEC=60"

# TLS
Environment="CERT_PATH=/etc/letsencrypt/live/dns.example.com/fullchain.pem"
Environment="KEY_PATH=/etc/letsencrypt/live/dns.example.com/privkey.pem"

# Cache
Environment="CACHE_FILE=cache.json"
Environment="CACHE_MAX_ENTRIES=500000"
Environment="CACHE_PREFETCH=1"

# Root zone — relative paths resolve against WorkingDirectory
#Environment="ROOT_ZONE_FILE=root.zone"
#Environment="ROOT_ZONE_REFRESH_HOURS=168"

# Geo-aware GSLB
Environment="GEO_IP_FAILOVER_IP=3"
Environment="GEO_ROUTING_ENABLED=1"
Environment="GEO_AUTHORITATIVE_NAMES=dns.example.com"
Environment="GEOIP_DATABASE=GeoLite2-City.mmdb"
Environment="GEO_ROUTING_TTL=30"
Environment="GEO_HEALTH_INTERVAL=30"

Environment="NODE1_NAME=asia-1"
Environment="NODE1_IPV4=101.212.112.112"
Environment="NODE1_LOCATION=asia"
Environment="NODE1_LAT=1.3521"
Environment="NODE1_LON=103.8198"
Environment="NODE1_ENABLED=true"

Environment="NODE2_NAME=europe-1"
Environment="NODE2_IPV4=191.221.231.111"
Environment="NODE2_LOCATION=europe"
Environment="NODE2_LAT=52.5200"
Environment="NODE2_LON=13.4050"
Environment="NODE2_ENABLED=true"

Environment="NODE3_NAME=usa-1"
Environment="NODE3_IPV4=191.221.102.212"
Environment="NODE3_LOCATION=north_america"
Environment="NODE3_LAT=40.7128"
Environment="NODE3_LON=-74.0060"
Environment="NODE3_ENABLED=true"

# Logging
Environment="RUST_LOG=info,unified_dns=info"

Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now unified-dns.service
```

Optional first-time setup for GSLB:

```bash
# Fetch root zone (for recursive performance)
sudo -u doh curl -sS -o /var/lib/unified-dns/root.zone \
    https://www.internic.net/domain/root.zone

# Download MaxMind GeoLite2-City (requires free MaxMind account)
# https://www.maxmind.com/en/geolite2/signup
sudo -u doh cp GeoLite2-City.mmdb /var/lib/unified-dns/
```

Then configure the delegation in your parent zone's DNS panel as described in the **Delegating a GSLB Name** section above.

---

## Option B, Reverse Proxy Deployment

A reverse proxy can terminate public HTTPS and HTTP/3 while the resolver listens locally in unencrypted HTTP mode.

Example architecture:

```text
Internet
   │
   ├─► Nginx :443 (TCP - HTTP/1.1 & HTTP/2)
   │
   └─► Nginx :443 (UDP - HTTP/3 / QUIC)
         │
         │ HTTP/1.1
         ▼
   127.0.0.1:3053
         │
         ▼
   Unified DNS Resolver
```

Configure:

```text
DOH_NO_TLS=1
DOH_PORT=3053
```

Example Nginx configuration:

```nginx
upstream doh_backend {
    server 127.0.0.1:3053;
    keepalive 64;
}

server {
    # HTTP/2 and HTTP/1.1 over TLS
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # HTTP/3 over QUIC
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;

    server_name dns.example.com;

    ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Advertise HTTP/3 support to connecting clients
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    client_max_body_size 10k;

    location = /dns-query {
        proxy_pass http://doh_backend/dns-query;

        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;

        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_buffering off;
        proxy_request_buffering off;
    }

    location = /health {
        proxy_pass http://doh_backend/health;
        proxy_set_header Host $host;
    }

    # Metrics: restrict access. Do not expose to the public internet
    # without an allowlist.
    location = /metrics {
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;

        proxy_pass http://doh_backend/metrics;
        proxy_set_header Host $host;
    }
}
```

The resolver's proxy-header protection ensures forwarded client identity is only trusted when the immediate connection is from a trusted local proxy.

---

# Verification

## Plain DNS

```bash
dig @127.0.0.1 -p 53 example.com A +dnssec
```

TCP:

```bash
dig +tcp @127.0.0.1 -p 53 example.com A +dnssec
```

## DNS-over-TLS (DoT)

```bash
kdig -d @dns.example.com:853 +tls example.com A
```

## DNS-over-QUIC (DoQ)

```bash
kdig -d @dns.example.com:853 +quic example.com A
```

## DNS-over-HTTPS (DoH)

### POST

```bash
echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  | base64 -d \
  | curl -s -X POST \
      --data-binary @- \
      -H "Content-Type: application/dns-message" \
      -H "Accept: application/dns-message" \
      https://dns.example.com/dns-query \
  | hexdump -C
```

### GET

```bash
curl -s \
  -H "Accept: application/dns-message" \
  "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  | hexdump -C
```

## DNS-over-HTTP/3 (DoH3)

### GET (HTTP/3 over QUIC)

```bash
curl --http3 -s \
  -H "Accept: application/dns-message" \
  "https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  | hexdump -C
```

### POST (HTTP/3 over QUIC)

```bash
echo -n "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  | base64 -d \
  | curl --http3 -s -X POST \
      --data-binary @- \
      -H "Content-Type: application/dns-message" \
      -H "Accept: application/dns-message" \
      https://dns.example.com/dns-query \
  | hexdump -C
```

## Metrics

```bash
curl -sk https://dns.example.com/metrics | python3 -m json.tool
```

## GSLB Steering

```bash
# Verify the delegation resolves and returns a single A record
dig dns.example.com A +trace

# Verify that the resolver returns different regional IPs for different clients
# (from clients in different regions, or via public resolvers)
dig dns.example.com A @1.1.1.1 +short
dig dns.example.com A @8.8.8.8 +short
```

## DNSSEC Failure Test

```bash
dig @127.0.0.1 -p 53 dnssec-failed.org A
```

Expected result:

```text
SERVFAIL
```

## Valid DNSSEC Test

```bash
dig @127.0.0.1 -p 53 cloudflare.com A +dnssec
```

Expected result:

```text
NOERROR
flags: ... ad ...
```

---

# Security Model

| Threat                               | Mitigation                                                                                      |
| ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Broken root trust chain              | Strict DNSSEC validation and fail-closed enforcement                                            |
| DS stripping / downgrade             | Authenticated DS nonexistence proofs required                                                   |
| Parent DS rollover desynchronization | Child DNSKEY trust lifetime bounded by parent DS TTL                                            |
| DNSSEC signature expiration          | Effective cache TTL bounded by required RRSIG validity                                          |
| Forged negative responses            | Cryptographically validated NSEC/NSEC3 proofs                                                   |
| NSEC3 Opt-Out abuse                  | Opt-Out accepted only for appropriate insecure delegations                                      |
| DNS cache poisoning                  | Transaction ID validation, response matching, bailiwick controls, randomized upstream selection |
| Forged/out-of-bailiwick glue         | Bailiwick validation and independent resolution                                                 |
| Recursive SSRF                       | Special-use/private/link-local/metadata address filtering                                       |
| Broken EDNS servers                  | EDNS fallback to plain DNS                                                                      |
| Slow authoritative servers           | Whole-transaction TCP timeouts and bounded recursion                                            |
| CNAME/DNAME loops                    | Hop limits and cycle detection                                                                  |
| DNAME name overflow                  | RFC 6672 name-length validation                                                                 |
| DNSSEC algorithmic DoS               | Per-validation signature budget                                                                 |
| DNS amplification                    | ANY handling, response-size enforcement, UDP duplicate-domain RRL                               |
| Volumetric flooding                  | Subnet token-bucket rate limiting                                                               |
| UDP duplicate flooding               | Atomic per-domain RRL                                                                           |
| Stale DNSSEC authentication          | Stale responses always clear `AD`                                                               |
| Zombie cache entries                 | Hard expiration after stale window                                                              |
| Legacy cache downgrade               | Entries without explicit DNSSEC state are discarded                                             |
| Proxy identity spoofing              | Forwarded headers trusted only from loopback                                                    |
| UDP application truncation           | 65,535-byte receive buffer                                                                      |
| QUIC / HTTP/3 HoL blocking           | Multiplexed, independent byte streams per DNS query via QUIC                                    |
| Post-quantum response truncation     | Automatic TCP retry after `TC=1`                                                                |
| Cache memory exhaustion              | Bounded W-TinyLFU admission with configurable capacity                                          |
| Thundering herd on cache miss        | Per-key single-flight coalescing                                                                |
| Root zone tampering                  | Downloaded over TLS; parse validation; atomic swap; previous known-good retained on failure      |
| Stale root zone data                 | Explicit staleness states; fallback to live root servers when too old                            |
| GSLB cache poisoning                 | GSLB decisions run before the shared cache and are never cached                                  |
| GSLB node address injection          | Node addresses accepted only from `NODE<N>_IPV4` / `NODE<N>_IPV6` env vars                       |
| GSLB health check SSRF               | Only configured node addresses are probed; query data is never used as a target                  |
| ECS spoofing                         | ECS is used only for GeoIP lookup, not for routing decisions in isolation; source IP is preferred when ECS is absent |

---

# Design Principles

The resolver is built around several core principles:

### 1. Resolve, don't forward

The server performs iterative resolution itself instead of outsourcing recursion to a public resolver.

### 2. Validate before trusting

Delegations, glue, DNSSEC signatures, negative proofs, and cached security state are independently validated before being trusted.

### 3. Keep canonical state separate from presentation

The cache represents resolver state, not one particular client's DNS request.

### 4. Never manufacture security state

Legacy or incomplete cache entries are discarded rather than assigned an assumed DNSSEC status.

### 5. Expiration is security-sensitive

DNSSEC signature validity constrains cache lifetime. Expired authenticated data cannot remain `Fresh`.

### 6. Stale data is explicitly unauthenticated

RFC 8767 stale responses are served with `AD=0`, regardless of their previous DNSSEC state.

### 7. Bound every expensive operation

Recursive depth, resolution steps, redirections, concurrent connections, rate limits, cache capacity, and cryptographic verification are all explicitly bounded.

### 8. Treat network-provided addresses as untrusted input

Delegation glue and resolved nameserver addresses are filtered before they can become outbound connection targets.

### 9. Separate lifecycles for separate concerns

The answer cache, delegation cache, DNSSEC key caches, root zone, and GSLB health state each have their own expiration and refresh behavior. No single mechanism governs all of them, and no single event invalidates all of them.

### 10. Coalesce, don't multiply

Concurrent identical requests share a single upstream resolution. Concurrent unrelated requests proceed in parallel.

### 11. Authoritative answers never pollute the recursive cache

When the resolver acts as an authoritative GSLB, the per-client steering decision is computed on the request path and never stored in the shared recursive cache. Two clients with different geographic origins can receive different answers for the same name without either affecting the other.

---

# License

This project is licensed under the **MIT License**.


