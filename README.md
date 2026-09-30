# CDN-Unmasker

> **Uncover the real IP of any web server hiding behind a CDN.**

Most modern targets sit behind Cloudflare, Akamai, Fastly, or AWS CloudFront. When you scan them, you're scanning CDN edge nodes — not the actual server. CDN-Unmasker chains nine recon techniques, filters out CDN address space, and scores every candidate origin IP by how many independent signals point to it.

```
$ ./cdn_unmasker.sh example.com --report --nmap

[*] CDN Unmasking v3.4 for example.com
[*] Output: recon_example.com_20240812_143022
[+] CDN ranges saved (312 entries).
[+] 847 passive subdomains collected.
[+] 23 subdomains from DNS brute-force.
[+] 4 vhosts discovered.
[+] Historical IPs: 203.0.113.47 198.51.101.13
[+] Candidate origin IPs (weighted):
185.220.101.47   7   historical_dns,ssl_san,spf,asn_mismatch
37.48.89.12      3   historical_dns,asn_mismatch
[+] All data in recon_example.com_20240812_143022
```

---

## How It Works

CDN-Unmasker runs nine stages in sequence, each feeding into the final scoring pass.

| Stage | Technique | Tools |
|-------|-----------|-------|
| 1 | Passive subdomain enumeration | `subfinder`, `assetfinder`, `crt.sh` |
| 2 | Active DNS brute-force | `ffuf` + SecLists 110k wordlist |
| 3 | Virtual host brute-force | `gobuster` vhost mode |
| 4 | Whois lookups | `whois` (parallel, rate-limited) |
| 5 | DNS resolution (A/AAAA/CNAME) | `dig` (parallel) |
| 6 | Historical DNS records | HackerTarget API + crt.sh timeline |
| 7 | SSL certificate inspection | `openssl` — SAN IP extraction |
| 8 | CDN-bypass automated check | `cloudrip.py` |
| 9 | Evidence aggregation & scoring | `grepcidr` + weighted scoring |

All resolved IPs are filtered against a live-aggregated list of CDN ranges (Cloudflare, Akamai, Fastly, AWS CloudFront, Azure). What remains is scored by how many independent evidence sources point to it.

---

## Scoring System

Every candidate IP receives a weighted score based on which signals identified it. Higher score = higher confidence it is the real origin.

| Source | Weight | Rationale |
|--------|--------|-----------|
| `historical_dns` | **3** | The strongest signal. Historical A records reflect where the server lived *before* CDN adoption — the IP most likely hasn't changed. |
| `ssl_san` | **2** | SSL Subject Alternative Names are infrastructure records. Developers often forget to update them when moving behind a CDN, leaking the real IP. |
| `spf` | **2** | SPF records frequently expose mail server IPs on the same infrastructure. Mail is rarely routed through the CDN. |
| `asn_mismatch` | **1** | Weak signal. An IP resolving to a non-CDN ASN is suspicious, but small hosters can produce false positives here. |
| `passive_subdomain` | **1** | A subdomain that resolves directly, bypassing the CDN. Common on staging environments and internal services. |

Example output:

```
IP               Score  Sources
185.220.101.47   7      historical_dns,ssl_san,spf,asn_mismatch
37.48.89.12      3      historical_dns,asn_mismatch
203.0.113.42     2      ssl_san
```

An IP scoring 5+ across multiple independent sources is a high-confidence origin candidate. An IP scoring 1 from ASN mismatch alone warrants further verification before acting on it.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/verygoodsecbadsec/cdnunmasker.git
cd cdnunmasker
```

### 2. Install dependencies

**Go tools:**
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
```

**System tools:**
```bash
# Debian / Ubuntu
sudo apt install jq whois dnsutils openssl grepcidr nmap curl python3


**CloudRip:**
```bash
git clone https://github.com/staxsum/CloudRip.git
cp CloudRip/cloudrip.py .
```

### 3. Download the wordlist

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt
```

### 4. Verify setup

```bash
chmod +x cdn_unmasker.sh
./cdn_unmasker.sh --help
```

---

## Usage

```
./cdn_unmasker.sh <domain> [--report] [--nmap]
```

| Flag | Description |
|------|-------------|
| `--report` | Generate a `REPORT.md` in the output directory with a full findings table |
| `--nmap` | Run `nmap -sV` against the top 5 scoring candidates after analysis |

**Basic scan:**
```bash
./cdn_unmasker.sh example.com
```

**Full scan with report and service detection:**
```bash
./cdn_unmasker.sh example.com --report --nmap
```

**Custom wordlist or cloudrip path:**
```bash
WORDLIST=/path/to/wordlist.txt CLOUDRIP_SCRIPT=/opt/cloudrip.py ./cdn_unmasker.sh example.com
```

---

## Output Structure

Every run creates a timestamped directory:

```
recon_example.com_YYYYMMDD_HHMMSS/
├── cdn_ranges.txt                   # Aggregated CDN CIDR ranges used for filtering
├── passive_subs.txt                 # Subdomains from subfinder + assetfinder + crt.sh
├── bruteforce_subs.txt              # Subdomains from ffuf DNS brute-force
├── vhosts.txt                       # Virtual hosts from gobuster
├── all_discovered.txt               # Deduplicated union of all above
├── current_ips.txt                  # All IPs resolved from DNS records
├── possible_origin_ips_raw.txt      # Non-CDN IPs (post grepcidr filter)
├── possible_origin_ips_scored.txt   # Final candidates with weighted scores  ← key file
├── all_candidates.txt               # All IPs fed into ASN analysis
├── spf_cidrs.txt                    # SPF CIDRs extracted from DNS TXT records
├── asn_work.txt                     # Raw ASN lookup results
├── whois/                           # Per-host whois output
├── dns/                             # Per-host A, AAAA, CNAME records
├── ssl/                             # Per-host SSL certificate text dumps
├── historical/
│   ├── historical_example.com_ips.txt   # Historical IPs from HackerTarget
│   └── crtsh_timeline.txt               # Certificate issuance timeline
├── cloudrip_results.txt             # CloudRip findings
└── REPORT.md                        # Markdown report (if --report was used)
```

---

## API Limits & External Services

| Service | Limit | Notes |
|---------|-------|-------|
| HackerTarget | 50 queries/day (free) | Used for historical DNS. Set `ST_API_KEY` for SecurityTrails as an alternative. |
| crt.sh | No hard limit | May be slow under load. Results cached in `crtsh.txt`. |
| Team Cymru whois | Rate-limited | Script uses `-P 3` with 0.5s delay between queries to stay within acceptable use. |
| Cloudflare / Fastly / AWS | No limit | IP range files fetched fresh on each run. |

**Azure CDN ranges** are included as a static list. Microsoft publishes updated ranges weekly at `aka.ms/azureipranges` — update the heredoc in `aggregate_cdn_ranges()` periodically for accuracy.

---

## Known Limitations

- **Mutual TLS and certificate pinning** will prevent SSL SAN extraction on some targets.
- **SPF expansion** covers one level of `include:` directives. Deeply nested SPF chains (e.g. `include: → include: → ip4:`) will not be fully resolved.
- **ASN mismatch** produces false positives for targets hosted on small or regional providers whose ASN is not in `KNOWN_CDN_ASNS`. Treat score-1 candidates as leads, not findings.
- **CloudRip** depends on an externally maintained tool. If its flag interface changes, stage 8 may fail silently (caught by stage tracking).
- The script is designed for **authorized penetration testing only**. Running it against targets you do not have permission to test is illegal.

---

## Legal Notice

This tool is intended for authorized use in CTF competitions, security research, and controlled test environments only. Capturing traffic on networks you do not own or have explicit permission to monitor is illegal in most jurisdictions. The author accepts no liability for unauthorized use.

---

## License
 - This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
