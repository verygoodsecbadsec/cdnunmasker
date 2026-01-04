# CDN-Unmasker — Usage Examples

Practical walkthroughs for the most common scenarios you will encounter during an engagement.

---

## Table of Contents

- [Quick start](#quick-start)
- [Scenario 1 — Basic recon on a single target](#scenario-1--basic-recon-on-a-single-target)
- [Scenario 2 — Full engagement scan with report](#scenario-2--full-engagement-scan-with-report)
- [Scenario 3 — Immediate service fingerprinting](#scenario-3--immediate-service-fingerprinting)
- [Scenario 4 — Custom wordlist and tool paths](#scenario-4--custom-wordlist-and-tool-paths)
- [Scenario 5 — SecurityTrails historical DNS](#scenario-5--securitytrails-historical-dns)
- [Scenario 6 — Interpreting the scored output](#scenario-6--interpreting-the-scored-output)
- [Scenario 7 — Acting on the results](#scenario-7--acting-on-the-results)
- [Cheat sheet](#cheat-sheet)

---

## Quick Start

```bash
./cdn_unmasker.sh example.com
```

That's the minimum. The script runs all nine stages, prints scored candidates to stdout, and saves everything under `recon_example.com_YYYYMMDD_HHMMSS/`.

---

## Scenario 1 — Basic Recon on a Single Target

**Situation:** You are in the recon phase of a web application pentest. The target resolves to a Cloudflare IP. You want to find the origin before you start scanning.

```bash
./cdn_unmasker.sh targetsite.com
```

**What happens:**

1. Passive subdomains are collected from subfinder, assetfinder, and crt.sh in parallel.
2. ffuf brute-forces 110,000 DNS names against the target.
3. gobuster brute-forces virtual hosts on the base domain.
4. Whois, DNS records, and SSL certs are pulled for every discovered host.
5. HackerTarget is queried for historical A records.
6. All IPs are filtered against live CDN ranges (Cloudflare, Akamai, Fastly, CloudFront, Azure).
7. Remaining IPs are scored by how many independent signals point to them.

**Expected stdout:**

```
[*] CDN Unmasking v3.4 for targetsite.com
[*] Output: recon_targetsite.com_20240812_091532
[+] CDN ranges saved (312 entries).
[*] 1) Passive subdomain enumeration...
[+] 634 unique subdomains from passive sources.
[+] 41 live passive subdomains.
[*] 2) DNS brute-force (ffuf)...
[+] 17 subdomains from DNS brute-force.
[*] 3) Vhost brute-force (gobuster)...
[+] 2 vhosts discovered.
[*] 4) Whois lookups...
[+] Whois data saved.
[*] 5) DNS resolution...
[*] 6) Historical DNS...
[+] Historical IPs: 185.220.101.47 37.48.89.12
[*] 7) SSL certificates...
[*] 8) CloudRip...
[*] 9) Scoring origin IPs...
[+] Candidate origin IPs (weighted):
185.220.101.47   7   historical_dns,ssl_san,spf,asn_mismatch
37.48.89.12      3   historical_dns,asn_mismatch
203.0.113.42     2   ssl_san
[+] All data in recon_targetsite.com_20240812_091532

[=== Stage Summary ===]
  passive_enum     : OK
  dns_bruteforce   : OK
  vhost_bruteforce : OK
  whois            : OK
  dns_resolution   : OK
  historical_dns   : OK
  ssl_certs        : OK
  cloudrip         : OK
```

**Key file to open next:**

```bash
cat recon_targetsite.com_20240812_091532/possible_origin_ips_scored.txt
```

---

## Scenario 2 — Full Engagement Scan with Report

**Situation:** You need to document findings for a client report. You want a clean Markdown summary alongside all raw data.

```bash
./cdn_unmasker.sh targetsite.com --report
```

This adds a `REPORT.md` to the output directory after all stages complete.

**REPORT.md structure:**

```markdown
# CDN Unmasking Report for targetsite.com
Generated: Mon Aug 12 09:15:32 UTC 2024

## Stage Status
- **passive_enum**: ✅ SUCCESS
- **dns_bruteforce**: ✅ SUCCESS
- **vhost_bruteforce**: ✅ SUCCESS
- **historical_dns**: ✅ SUCCESS
- **ssl_certs**: ✅ SUCCESS
- **cloudrip**: ✅ SUCCESS

## Candidate Origin IPs (Weighted)
| IP Address     | Score | Sources                                    |
|----------------|-------|--------------------------------------------|
| 185.220.101.47 | 7     | historical_dns,ssl_san,spf,asn_mismatch    |
| 37.48.89.12    | 3     | historical_dns,asn_mismatch                |
| 203.0.113.42   | 2     | ssl_san                                    |

## Subdomains Collected
- Passive: 634 hosts
- Brute-force: 17 hosts
- Vhosts: 2 hosts

## Live Hosts
- HTTP/HTTPS: 41
```

You can paste the candidates table directly into a pentest report or share the file with a client.

---

## Scenario 3 — Immediate Service Fingerprinting

**Situation:** You want to jump straight from origin discovery to service detection without running nmap separately.

```bash
./cdn_unmasker.sh targetsite.com --nmap
```

After scoring, the top 5 candidates are passed to:

```bash
nmap -sV -T4 -p 80,443,8080,8443 <ip>
```

Results are saved to `nmap_scan.txt` in the output directory.

**Full pipeline in one command:**

```bash
./cdn_unmasker.sh targetsite.com --report --nmap
```

This runs everything — recon, scoring, nmap on top 5, and a final Markdown report.

**nmap_scan.txt example output:**

```
Nmap scan report for 185.220.101.47
Host is up (0.031s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     nginx 1.18.0 (Ubuntu)
443/tcp  open  ssl/http nginx 1.18.0 (Ubuntu)
8080/tcp open  http     Apache httpd 2.4.41
8443/tcp closed https

Nmap scan report for 37.48.89.12
Host is up (0.045s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.41 ((Debian))
443/tcp open  ssl/http Apache httpd 2.4.41 ((Debian))
```

Two different web servers on two different IPs is a strong indicator that `185.220.101.47` is the primary origin (nginx matching the target's known stack) and `37.48.89.12` may be a staging server or old deployment.

---

## Scenario 4 — Custom Wordlist and Tool Paths

**Situation:** You are running the script in a non-standard environment where tools are not in `$PATH`, or you want to use a larger wordlist.

```bash
WORDLIST=/opt/seclists/Discovery/DNS/subdomains-top1million-5000000.txt \
CLOUDRIP_SCRIPT=/opt/tools/cloudrip.py \
./cdn_unmasker.sh targetsite.com
```

Both variables are read at startup before `check_tools` runs, so any path issues are caught immediately with a clear error message rather than failing mid-scan.

**Validating paths before a long run:**

```bash
# Quick sanity check
ls -la $WORDLIST $CLOUDRIP_SCRIPT
wc -l $WORDLIST
```

**Typical wordlist choices by engagement type:**

| Wordlist | Lines | Use case |
|----------|-------|----------|
| `subdomains-top1million-110000.txt` | 110,000 | Standard web app pentest |
| `subdomains-top1million-5000000.txt` | 5,000,000 | Deep recon, longer runtime |
| `bitquark-subdomains-top100000.txt` | 100,000 | Alternative ordering |
| Custom client-specific list | Varies | When you have internal naming conventions |

---

## Scenario 5 — SecurityTrails Historical DNS

**Situation:** HackerTarget's free tier (50 queries/day) is exhausted, or you need deeper historical coverage that goes back several years.

Set your SecurityTrails API key before running:

```bash
export ST_API_KEY="your_securitytrails_api_key_here"
./cdn_unmasker.sh targetsite.com
```

With `ST_API_KEY` set, stage 6 queries the SecurityTrails v1 API for historical A records in addition to HackerTarget. SecurityTrails typically returns a richer history, especially for targets that have changed hosting providers multiple times.

**Getting a SecurityTrails key:**

Free tier available at [securitytrails.com](https://securitytrails.com) — 50 API queries/month on the free plan, sufficient for most individual engagements.

---

## Scenario 6 — Interpreting the Scored Output

**Situation:** The scan has finished. You have a scored list and need to decide which IPs to act on.

```bash
cat recon_targetsite.com_20240812_091532/possible_origin_ips_scored.txt
```

```
185.220.101.47|7|historical_dns,ssl_san,spf,asn_mismatch
37.48.89.12|3|historical_dns,asn_mismatch
203.0.113.42|2|ssl_san
198.51.100.8|1|asn_mismatch
```

**Reading the scores:**

| Score | Confidence | Recommended action |
|-------|------------|--------------------|
| 5 or higher | High — multiple independent signals agree | Treat as confirmed origin candidate. Scan directly. |
| 3–4 | Medium — at least two signals | Verify with a direct HTTP request (`curl -H "Host: targetsite.com" http://<ip>`) before scanning. |
| 1–2 | Low — single weak signal | Manual investigation only. ASN mismatch alone is unreliable. |

**Quick verification for a candidate IP:**

```bash
# Does the server respond to the target domain when addressed directly?
curl -sk -H "Host: targetsite.com" https://185.220.101.47 | head -50

# Compare the response to the CDN-fronted version
curl -sk https://targetsite.com | head -50
```

If both responses contain the same page content, you have confirmed the origin IP. If the direct request returns a default page or 404 with no CDN headers, it is likely a false positive.

**Checking for CDN headers on the candidate:**

```bash
curl -sk -I -H "Host: targetsite.com" https://185.220.101.47 | grep -iE 'server|x-powered|cf-ray|x-cache|via'
```

A response without `CF-Ray`, `X-Cache`, or `Via` headers is consistent with a direct origin connection.

---

## Scenario 7 — Acting on the Results

Once you have a confirmed origin IP, you can scan it directly without CDN interference.

**Direct nmap scan bypassing the CDN:**

```bash
nmap -sV -sC -T4 -p- 185.220.101.47 -oA direct_scan
```

**Web application scan directly against origin:**

```bash
# nikto
nikto -h https://185.220.101.47 -vhost targetsite.com

# nuclei
nuclei -u https://185.220.101.47 -H "Host: targetsite.com" -t cves/

# ffuf directory brute-force against origin
ffuf -u https://185.220.101.47/FUZZ -H "Host: targetsite.com" -w /opt/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**Why this matters:** Cloudflare and similar CDNs block many scanner signatures and rate-limit requests. Scanning the origin directly bypasses WAF rules, exposes the real server headers, and gives accurate port and service information.

---

## Cheat Sheet

```bash
# Minimal scan
./cdn_unmasker.sh example.com

# Full scan with report
./cdn_unmasker.sh example.com --report

# Full scan with report and nmap
./cdn_unmasker.sh example.com --report --nmap

# Custom paths
WORDLIST=/path/to/list.txt CLOUDRIP_SCRIPT=/path/to/cloudrip.py \
    ./cdn_unmasker.sh example.com

# With SecurityTrails
ST_API_KEY=your_key ./cdn_unmasker.sh example.com --report

# Check scored results
cat recon_*/possible_origin_ips_scored.txt

# Verify a candidate IP manually
curl -sk -H "Host: example.com" https://<candidate_ip> | head -50

# Check response headers on candidate
curl -sk -I -H "Host: example.com" https://<candidate_ip>

# Scan confirmed origin directly
nmap -sV -sC -T4 -p- <confirmed_origin_ip>
```

---

> **Legal reminder:** Only run this tool against targets you have explicit written authorization to test. Unauthorized use is illegal.
