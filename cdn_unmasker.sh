#!/usr/bin/env bash
#==================================================================
#
# This script tries to find the real IP address of a website that
# is hidden behind a CDN (Cloudflare, Akamai, Fastly, etc.).
#
# Usage:
#   ./cdn_unmasker.sh example.com
#   ./cdn_unmasker.sh example.com --report   (creates a summary)
#   ./cdn_unmasker.sh example.com --nmap     (runs an nmap scan)
#==================================================================

# If any command fails, stop the whole script immediately
set -euo pipefail

# ---------- settings you can override ----------
WORDLIST="${WORDLIST:-subdomains-top1million-110000.txt}"   # subdomain wordlist
CLOUDRIP_SCRIPT="${CLOUDRIP_SCRIPT:-./cloudrip.py}"         # CloudRip helper

# flags turned on by the user
REPORT_MODE=false
NMAP_MODE=false

# ---------- read command line arguments ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --report) REPORT_MODE=true ;;
        --nmap)   NMAP_MODE=true ;;
        *)        TARGET="$1" ;;               # the domain to investigate
    esac
    shift
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain> [--report] [--nmap]"
    exit 1
fi

# ---------- helper functions (coloured output) ----------
info()  { echo -e "\033[1;34m[*]\033[0m $*"; }       # blue star
ok()    { echo -e "\033[1;32m[+]\033[0m $*"; }       # green plus
warn()  { echo -e "\033[1;33m[!]\033[0m $*"; }       # yellow exclamation
fail()  { echo -e "\033[1;31m[-]\033[0m $*"; exit 1; }  # red minus + exit

# Keep track of which parts worked and which didn't
declare -A STAGE_STATUS
stage_success() { STAGE_STATUS["$1"]="SUCCESS"; }
stage_failure() { STAGE_STATUS["$1"]="FAILED"; }

# Show a summary of all stages at the end
print_stage_summary() {
    echo -e "\n\033[1;36m[=== Stage Summary ===]\033[0m"
    for stage in "${!STAGE_STATUS[@]}"; do
        if [ "${STAGE_STATUS[$stage]}" = "SUCCESS" ]; then
            echo -e "  $stage : \033[1;32mOK\033[0m"
        else
            echo -e "  $stage : \033[1;31m${STAGE_STATUS[$stage]}\033[0m"
        fi
    done
}

# ---------- download all CDN IP ranges ----------
# We need to know which IPs belong to the big CDNs so we can
# filter them out later. Only non‑CDN IPs are interesting.
aggregate_cdn_ranges() {
    local cdnfile="$1"
    info "Collecting CDN IP ranges..."

    # Cloudflare (always up‑to‑date)
    curl -s https://www.cloudflare.com/ips-v4 >> "$cdnfile"
    curl -s https://www.cloudflare.com/ips-v6 >> "$cdnfile"

    # Akamai
    curl -s https://www.akamai.com/us/en/multimedia/documents/technical-publication/akamai-ipv4-ranges.txt >> "$cdnfile" || true
    curl -s https://www.akamai.com/us/en/multimedia/documents/technical-publication/akamai-ipv6-ranges.txt >> "$cdnfile" || true

    # Fastly
    curl -s https://api.fastly.com/public-ip-list | jq -r '.addresses[]' 2>/dev/null >> "$cdnfile" || true

    # Amazon CloudFront
    curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
        jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' 2>/dev/null >> "$cdnfile" || true

    # Azure CDN (a static list – update it from Microsoft docs once in a while)
    cat <<-'EOF' >> "$cdnfile"
13.82.0.0/16
13.89.0.0/16
20.36.0.0/16
40.77.0.0/16
51.11.0.0/16
191.233.0.0/16
52.228.0.0/16
EOF

    # Remove duplicate ranges
    sort -u -o "$cdnfile" "$cdnfile"

    if [ -s "$cdnfile" ]; then
        ok "CDN ranges saved ($(wc -l < "$cdnfile") lines)"
        stage_success "cdn_ranges"
    else
        fail "Could not download any CDN ranges!"
    fi
}

# ---------- get old IP addresses from HackerTarget ----------
# If a domain used to point directly to a server before they
# added the CDN, we can often find that old IP here.
fetch_historical_dns() {
    local domain="$1" outfile="$2"
    info "Checking historical DNS for $domain..."

    local response
    response=$(curl -s --max-time 10 "https://api.hackertarget.com/iphistory/?q=${domain}")

    # The API returns plain text – either a list of IPs or "No records found."
    if [[ -z "$response" || "$response" == *"No records"* ]]; then
        warn "No historical IPs for $domain"
        return 1
    fi

    # Extract just the IPv4 addresses
    echo "$response" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "$outfile"
    [ -s "$outfile" ] && ok "Historical IPs: $(cat "$outfile")"
}

# ---------- a few helpers for the final scoring ----------
# These known AS numbers belong to CDNs.
KNOWN_CDN_ASNS="13335 16625 54113 16509 20940 15169 36351 3356 7922"

# We assign a weight (importance) to each piece of evidence.
declare -A SOURCE_WEIGHTS=(
    ["historical_dns"]=3        # very strong – it shows the IP before CDN was used
    ["ssl_san"]=2               # strong – certificates often leak the real IP
    ["spf"]=2                   # strong – mail servers frequently sit on the same network
    ["asn_mismatch"]=1          # weak – many hosting providers look “non‑CDN”
    ["passive_subdomain"]=1     # weak – just appearing in passive lists is not enough
)

# This map remembers which evidence we have for each IP.
declare -A IP_EVIDENCE

record_evidence() {
    local ip="$1" source="$2"
    if [[ -n "${IP_EVIDENCE[$ip]:-}" ]]; then
        # Already has some evidence – append this new source
        IP_EVIDENCE[$ip]="${IP_EVIDENCE[$ip]},$source"
    else
        IP_EVIDENCE[$ip]="$source"
    fi
}

# Calculate the final score for a candidate IP.
weighted_score() {
    local sources="$1" total=0
    # split the comma‑separated list of evidence sources
    IFS=',' read -ra SRC <<< "$sources"
    for s in "${SRC[@]}"; do
        total=$(( total + ${SOURCE_WEIGHTS[$s]:-0} ))
    done
    echo "$total"
}

# ---------- optional: create a Markdown report ----------
generate_report() {
    local outdir="$1" target="$2"
    local report="${outdir}/REPORT.md"
    info "Writing report → $report"

    {
        echo "# CDN Unmasking Report for **$target**"
        echo "Generated: $(date)"
        echo ""
        echo "## Stage Status"
        for stage in "${!STAGE_STATUS[@]}"; do
            local status="${STAGE_STATUS[$stage]}"
            if [ "$status" = "SUCCESS" ]; then
                echo "- **$stage**: ✅ $status"
            else
                echo "- **$stage**: ❌ $status"
            fi
        done
        echo ""
        echo "## Candidate Origin IPs (Weighted)"
        echo "| IP Address | Score | Sources |"
        echo "|------------|-------|---------|"
        local scored="${outdir}/possible_origin_ips_scored.txt"
        if [ -f "$scored" ]; then
            while IFS='|' read -r ip score srcs; do
                echo "| $ip | $score | $srcs |"
            done < "$scored"
        fi
        echo ""
    } > "$report"
    ok "Report written."
}

# =====================================================================
#                         MAIN WORKFLOW
# =====================================================================
main() {
    # Create a timestamped folder to store everything
    local OUTDIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTDIR"
    info "Starting CDN Unmasking for: $TARGET"
    info "All results will be saved in: $OUTDIR"

    # ---- Step 0: gather all CDN IP ranges ----
    aggregate_cdn_ranges "$OUTDIR/cdn_ranges.txt"

    # ============================================
    # 1) PASSIVE SUBDOMAIN DISCOVERY
    #    We ask free online databases for subdomains
    #    without actively sending packets to the target.
    # ============================================
    info "1) Passive subdomain discovery..."
    subfinder -d "$TARGET" -silent -o "$OUTDIR/subfinder.txt" &
    assetfinder --subs-only "$TARGET" > "$OUTDIR/assetfinder.txt" &
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\*\.//g' | sort -u > "$OUTDIR/crtsh.txt" &
    wait   # wait for all three to finish

    # Merge all passive results into one list
    cat "$OUTDIR/subfinder.txt" "$OUTDIR/assetfinder.txt" "$OUTDIR/crtsh.txt" | \
        sort -u > "$OUTDIR/passive_subs.txt"

    # Check which of those subdomains are actually alive (return a web page)
    httpx -l "$OUTDIR/passive_subs.txt" -silent -o "$OUTDIR/live_passive.txt"
    stage_success "passive_enum"

    # ============================================
    # 2) ACTIVE DNS BRUTE‑FORCE
    #    Try thousands of common subdomain names
    #    by making DNS requests.
    # ============================================
    info "2) DNS brute‑force (ffuf)..."
    ffuf -w "$WORDLIST" \
         -u "https://FUZZ.${TARGET}" \
         -H "User-Agent: Mozilla/5.0" \
         -t 50 \
         -fc 404 \
         -o "$OUTDIR/ffuf_dns.json" -of json > /dev/null 2>&1 || true

    # Extract the subdomain names from ffuf's JSON output
    jq -r '.results[]?.url' "$OUTDIR/ffuf_dns.json" 2>/dev/null | \
        sed 's|https://||;s|http://||' | cut -d/ -f1 | sort -u > "$OUTDIR/bruteforce_subs.txt"
    stage_success "dns_bruteforce"

    # ============================================
    # 3) VIRTUAL HOST BRUTE‑FORCE
    #    Some servers host several websites on the
    #    same IP, differentiated by the Host header.
    # ============================================
    info "3) Virtual host brute‑force (gobuster)..."
    gobuster vhost -u "https://${TARGET}" \
        -w "$WORDLIST" \
        -t 50 \
        --timeout 10s \
        -o "$OUTDIR/gobuster_vhosts_raw.txt" > /dev/null 2>&1 || true

    # Extract the discovered virtual host names
    grep -oP 'Found:\s+\K\S+' "$OUTDIR/gobuster_vhosts_raw.txt" 2>/dev/null | \
        sort -u > "$OUTDIR/vhosts.txt"
    stage_success "vhost_bruteforce"

    # ---- Combine everything into one big master list ----
    {
        cat "$OUTDIR/passive_subs.txt"
        cat "$OUTDIR/bruteforce_subs.txt"
        cat "$OUTDIR/vhosts.txt"
    } | sort -u > "$OUTDIR/all_discovered.txt"
    ok "$(wc -l < "$OUTDIR/all_discovered.txt") unique hosts to investigate."

    # ============================================
    # 4) WHOIS LOOKUPS
    #    Whois records sometimes contain the real
    #    organisation’s IP ranges.
    # ============================================
    info "4) Whois lookups (this may take a few minutes)..."
    mkdir -p "$OUTDIR/whois"
    # Use xargs to run several whois queries in parallel (but gently)
    cat "$OUTDIR/all_discovered.txt" | \
        xargs -P 5 -I {} sh -c '
            # Replace characters that are unsafe for file names
            safe=$(echo "{}" | tr "/\\:" "_")
            sleep 0.2
            whois "{}" > "'$OUTDIR'/whois/${safe}.txt" 2>/dev/null
        ' || true
    stage_success "whois"

    # ============================================
    # 5) DNS RESOLUTION
    #    Find the actual IP addresses behind each
    #    discovered hostname.
    # ============================================
    info "5) DNS queries (parallel)..."
    mkdir -p "$OUTDIR/dns"
    cat "$OUTDIR/all_discovered.txt" | \
        xargs -P 20 -I {} sh -c '
            safe=$(echo "{}" | tr "/\\:" "_")
            dig +short A    "{}" > "'$OUTDIR'/dns/${safe}_A.txt"    2>/dev/null
            dig +short AAAA "{}" > "'$OUTDIR'/dns/${safe}_AAAA.txt" 2>/dev/null
            dig +short CNAME "{}" > "'$OUTDIR'/dns/${safe}_CNAME.txt" 2>/dev/null
        '
    stage_success "dns_resolution"

    # ============================================
    # 6) HISTORICAL DNS RECORDS
    #    Look for IP addresses the domain used in
    #    the past, before they added the CDN.
    # ============================================
    info "6) Historical DNS..."
    mkdir -p "$OUTDIR/historical"
    fetch_historical_dns "$TARGET" "$OUTDIR/historical/historical_${TARGET}_ips.txt"
    # Also save certificate transparency log timestamps as a reference
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
        jq -r '.[] | "\(.name_value) \(.entry_timestamp)"' 2>/dev/null \
        > "$OUTDIR/historical/crtsh_timeline.txt"
    stage_success "historical_dns"

    # ============================================
    # 7) SSL CERTIFICATE COLLECTION
    #    Certificates often list extra domain names
    #    and sometimes even plain IP addresses.
    # ============================================
    info "7) SSL certificate inspection..."
    mkdir -p "$OUTDIR/ssl"
    cat "$OUTDIR/all_discovered.txt" | \
        xargs -P 15 -I {} sh -c '
            safe=$(echo "{}" | tr "/\\:" "_")
            timeout 8 bash -c "
                echo | openssl s_client -connect \"{}:443\" \
                    -servername \"{}\" 2>/dev/null | \
                    openssl x509 -noout -text
            " > "'$OUTDIR'/ssl/${safe}.txt" 2>/dev/null
        ' || true
    stage_success "ssl_certs"

    # ============================================
    # 8) CLOUDRIP (CDN‑bypass helper)
    #    An external tool that checks whether
    #    subdomains still point to Cloudflare.
    # ============================================
    info "8) CloudRip..."
    python3 "$CLOUDRIP_SCRIPT" "$TARGET" \
        -l "$OUTDIR/all_discovered.txt" \
        -t 20 \
        -o "$OUTDIR/cloudrip_results.txt" 2>/dev/null || true
    stage_success "cloudrip"

    # ============================================
    # 9) FINAL ANALYSIS – FIND THE ORIGIN IP
    # ============================================
    info "9) Scoring all IPs we found..."

    # --- collect all IPs that currently resolve ---
    grep -rhE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTDIR/dns/" 2>/dev/null | \
        sort -u > "$OUTDIR/current_ips.txt"

    # --- remove IPs that belong to a CDN (they are not the real server) ---
    grepcidr -v -f "$OUTDIR/cdn_ranges.txt" "$OUTDIR/current_ips.txt" \
        > "$OUTDIR/possible_origin_ips_raw.txt" 2>/dev/null || true

    # ============================================
    # GATHER ALL THE EVIDENCE WE CAN
    # ============================================

    # --- A. Historical DNS ---
    if [ -s "$OUTDIR/historical/historical_${TARGET}_ips.txt" ]; then
        while read -r ip; do
            record_evidence "$ip" "historical_dns"
        done < "$OUTDIR/historical/historical_${TARGET}_ips.txt"
    fi

    # --- B. SSL SANs (IP addresses found inside certificates) ---
    # We use process substitution "< <(...)" to keep the loop
    # inside the main shell, not a subshell.
    while read -r ip; do
        record_evidence "$ip" "ssl_san"
    done < <(
        find "$OUTDIR/ssl" -name "*.txt" -exec \
            openssl x509 -in {} -noout -ext subjectAltName 2>/dev/null \; | \
            tr ',' '\n' | grep -oP 'IP Address:\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
    )

    # --- C. SPF records (mail servers are sometimes the origin) ---
    local spf_cidrs="$OUTDIR/spf_cidrs.txt"
    > "$spf_cidrs"   # start with an empty file

    # Pull direct ip4: entries from the main domain’s TXT record
    dig +short TXT "$TARGET" 2>/dev/null | \
        grep 'v=spf1' | grep -oP 'ip4:\K[0-9./]+' >> "$spf_cidrs" || true

    # Follow one level of "include:" (e.g. include:_spf.google.com)
    dig +short TXT "$TARGET" 2>/dev/null | \
        grep 'v=spf1' | grep -oP 'include:\K\S+' | while read -r inc; do
            dig +short TXT "$inc" 2>/dev/null | grep -oP 'ip4:\K[0-9./]+'
        done >> "$spf_cidrs" || true

    sort -u -o "$spf_cidrs" "$spf_cidrs"

    # Check which candidate IPs fall inside these SPF CIDRs
    while read -r ip; do
        record_evidence "$ip" "spf"
    done < <(
        {
            cat "$OUTDIR/possible_origin_ips_raw.txt" 2>/dev/null
            for ip in "${!IP_EVIDENCE[@]}"; do echo "$ip"; done
        } | sort -u | grepcidr -f "$spf_cidrs" - 2>/dev/null
    )

    # --- D. ASN mismatches (is the IP hosted somewhere that is NOT a CDN?) ---
    local asn_tmp="$OUTDIR/asn_work.txt"
    > "$asn_tmp"

    # Create a full list of candidates (raw + evidence IPs)
    {
        cat "$OUTDIR/possible_origin_ips_raw.txt" 2>/dev/null
        for ip in "${!IP_EVIDENCE[@]}"; do echo "$ip"; done
    } | sort -u > "$OUTDIR/all_candidates.txt"

    # Look up the AS number for each candidate (parallel but polite)
    cat "$OUTDIR/all_candidates.txt" | \
        xargs -P 3 -I {} bash -c '
            ip="{}"
            sleep 0.5
            asn=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | \
                  tail -1 | awk "{print \$1}" | tr -d "AS")
            echo "${ip}|${asn}"
        ' >> "$asn_tmp"

    # Record the "asn_mismatch" evidence for any IP that is NOT inside
    # a known CDN AS number.
    while IFS='|' read -r ip asn; do
        if [[ -n "$asn" && ! " $KNOWN_CDN_ASNS " =~ " $asn " ]]; then
            record_evidence "$ip" "asn_mismatch"
        fi
    done < "$asn_tmp"

    # ============================================
    # CALCULATE FINAL SCORES
    # ============================================
    local scored="$OUTDIR/possible_origin_ips_scored.txt"
    > "$scored"

    # Build a final list that includes both the raw non‑CDN IPs AND
    # any IP that we found evidence for (even if it is currently inside
    # a CDN range, because it might be the historical origin).
    {
        cat "$OUTDIR/possible_origin_ips_raw.txt" 2>/dev/null
        for ip in "${!IP_EVIDENCE[@]}"; do echo "$ip"; done
    } | sort -u | while read -r ip; do
        sources="${IP_EVIDENCE[$ip]:-}"
        score=0
        if [[ -n "$sources" ]]; then
            score=$(weighted_score "$sources")
        fi
        echo "$ip|$score|${sources:-none}" >> "$scored"
    done

    # Show the IPs with the highest score at the top
    sort -t'|' -k2 -nr -o "$scored" "$scored"

    if [ -s "$scored" ]; then
        ok "Candidate origin IPs (weighted):"
        head -10 "$scored" | column -t -s '|'
    else
        warn "Zero candidates found."
    fi

    # ============================================
    # OPTIONAL: nmap scan on the top candidates
    # ============================================
    if $NMAP_MODE; then
        info "Launching nmap scan on top 5 candidates..."
        cut -d'|' -f1 "$scored" | head -5 | \
            xargs -I {} nmap -sV -T4 -p 80,443,8080,8443 {} \
                -oN "$OUTDIR/nmap_scan.txt" > /dev/null 2>&1 &
        wait $!   # wait for nmap to finish before we end
        ok "Nmap scan completed."
    fi

    # ============================================
    # FINAL SUMMARY
    # ============================================
    print_stage_summary
    if $REPORT_MODE; then
        generate_report "$OUTDIR" "$TARGET"
    fi
    ok "All done! Results are in: $OUTDIR"
}

# ---------- make sure all required tools are installed ----------
check_tools() {
    local tools=("subfinder" "assetfinder" "httpx" "ffuf" "gobuster" "jq" "whois" "dig" "openssl" "python3" "grepcidr" "curl")
    local missing=()
    for t in "${tools[@]}"; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        fail "Missing tools: ${missing[*]}. Please install them and try again."
    fi
    if [ ! -f "$CLOUDRIP_SCRIPT" ]; then
        fail "cloudrip.py not found. Please set CLOUDRIP_SCRIPT or clone it from GitHub."
    fi
    if [ ! -f "$WORDLIST" ]; then
        fail "Wordlist not found: $WORDLIST. Download it from SecLists."
    fi
}

# ---------- run ----------
check_tools
main
