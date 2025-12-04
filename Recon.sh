#!/bin/bash

# ---------------------------
# Recon Automation Script (Improved)
# ---------------------------

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# Pretty print helpers
info() { echo -e "${BLUE}[i]${RESET} $1"; }
ok() { echo -e "${GREEN}[+]${RESET} $1"; }
err() { echo -e "${RED}[X]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }

# Strict mode: Exit if any command fails
set -e

if [ -z "$2" ]; then
    err "Usage: ./recon.sh target.com output_file_name"
    exit 1
fi

# Check if command exists
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        err "ERROR: $1 not found! Install it first."
        exit 1
    else
        ok "$1 found"
    fi
}

info "Checking Required Tools"
check_tool subfinder
check_tool assetfinder
check_tool httprobe
check_tool httpx
check_tool waybackurls
check_tool subzy
check_tool katana



domain=$1
output=$2
mkdir -p "$output"
ok "Output folder created: $output\n"

# ---------------------------
# 1. Subdomain Enumeration
# ---------------------------

ok "Running Subfinder..."
subfinder -d "$domain" -silent > "$output/subfinder.txt"

ok "Running Assetfinder..."
assetfinder --subs-only "$domain" > "$output/assetfinder.txt"

cat "$output/subfinder.txt" "$output/assetfinder.txt" | sort -u > "$output/all_subs.txt"
rm "$output/assetfinder.txt"
rm "$output/subfinder.txt"
info "Total unique subdomains: $(wc -l < "$output/all_subs.txt")\n"

# ---------------------------
# 2. Alive Domain Checking
# ---------------------------

ok "Checking Alive Subdomains (httprobe)..."
cat "$output/all_subs.txt" | httprobe > "$output/alive_sub-domain.txt"
info "Alive hosts: $(wc -l < "$output/alive_sub-domain.txt")\n"

# ---------------------------
# 3. Httpx Scan
# ---------------------------
ok "Running Github Tool Httpx...\n"
/home/kali/Tools/Httpx/httpx \
    -silent \
    -sc \
    -title \
    -server \
    -cdn \
    -method \
    -nc \
    -rl 20 \
    -l "$output/alive_sub-domain.txt" \
    > "$output/httpx.txt"

: << 'COMMENT'
mkdir -p "$output/httpx"
ok "Running Github Tool Httpx..."
info "Status Code"
/home/kali/Tools/Httpx/httpx -silent -sc -nc -l "$output/alive_sub-domain.txt" > "$output/httpx/status_code.txt"
if [ -s "$output/httpx/status_code.txt" ]; then
    ok "Status code retrived"
else
    err "No Status Code"
    rm "$output/httpx/status_code.txt"
fi
info "Titles"
/home/kali/Tools/Httpx/httpx -silent -title -nc -rl 50 -l "$output/alive_sub-domain.txt" > "$output/httpx/Titles.txt"
if [ -s "$output/httpx/Titles.txt" ]; then
    ok "Titles retrived"
else
    err "No Titles"
    rm "$output/httpx/Titles.txt"
fi
info "Server Banner"
/home/kali/Tools/Httpx/httpx -server -silent -nc -rl 30 -l "$output/alive_sub-domain.txt" > "$output/httpx/Servers.txt"
if [ -s "$output/httpx/Servers.txt" ]; then
    ok "Server Banner retrived"
else
    err "No Banner"
    rm "$output/httpx/Servers.txt"
fi
info "Firewalls"
/home/kali/Tools/Httpx/httpx -cdn -silent -nc -rl 10 -l "$output/alive_sub-domain.txt" > "$output/httpx/firewalls.txt"
if [ -s "$output/httpx/firewalls.txt" ]; then
    ok "Firewall Detected!!"
    #cat "$output/httpx/firewalls.txt"
else
    err "No Banner"
    rm "$output/httpx/firewalls.txt"
fi
info "HTTP METHOD ALLOWED"
/home/kali/Tools/Httpx/httpx -method -silent -nc -rl 10 -l "$output/alive_sub-domain.txt" > "$output/httpx/http_method.txt"
if [ -s "$output/httpx/http_method.txt" ]; then
    ok "Http Methods Extracted\n"
else
    err "No Additional Methods Found\n"
    rm "$output/httpx/http_method.txt"
fi
COMMENT
# ---------------------------
# 4. Waybackurls
# ---------------------------

ok "Fetching historical URLs (waybackurls)..."
cat "$output/alive_sub-domain.txt" | waybackurls > "$output/waybackurl.txt"
cat "$output/waybackurl.txt" | sort -u > "$output/waybackurls.txt"
ok "WayBackurls: $(wc -l < "$output/waybackurls.txt")"
if [ -s "$output/waybackurls.txt" ]; then
    info "Waybackurls retrieved\n"
    cat "$output/waybackurls.txt" | grep "=" > "$output/way-parameters.txt"
    cat "$output/waybackurls.txt" | grep -Ei "\.js" > "$output/way-js-urls.txt"
else
    err "No Wayback urls"
fi
rm "$output/waybackurl.txt"
# ---------------------------
# 5. Subdomain Takeover Scan
# ---------------------------

ok "Checking for Subdomain Takeover (subzy)..."
subzy run --targets "$output/all_subs.txt" > "$output/subzy.txt"
rm $output/all_subs.txt
if grep -q "DISCUSSION" "$output/subzy.txt"; then
    info "Found Vuln Subdomains...\n"
else
    err "No Subdomains is Vulnerable\n"
fi
# ---------------------------
# 6. Crawling with Katana
# ---------------------------

ok "Running Katana crawler..."
katana -list "$output/alive_sub-domain.txt" -silent > "$output/katana.txt"
if [ -s "$output/katana.txt" ]; then
    info "URL retrived with katana\n"
else
    err "[-] No URL Found"
fi
# ---------------------------
# 7. Extract JS files
# ---------------------------

ok "Extracting Vectors from Katana Output..\n"
grep -Ei "\.js$" "$output/katana.txt" | sort -u > "$output/js_urls.txt"
if [ -s "$output/js_urls.txt" ]; then
    info "JS Files retrived"
else
    err "No JS Files Found"
    rm "$output/js_urls.txt"
fi

# ---------------------------
# 8. Extract URLs with Parameters
# ---------------------------

#ok "Extracting URLs with parameters..."
grep "?" "$output/katana.txt" | sort -u > "$output/params_urls.txt"
if [ -s "$output/params_urls.txt" ]; then
    info "Parameters retrived\n"
else
    err "No JS Files Found\n"
    rm "$output/js_urls.txt"
fi

# ---------------------------
# 9. Extract files by extensions
# ---------------------------

ok "Extracting files by extension...\n"

extract_file() {
    ext="$1"
    file="$output/${ext}_files.txt"

    grep -Ei "\.${ext}$" "$output/katana.txt" > "$file" 2>/dev/null || true
    [ -s "$file" ] || rm -f "$file"
}

extract_file "php"
extract_file "json"
extract_file "txt"
extract_file "html"
extract_file "config"
extract_file "conf"

#------------------------------------------------------
#Secret Finder
#------------------------------------------------------
ok "Running SecretFinder...."
if [ -s "$output/js_urls.txt" ]; then
    input_file="$output/js_urls.txt"
    info "JS FILES is PRESENT"
    output_dir="secretfinder_output"
    mkdir -p "$output_dir"
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        # Safe filename
        filename=$(echo "$url" | sed 's|https\?://||' | sed 's|/|_|g')
        outfile="$output_dir/${filename}.txt"

        echo "Scanning: $url"

    # Temporary output
        temp_out=$(mktemp)

    # Run SecretFinder
        python3 /home/kali/Tools/SecretFinder/SecretFinder.py -i "$url" -o cli > "$temp_out"

    # -------------------------------
    # If output has only 1 line → discard
    # -------------------------------
        if [ "$(wc -l < "$temp_out")" -eq 1 ]; then
            echo "➤ No secrets for $url — discarded"
            rm "$temp_out"
            continue
        fi

        # Otherwise save result
        mv "$temp_out" "$outfile"
        echo "➤ Saved: $outfile"

    done < "$input_file"
else
    err "No JS Files Present\n"
fi
# ---------------------------------
# FINAL CHECK: ANY FILES GENERATED?
# ---------------------------------
if [ -d "secretfinder_output" ]; then
    if [ "$(ls -1 "$output_dir" | wc -l)" -eq 0 ]; then
        err "NO SECRETS FOUND"
    # Optional: remove empty directory
        rmdir "$output_dir"
    else
        ok "SECRETS FOUND — Results saved in: $output_dir"
    fi
fi

# ---------------------------
# Summary
# ---------------------------

echo -e "${GREEN}=================================${RESET}"
echo -e "${GREEN}        RECON COMPLETE${RESET}"
echo -e "${GREEN}=================================${RESET}"
ok "Output stored in: $output\n"

echo -e "${BLUE}Files created:${RESET}"
ls -1 "$output"

echo -e "\n${GREEN}Happy Hunting!${RESET}"

