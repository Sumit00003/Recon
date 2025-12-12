#!/bin/bash
# ------------------------------------------------------
#  RECON Automation — ASCII Banner
# ------------------------------------------------------

echo -e "
\e[35m██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\e[0m

       \e[96mAutomated Recon Framework\e[0m
------------------------------------------------------
"
# ---------------------------
# Recon Automation Script (Improved)
# ---------------------------

# Colors
RED="\e[91m"
GREEN="\e[92m"
YELLOW="\e[93m"
BLUE="\e[94m"
PURPLE="\e[95m"
CYAN="\e[96m"
RESET="\e[0m"

# Pretty print helpers (FULL COLOR)
info()  { echo -e "${BLUE}[ INFO ]${RESET}  ${CYAN}$1${RESET}"; }
ok()    { echo -e "${GREEN}[ OK ]${RESET}    ${GREEN}$1${RESET}"; }
err()   { echo -e "${RED}[ ERROR ]${RESET} ${RED}$1${RESET}"; }
warn()  { echo -e "${YELLOW}[ WARN ]${RESET}  ${YELLOW}$1${RESET}"; }

# Strict mode: Exit if any command fails
#set -e

if [ -z "$2" ]; then
    err "Usage: ./recon.sh target.com output_file_name"
    exit 1
fi

# Check if command exists
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        err "{RED}ERROR: $1 not found! Install it first."
        exit 1
    else
        ok "$1 found"
    fi
}

info "Checking Required Tools\n"
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
#echo -e "\n"
ok "Making Output Directory...\n"

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
rm $output/all_subs.txt
# ---------------------------
# 3. Httpx Scan
# ---------------------------
ok "Running Github Tool Httpx..."
ok "Extracting ---> Status Code - Titles - Server Name"
/home/kali/Tools/Httpx/httpx \
    -silent \
    -sc \
    -title \
    -server \
    -nc \
    -rl 20 \
    -l "$output/alive_sub-domain.txt" \
    > "$output/httpx.txt"
# Remove empty brackets and add header line
if [ -s "$output/httpx.txt" ]; then
    sed -i '1i Status code - Title - Web server name' "$output/httpx.txt"
    sed -i 's/\[\s*\]//g' "$output/httpx.txt"
    info "Httpx Result Found\n"
else 
    err "Not Found any result\n"
fi

#The comment Code was save to other file
# ---------------------------
# 4. Waybackurls
# ---------------------------

ok "Fetching historical URLs (waybackurls)..."
cat "$output/alive_sub-domain.txt" | waybackurls > "$output/way.txt"
cat "$output/way.txt" | sort -u > "$output/wayback.txt"
info "Waybackurls retrieved\n"
ok "WayBackurls: $(wc -l < "$output/wayback.txt")"
if [ -s "$output/wayback.txt" ]; then
    awk -F'?' '
    {
        url=$0
        # Case 1: No parameters → keep all unique exact URLs
        if (NF == 1) {
            if (!seen_no_param[url]++) print url
            next
        }
        # Case 2: URL contains parameters
        base=$1
        params=$2
        # Remove parameter values → keep only key names for uniqueness
        param_key = params
        gsub(/=[^&]*/, "=", param_key)
        # Uniqueness key is: path + stripped param names
        key = base "?" param_key
        # Print only the FIRST occurrence of this pattern
        if (!seen[key]++) print url
    }
    ' "$output/wayback.txt" > "$output/waybackurls.txt" 
    ok "Sorted"
    ok "WayBackurls: $(wc -l < "$output/waybackurls.txt")"
    cat "$output/waybackurls.txt" | grep "=" > "$output/way-parameters.txt"
    cat "$output/waybackurls.txt" | grep -Ei '\.[a-z0-9]{1,5}($|\?)' "$output/waybackurls.txt" > "$output/way-files.txt"
else
    err "No Wayback urls"
fi
rm "$output/way.txt" 
#rm "$output/wayback.txt" <--- May have something
# ---------------------------
# 5. Subdomain Takeover Scan
# ---------------------------

ok "Checking for Subdomain Takeover (subzy)..."
subzy run --targets "$output/alive_sub-domain.txt" > "$output/subzy.txt"
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
 
    
else
    err "[-] No URL Found"
fi

#------------------------------------------------------
# Secret Finder
#------------------------------------------------------
ok "Running SecretFinder...."
if [ -s "$output/js_urls.txt" ]; then
    input_file="$output/js_urls.txt"
    info "JS FILES is PRESENT\n"
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
        echo -e "\n"
        err "NO SECRETS FOUND\n"
    # Optional: remove empty directory
        rmdir "$output_dir"
    else
        echo -e "\n"
        ok "SECRETS FOUND — Results saved in: $output_dir\n"
    fi
fi

echo -e "${GREEN} RECON COMPLETE${RESET}\n"
ok "Staring AI Analysis\n"
info "Changing Directory"

cd "$output"

python3 /home/kali/Recon/AI.py


