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
