#!/usr/bin/env bash

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
HTML_REPORT="$RESULTS_DIR/dorks.html"
CONFIG_DIR="$SCRIPT_DIR/config"
DORKS_FILE="$CONFIG_DIR/dorks.cfg"
USER_AGENTS_FILE="$CONFIG_DIR/user_agents.txt"
PROXIES_FILE="$CONFIG_DIR/proxies.txt"
DOMAIN=""
COMPANY=""
DELAY_MIN=35
DELAY_MAX=60
TAB_DELAY=10
MAX_RETRIES=2
MAX_TABS=0
USE_PROXIES=false
CURRENT_YEAR=$(date +%Y)

# Banner
f_banner() {
    echo
    echo -e "${CYAN}"
    cat << "BANNER"
              ___.        .___            __            
__  _  __ ____\_ |__    __| _/___________|  | __  ______
\ \/ \/ // __ \| __ \  / __ |/  _ \_  __ \  |/ / /  ___/
 \     /\  ___/| \_\ \/ /_/ (  <_> )  | \/    <  \___ \ 
  \/\_/  \___  >___  /\____ |\____/|__|  |__|_ \/____  >
             \/    \/      \/                 \/     \/ 

                            by ~/.manojxshrestha
BANNER
    echo -e "${NC}"
    echo -e "${YELLOW}Advanced Google Dorking Automation Suite${NC}"
    echo -e "${BLUE}Smart Query Engine with Anti-Detection & Proxy Rotation${NC}"
    echo
}

# Error handling
f_error() {
    echo -e "${RED}[!] Error: $1${NC}" >&2
    exit 1
}

# Check dependencies
f_check_deps() {
    local deps=("curl" "python3")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        f_error "Missing dependencies: ${missing[*]}"
    fi
    
    if ! command -v "firefox" &> /dev/null; then
        echo -e "${YELLOW}[!] Firefox not found - manual tab opening disabled${NC}"
    fi
}

# Enhanced proxy validation
f_validate_proxy() {
    local proxy="$1"
    
    if [ -z "$proxy" ]; then
        return 1
    fi
    
    if timeout 15 curl -s --proxy "$proxy" "https://www.google.com" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Initialize configuration
f_init_config() {
    echo -e "${BLUE}[*] Initializing configuration...${NC}"
    
    mkdir -p "$RESULTS_DIR" "$CONFIG_DIR" || f_error "Cannot create directories"
    
    if [ ! -f "$DORKS_FILE" ] || [ ! -s "$DORKS_FILE" ]; then
        f_error "Dorks configuration file not found or empty: $DORKS_FILE"
    fi
    
    if [ ! -f "$USER_AGENTS_FILE" ]; then
        echo -e "${YELLOW}[*] Creating default user agents file...${NC}"
        cat > "$USER_AGENTS_FILE" << 'EOF'
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
EOF
    fi
    
    if [ ! -f "$PROXIES_FILE" ]; then
        echo -e "${YELLOW}[*] Creating proxies template...${NC}"
        cat > "$PROXIES_FILE" << 'EOF'
# Add your proxies here (one per line)
# Format: http://username:password@proxy:port
# Or: http://proxy:port
# Free proxy sources (test before using):
# https://www.sslproxies.org/
# https://free-proxy-list.net/
# https://geonode.com/free-proxy-list/

# Example working proxies (replace with your own):
# http://45.77.56.113:3128
# http://138.197.157.32:3128
EOF
        echo -e "${YELLOW}[!] No proxies configured. Using direct connection${NC}"
    else
        local total_proxies=0
        local valid_proxies=0
        local temp_proxies_file="$PROXIES_FILE.validated"
        
        > "$temp_proxies_file"
        
        while IFS= read -r proxy || [ -n "$proxy" ]; do
            [[ -z "$proxy" || "$proxy" =~ ^[[:space:]]*# ]] && continue
            ((total_proxies++))
            
            if f_validate_proxy "$proxy"; then
                echo "$proxy" >> "$temp_proxies_file"
                ((valid_proxies++))
                echo -e "${GREEN}[+] Valid proxy: $(echo "$proxy" | cut -d'@' -f2-)${NC}"
            else
                echo -e "${YELLOW}[-] Invalid proxy: $proxy${NC}"
            fi
        done < "$PROXIES_FILE"
        
        if [ $valid_proxies -gt 0 ]; then
            mv "$temp_proxies_file" "$PROXIES_FILE"
            USE_PROXIES=true
            echo -e "${GREEN}[+] Proxies enabled ($valid_proxies/$total_proxies valid proxies)${NC}"
        else
            rm -f "$temp_proxies_file"
            echo -e "${YELLOW}[!] No valid proxies found - using direct connection${NC}"
        fi
    fi
    
    echo -e "${GREEN}[+] Configuration initialized${NC}"
}

# Get random user agent
f_get_random_ua() {
    if [ -f "$USER_AGENTS_FILE" ] && [ -s "$USER_AGENTS_FILE" ]; then
        shuf -n 1 "$USER_AGENTS_FILE" 2>/dev/null || \
        echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    else
        echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    fi
}

# Get random proxy
f_get_random_proxy() {
    if [ "$USE_PROXIES" = true ] && [ -f "$PROXIES_FILE" ] && [ -s "$PROXIES_FILE" ]; then
        grep -E '^[^#]' "$PROXIES_FILE" | shuf -n 1 2>/dev/null | tr -d '\n'
    else
        echo ""
    fi
}

# Get random delay
f_get_random_delay() {
    echo $((RANDOM % (DELAY_MAX - DELAY_MIN + 1) + DELAY_MIN))
}

# URL encode function
f_url_encode() {
    local input="$1"
    python3 -c "import urllib.parse; print(urllib.parse.quote('''$input'''))" 2>/dev/null || echo "$input"
}

# Load and process dorks
f_load_dorks() {
    local domain="$1"
    
    echo -e "${BLUE}[*] Loading and processing dorks...${NC}"
    
    sed "s/TARGET/$domain/g; s/CURRENT_YEAR/$CURRENT_YEAR/g" "$DORKS_FILE" | \
    grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$'
}

# Enhanced Google search with CAPTCHA avoidance
f_google_search() {
    local query="$1"
    local output_file="$2"
    local attempt=0
    local success=false
    
    local encoded_query
    encoded_query=$(f_url_encode "$query")
    local google_url="https://www.google.com/search?q=$encoded_query&num=10&hl=en"
    
    while [ $attempt -lt $MAX_RETRIES ] && [ "$success" = false ]; do
        ((attempt++))
        
        local user_agent=$(f_get_random_ua)
        local delay=$(f_get_random_delay)
        local proxy=$(f_get_random_proxy)
        
        echo -e "${YELLOW}[Attempt $attempt]${NC} $(echo "$query" | cut -c-60)..."
        
        local curl_cmd=("curl" "-s" "-A" "$user_agent")
        
        if [ -n "$proxy" ] && [ "$USE_PROXIES" = true ]; then
            curl_cmd+=("--proxy" "$proxy")
            echo -e "${PURPLE}[Proxy] Using: $(echo "$proxy" | cut -d'@' -f2- | cut -c-30)${NC}"
        fi
        
        curl_cmd+=(
            "-H" "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
            "-H" "Accept-Language: en-US,en;q=0.9"
            "-H" "Accept-Encoding: gzip, deflate, br"
            "-H" "DNT: 1"
            "-H" "Connection: keep-alive"
            "-H" "Upgrade-Insecure-Requests: 1"
            "-H" "Sec-Fetch-Dest: document"
            "-H" "Sec-Fetch-Mode: navigate"
            "-H" "Sec-Fetch-Site: none"
            "-H" "Cache-Control: max-age=0"
            "--max-time" "45"
            "--retry" "1"
            "--location"
            "$google_url"
        )
        
        local micro_delay=$((RANDOM % 3 + 1))
        sleep $micro_delay
        
        local curl_output
        if curl_output=$("${curl_cmd[@]}" 2>/dev/null); then
            if echo "$curl_output" | grep -qi "captcha\|sorry\|detected.*unusual\|rate.*limit\|automated.*requests\|429\|503"; then
                echo -e "${RED}[!] CAPTCHA/Block detected${NC}"
                local block_delay=300
                echo -e "${YELLOW}[*] Heavy block - waiting ${block_delay}s...${NC}"
                sleep $block_delay
                return 1
            fi
            
            if [ -z "$curl_output" ] || [ $(echo "$curl_output" | wc -c) -lt 500 ]; then
                echo -e "${YELLOW}[!] Empty response received${NC}"
                sleep $delay
                continue
            fi
            
            if echo "$curl_output" | grep -qi "search.*result\|result-stats\|About.*results"; then
                echo "$curl_output" > "$output_file"
                success=true
                
                local result_count
                result_count=$(grep -o "About [0-9,]* results" "$output_file" | head -1 | grep -o "[0-9,]*" | tr -d ',' 2>/dev/null || echo "0")
                if [ -n "$result_count" ] && [ "$result_count" -gt 0 ]; then
                    echo -e "${GREEN}[+] Success - Found ~$result_count results${NC}"
                else
                    echo -e "${GREEN}[+] Successfully fetched results${NC}"
                fi
            else
                echo -e "${YELLOW}[!] No search results in response${NC}"
                sleep $delay
            fi
        else
            echo -e "${YELLOW}[!] Curl command failed${NC}"
            sleep $delay
        fi
        
        if [ $attempt -lt $MAX_RETRIES ]; then
            echo -e "${CYAN}[*] Waiting ${delay}s before next attempt...${NC}"
            sleep $delay
        fi
    done
    
    if [ "$success" = false ]; then
        echo -e "${RED}[!] Failed after $MAX_RETRIES attempts - skipping${NC}"
        return 1
    fi
    
    return 0
}

# Enhanced HTML parsing
f_parse_google_results() {
    local html_file="$1"
    local domain="$2"
    local severity="$3"
    
    python3 - << EOF
import re
import html
from urllib.parse import unquote, urlparse
import sys

def advanced_google_parser(html_file, target_domain, severity):
    try:
        with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return []
    
    results = []
    
    patterns = [
        r'<a href="/url\?q=([^"]+)"',
        r'<a href="([^"]+)"[^>]*data-ved',
        r'<a class="[^"]*" href="/url\?q=([^"]+)"',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            try:
                url = unquote(match.split('&')[0])
                
                if any(block in url.lower() for block in ['google.com', 'googleusercontent.com', '/settings/', 'accounts.google']):
                    continue
                    
                if not url.startswith(('http://', 'https://')):
                    continue
                
                parsed_url = urlparse(url)
                if target_domain in parsed_url.netloc or target_domain in url:
                    results.append({
                        'url': url,
                        'severity': severity,
                        'domain': parsed_url.netloc
                    })
                    
            except Exception as e:
                continue
    
    seen = set()
    unique_results = []
    for result in results:
        if result['url'] not in seen:
            seen.add(result['url'])
            unique_results.append(result)
    
    return unique_results

if __name__ == "__main__":
    html_file = "$html_file"
    domain = "$domain"
    severity = "$severity"
    
    try:
        results = advanced_google_parser(html_file, domain, severity)
        for result in results:
            print(f"{result['url']}|||{result['severity']}|||{result['domain']}")
    except Exception as e:
        sys.exit(1)
EOF
}

# Initialize HTML report
f_init_html_report() {
    mkdir -p "$RESULTS_DIR" || f_error "Cannot create results directory"
    
    if ! touch "$HTML_REPORT" 2>/dev/null; then
        f_error "Cannot create HTML report file: $HTML_REPORT"
    fi
    
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>webdorks - $DOMAIN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #007cba; }
        h1 { color: #333; margin: 0; }
        .stats { background: #e9ecef; padding: 15px; border-radius: 5px; margin: 15px 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
        .stat-item { text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: bold; }
        .dork-group { margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        .dork-title { background: #f8f9fa; padding: 10px; font-weight: bold; }
        .result-item { margin: 5px 0; padding: 8px; background: #f9f9f9; border-left: 4px solid #007cba; word-break: break-all; }
        .result-item a { color: #007cba; text-decoration: none; }
        .critical { border-left-color: #dc3545; background: #ffe6e6; }
        .high { border-left-color: #fd7e14; background: #fff3e6; }
        .medium { border-left-color: #ffc107; background: #fff9e6; }
        .low { border-left-color: #28a745; background: #e6f4ea; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 webdorks - $DOMAIN</h1>
            <p>Scan Date: $(date)</p>
        </div>
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number" id="totalDorks">0</div>
                <div>Total Dorks</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="totalResults">0</div>
                <div>Total Findings</div>
            </div>
        </div>
EOF
    echo -e "${GREEN}[+] HTML report initialized: $HTML_REPORT${NC}"
}

# Add results to HTML report
f_add_to_html_report() {
    local dork_query="$1"
    local results_file="$2"
    local severity="$3"
    
    local result_count=0
    local severity_class=""
    
    case $severity in
        CRITICAL) severity_class="critical" ;;
        HIGH) severity_class="high" ;;
        MEDIUM) severity_class="medium" ;;
        LOW) severity_class="low" ;;
        *) severity_class="low" ;;
    esac
    
    if [ -f "$results_file" ] && [ -s "$results_file" ]; then
        result_count=$(wc -l < "$results_file" 2>/dev/null | tr -d ' ' || echo 0)
    fi
    
    {
        echo "        <div class=\"dork-group\">"
        echo "            <div class=\"dork-title\">"
        echo "                $dork_query - <small>$result_count results</small>"
        echo "            </div>"
    } >> "$HTML_REPORT"

    if [ -f "$results_file" ] && [ "$result_count" -gt 0 ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            [[ -z "$line" ]] && continue
            local url=$(echo "$line" | cut -d'|||' -f1)
            
            {
                echo "            <div class=\"result-item $severity_class\">"
                echo "                <a href=\"$url\" target=\"_blank\">$url</a>"
                echo "            </div>"
            } >> "$HTML_REPORT"
        done < "$results_file"
    else
        {
            echo "            <div style=\"padding: 20px; text-align: center; color: #666;\">No results found</div>"
        } >> "$HTML_REPORT"
    fi

    {
        echo "        </div>"
    } >> "$HTML_REPORT"
}

# Smart dork execution with CAPTCHA avoidance
f_smart_dork_execution() {
    local domain="$1"
    local company="$2"
    
    echo -e "${BLUE}[*] Starting smart dork execution...${NC}"
    echo -e "${CYAN}[*] Delays: ${DELAY_MIN}-${DELAY_MAX}s | Retries: ${MAX_RETRIES} | Results: 10 per search${NC}"
    
    local proxy_count=0
    if [ "$USE_PROXIES" = true ] && [ -f "$PROXIES_FILE" ]; then
        proxy_count=$(grep -c -E '^[^#]' "$PROXIES_FILE" 2>/dev/null || echo 0)
        echo -e "${GREEN}[*] Proxy rotation: ACTIVE ($proxy_count proxies)${NC}"
    else
        echo -e "${YELLOW}[*] Proxy rotation: INACTIVE${NC}"
    fi
    
    echo
    
    local total_dorks=0
    local successful_dorks=0
    local total_results=0
    
    local temp_dir
    temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT INT TERM
    
    for severity in CRITICAL HIGH MEDIUM LOW STEALTH; do
        echo -e "${PURPLE}[*] Processing $severity severity dorks...${NC}"
        
        while IFS= read -r line || [ -n "$line" ]; do
            [[ -z "$line" ]] && continue
            
            local dork_severity=$(echo "$line" | cut -d: -f1)
            local dork_query=$(echo "$line" | cut -d: -f2-)
            
            [ "$dork_severity" != "$severity" ] && continue
            [[ -z "$dork_query" ]] && continue
            
            ((total_dorks++))
            
            local safe_name
            safe_name=$(echo "$dork_query" | tr ' ' '_' | tr -cd '[:alnum:]_\-' | cut -c-50)
            local html_file="$temp_dir/${severity}_${safe_name}.html"
            local results_file="$temp_dir/${severity}_${safe_name}_results.txt"
            
            if f_google_search "$dork_query" "$html_file"; then
                ((successful_dorks++))
                
                local parsed_results=0
                if f_parse_google_results "$html_file" "$domain" "$severity" > "$results_file" 2>/dev/null; then
                    parsed_results=$(wc -l < "$results_file" 2>/dev/null | tr -d ' ' || echo 0)
                fi
                
                if [ "$parsed_results" -gt 0 ]; then
                    total_results=$((total_results + parsed_results))
                    echo -e "${GREEN}[+] Found $parsed_results results${NC}"
                else
                    echo -e "${YELLOW}[-] No results found${NC}"
                fi
                
                f_add_to_html_report "$dork_query" "$results_file" "$severity"
            else
                echo -e "${RED}[-] Search failed${NC}"
            fi
            
            echo
            
        done < <(f_load_dorks "$domain")
    done
    
    echo -e "${CYAN}[*] Scan Complete!${NC}"
    echo -e "${GREEN}[+] Dorks executed: $successful_dorks/$total_dorks${NC}"
    echo -e "${GREEN}[+] Total findings: $total_results${NC}"
    echo -e "${BLUE}[+] HTML Report: $HTML_REPORT${NC}"
}

# Firefox tab opening with 10-second delays
f_open_firefox_tabs() {
    local domain="$1"
    local company="$2"
    
    if ! command -v "firefox" &> /dev/null; then
        echo -e "${RED}[!] Firefox not available - cannot open tabs${NC}"
        return 1
    fi
    
    echo -e "${BLUE}[*] Opening Firefox tabs (UNLIMITED MODE - ${TAB_DELAY}s delays)...${NC}"
    
    local tab_count=0
    
    while IFS= read -r line || [ -n "$line" ]; do
        [[ -z "$line" ]] && continue
        
        local severity=$(echo "$line" | cut -d: -f1)
        local dork_query=$(echo "$line" | cut -d: -f2-)
        [[ -z "$dork_query" ]] && continue
        
        local encoded_dork
        encoded_dork=$(f_url_encode "$dork_query")
        local google_url="https://www.google.com/search?q=$encoded_dork&num=10"
        
        firefox --new-tab "$google_url" 2>/dev/null &
        
        ((tab_count++))
        echo -e "${GREEN}[+] Tab $tab_count: $(echo "$dork_query" | cut -c-50)...${NC}"
        echo -e "${YELLOW}[*] Waiting ${TAB_DELAY}s before next tab...${NC}"
        
        sleep $TAB_DELAY
        
    done < <(f_load_dorks "$domain")
    
    echo -e "${GREEN}[+] Opened $tab_count Firefox tabs (ALL dorks)${NC}"
}

# Finalize HTML report
f_finalize_html_report() {
    cat >> "$HTML_REPORT" << EOF
        <script>
            document.getElementById('totalResults').textContent = 
                document.querySelectorAll('.result-item').length;
            document.getElementById('totalDorks').textContent = 
                document.querySelectorAll('.dork-group').length;
        </script>
    </div>
</body>
</html>
EOF
}

# Main execution function
f_main() {
    f_banner
    f_check_deps
    f_init_config
    
    echo -e "${BLUE}Enter target information:${NC}"
    echo
    echo -n "Company: "
    read -r COMPANY
    [ -z "$COMPANY" ] && f_error "Company name is required"
    
    echo -n "Domain (without http://): "
    read -r DOMAIN
    [ -z "$DOMAIN" ] && f_error "Domain is required"
    
    if [[ ! "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        f_error "Invalid domain format: $DOMAIN"
    fi
    
    echo
    echo -e "${GREEN}[*] Target: $COMPANY ($DOMAIN)${NC}"
    echo -e "${YELLOW}[*] Dorks file: $DORKS_FILE${NC}"
    echo -e "${YELLOW}[*] User agents: $(wc -l < "$USER_AGENTS_FILE" 2>/dev/null | tr -d ' ' || echo 0) available${NC}"
    
    if [ "$USE_PROXIES" = true ]; then
        local proxy_count=$(grep -c -E '^[^#]' "$PROXIES_FILE" 2>/dev/null || echo 0)
        echo -e "${GREEN}[*] Proxies: $proxy_count available${NC}"
    else
        echo -e "${YELLOW}[!] No proxies - higher block risk${NC}"
    fi
    echo
    
    f_init_html_report
    
    echo -e "${CYAN}Select execution mode:${NC}"
    echo "1. Automated scanning (HTML report)"
    echo "2. Firefox tabs only (manual review)" 
    echo "3. Both automated and manual"
    echo -n "Choice [1-3]: "
    read -r choice
    
    case $choice in
        1)
            f_smart_dork_execution "$DOMAIN" "$COMPANY"
            ;;
        2)
            f_open_firefox_tabs "$DOMAIN" "$COMPANY"
            ;;
        3)
            echo -e "${YELLOW}[*] Starting combined execution...${NC}"
            f_smart_dork_execution "$DOMAIN" "$COMPANY" &
            local scan_pid=$!
            
            sleep 10
            f_open_firefox_tabs "$DOMAIN" "$COMPANY"
            
            wait "$scan_pid" 2>/dev/null
            ;;
        *)
            f_error "Invalid choice"
            ;;
    esac
    
    f_finalize_html_report
    
    echo
    echo -e "${GREEN}[+] webdorks execution completed!${NC}"
    echo -e "${GREEN}[+] HTML report: $HTML_REPORT${NC}"
    echo
}

trap 'echo -e "${RED}[!] Script interrupted${NC}"; exit 1' INT TERM
f_main "$@"

