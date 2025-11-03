#!/bin/bash

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

echo -e "${BLUE}[*] webdorks - Smart Proxy Scraper${NC}"
echo -e "${YELLOW}[*] Scraping from free-proxy-list.net${NC}"
echo

mkdir -p config
FINAL_FILE="config/proxies.txt"
> "$FINAL_FILE"

# Target number of working proxies
target=30

# Enhanced proxy validation (same as main script)
f_validate_proxy() {
    local proxy="$1"
    
    if [ -z "$proxy" ]; then
        return 1
    fi
    
    # Test proxy with timeout - use Google to test (same as main script)
    if curl -s --proxy "$proxy" --max-time 15 "https://www.google.com" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Fetch function for scraping free-proxy-list.net
fetch_proxies() {
    local url="$1"
    local tmp_file="config/proxies.tmp"
    
    echo -e "${YELLOW}[*] Scraping free-proxy-list.net...${NC}"
    
    curl -s "$url" | \
    grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}</td><td>[0-9]+' | \
    sed 's/<\/td><td>/:/g' | \
    sed 's/^/http:\/\//' > "$tmp_file"
    
    local count=$(wc -l < "$tmp_file" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
        echo -e "${GREEN}[+] Got $count proxies from free-proxy-list.net${NC}"
    else
        echo -e "${RED}[!] free-proxy-list.net failed (empty)${NC}"
        rm -f "$tmp_file"
        return 1
    fi
}

# Scrape from free-proxy-list.net
echo -e "${BLUE}[*] Getting fresh proxy list...${NC}"

if fetch_proxies "https://free-proxy-list.net/"; then
    # Dedup and shuffle
    sort -u config/proxies.tmp | shuf > config/proxies_candidates.tmp
    rm -f config/proxies.tmp
    
    total_candidates=$(wc -l < config/proxies_candidates.tmp 2>/dev/null || echo 0)
    
    if [ "$total_candidates" -eq 0 ]; then
        echo -e "${RED}[!] No proxies found—check connection & retry${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Total unique candidates: $total_candidates${NC}"
    echo
    
    # Test until target (using same validation as main script)
    echo -e "${BLUE}[*] Testing until $target working proxies...${NC}"
    valid_count=0
    tested_count=0
    
    while IFS= read -r proxy && [ $valid_count -lt $target ]; do
        [[ -z "$proxy" ]] && continue
        tested_count=$((tested_count + 1))
        
        printf "Testing %4d/%d: %-40s" "$tested_count" "$total_candidates" "$proxy"
        
        if f_validate_proxy "$proxy"; then
            echo "$proxy" >> "$FINAL_FILE"
            valid_count=$((valid_count + 1))
            echo -e " ${GREEN}✅ WORKING ($valid_count/$target)${NC}"
            
            # Short delay to avoid overwhelming
            sleep 0.5
        else
            echo -e " ${RED}❌ FAILED${NC}"
        fi
        
    done < config/proxies_candidates.tmp
    
    rm -f config/proxies_candidates.tmp
    
else
    echo -e "${RED}[!] Failed to fetch proxies from free-proxy-list.net${NC}"
    exit 1
fi

# Final results
echo
echo -e "${BLUE}[*] Proxy Setup Complete${NC}"
echo -e "${GREEN}=========================================${NC}"

if [ "$valid_count" -gt 0 ]; then
    echo -e "${GREEN}[SUCCESS] $valid_count working proxies saved${NC}"
    
    if [ $valid_count -ge $target ]; then
        echo -e "${GREEN}(Target of $target met!)${NC}"
    else
        echo -e "${YELLOW}(Got $valid_count/$target - good start; rerun for more if needed)${NC}"
    fi
    
    echo -e "${YELLOW}[INFO] File: $FINAL_FILE${NC}"
    echo
    echo -e "${BLUE}Working proxies:${NC}"
    cat "$FINAL_FILE"
    
    # Show proxy count for main script compatibility
    echo
    echo -e "${GREEN}[+] Proxies ready for webdorks${NC}"
    
else
    echo -e "${RED}[FAILURE] Zero working proxies found${NC}"
    echo -e "${YELLOW}[TIPS]${NC}"
    echo -e "1. Rerun in 15-30 mins for new proxy batches"
    echo -e "2. Free proxies have ~5-20% success rate"
    echo -e "3. Check your internet connection"
    > "$FINAL_FILE"
fi

echo
echo -e "${GREEN}=========================================${NC}"
echo -e "${BLUE}[*] Next: Run ./webdorks.sh${NC}"
