#!/bin/bash
# PBH P2P Blocklist Builder — 输出 CIDR 格式，供 PeerBanHelper 订阅
# 基于 Wael Isa 的 Blocklist-builder.sh v1.1.4

OUTPUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${OUTPUT_DIR}/blocklist-work"
OUTPUT_FILE="${OUTPUT_DIR}/wael.txt"
TEMP_RAW="${WORK_DIR}/raw_combined.tmp"
STATS_FILE="${WORK_DIR}/build_stats.log"

declare -A SOURCES=(
    ["Naunter_Mega"]="https://raw.githubusercontent.com/Naunter/BT_BlockLists/master/bt_blocklists.gz"
    ["mxdpeep_Comprehensive"]="https://raw.githubusercontent.com/mxdpeep/p2p-blocklist-creator/master/blocklist.p2p"
    ["eMule_Security"]="http://upd.emule-security.org/ipfilter.zip"
)

# ============================================================================
# 颜色与工具函数
# ============================================================================
if [[ -t 1 ]]; then
    RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
    BLUE='\033[1;34m'; PURPLE='\033[1;35m'; CYAN='\033[1;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; PURPLE=''; CYAN=''; NC=''
fi
log() { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
ok() { echo -e "${GREEN}[OK]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
err() { echo -e "${RED}[ERR]${NC} $1" >&2; }
format_number() {
    echo "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

# ============================================================================
# 依赖检查
# ============================================================================
check_deps() {
    local missing=()
    command -v curl &>/dev/null || missing+=("curl")
    command -v gunzip &>/dev/null || missing+=("gzip")
    command -v awk &>/dev/null || missing+=("awk")
    command -v python3 &>/dev/null || missing+=("python3")
    if [ "${#missing[@]}" -gt 0 ]; then
        err "Missing: ${missing[*]}"
        exit 1
    fi
    ok "All dependencies found"
}

# ============================================================================
# 下载
# ============================================================================
download_source() {
    local name="$1" url="$2" out="$3"
    echo -ne "\r  ${BLUE}▶${NC} Downloading $name... " >&2
    if curl -sL --connect-timeout 15 --max-time 60 --retry 3 --retry-delay 2 "$url" -o "$out"; then
        if file "$out" | grep -q "gzip compressed"; then
            local tmp="${out}.gz"; mv "$out" "$tmp"
            gunzip -c "$tmp" > "$out" 2>/dev/null; rm -f "$tmp"
            echo -e "\r  ${GREEN}✓${NC} $name (gzip)" >&2
        elif file "$out" | grep -q "Zip archive"; then
            local tmp="${out}.zip"; mv "$out" "$tmp"
            unzip -p "$tmp" > "$out" 2>/dev/null; rm -f "$tmp"
            echo -e "\r  ${GREEN}✓${NC} $name (zip)" >&2
        else
            echo -e "\r  ${GREEN}✓${NC} $name" >&2
        fi
        [ -s "$out" ] && return 0
    fi
    echo -e "\r  ${RED}✗${NC} $name" >&2
    return 1
}

download_sources() {
    log "Downloading sources..."
    mkdir -p "${WORK_DIR}/cache"; > "$TEMP_RAW"
    local ok=0 fail=0
    for name in "${!SOURCES[@]}"; do
        local url="${SOURCES[$name]}"
        local hash=$(echo "$url" | md5sum | cut -d' ' -f1 2>/dev/null || echo "$RANDOM")
        local cache="${WORK_DIR}/cache/${hash}.dat"
        if download_source "$name" "$url" "$cache"; then
            cat "$cache" >> "$TEMP_RAW"; ((ok++))
        else
            ((fail++))
        fi
    done
    echo >&2
    ok "Downloads: $ok OK, $fail failed"
    [ "$ok" -eq 0 ] && { err "All sources failed"; exit 1; }
}

# ============================================================================
# IP 范围合并去重
# ============================================================================
clean_and_merge() {
    local input="$1" output="$2" stats="$3"
    log "Processing and merging IP ranges..."

    local processed="${WORK_DIR}/processed.tmp"
    awk '
    function ip2dec(ip) {
        split(ip, a, "."); return (a[1]*16777216)+(a[2]*65536)+(a[3]*256)+a[4]
    }
    {
        name = "Wael_P2P"; content = $0
        if ($0 ~ /^[A-Za-z0-9_]+:/) { split($0, p, ":"); name = p[1]; content = p[2] }
        if (match(content, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
            split(substr(content, RSTART, RLENGTH), ips, "-")
            s = ip2dec(ips[1]); e = ip2dec(ips[2])
            if (s == 0) name = "Reserved_Local_Network"
            else if (s == 2130706432) name = "Reserved_Loopback"
            else if (s == 2851995648) name = "Reserved_LinkLocal"
            if (s <= e) print name "," s "," e
        } else if (match(content, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/)) {
            split(substr(content, RSTART, RLENGTH), parts, "/")
            s = ip2dec(parts[1]); e = s + (2^(32-parts[2])) - 1
            if (s == 0) name = "Reserved_Local_Network"
            else if (s == 2130706432) name = "Reserved_Loopback"
            else if (s == 2851995648) name = "Reserved_LinkLocal"
            print name "," s "," e
        }
    }' "$input" | sort -t',' -k1,1 -k2,2n > "$processed"

    local range_count=$(wc -l < "$processed")
    log "  Raw ranges extracted: $(format_number $range_count)"

    # 合并相邻/重叠 range → CIDR
    awk -F',' '
    function dec2ip(d) { return sprintf("%d.%d.%d.%d", d/16777216%256, d/65536%256, d/256%256, d%256) }
    NR==1 { n=$1; s=$2; e=$3; next }
    $1==n && $2<=e+1 { if($3>e) e=$3; next }
    { printf "%s %s\n", dec2ip(s), dec2ip(e); n=$1; s=$2; e=$3 }
    END { if(NR>0) printf "%s %s\n", dec2ip(s), dec2ip(e) }
    ' "$processed" | sort -u | python3 -c "
import sys, ipaddress
for line in sys.stdin:
    start, end = line.strip().split()
    for net in ipaddress.summarize_address_range(ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)):
        print(net)
" > "$output"

    local final_count=$(wc -l < "$output")
    local savings=$((range_count - final_count))
    local pct=$((range_count > 0 ? (savings * 100 / range_count) : 0))

    cat > "$stats" <<EOF
Raw ranges extracted: $range_count
Final merged CIDR entries: $final_count
Reduction: $savings entries ($pct%)
EOF

    rm -f "$processed"
    echo "$final_count"
}

# ============================================================================
# 构建流程
# ============================================================================
build() {
    local start=$(date +%s)

    mkdir -p "$WORK_DIR"
    download_sources

    local raw_count=$(wc -l < "$TEMP_RAW")
    log "Total raw lines: $(format_number $raw_count)"

    local temp_clean="${WORK_DIR}/cleaned.tmp"
    cleaned_count=$(clean_and_merge "$TEMP_RAW" "$temp_clean" "$STATS_FILE")

    log "Building final output..."
    > "$OUTPUT_FILE"
    cat > "$OUTPUT_FILE" <<EOF
# Wael P2P Blocklist for PeerBanHelper
# Build: $(date '+%Y-%m-%d %H:%M:%S')
# Sources: Naunter Mega, mxdpeep Comprehensive, eMule Security
# Entries: $cleaned_count
#
# Subscribe in PBH: Settings → Rules → Add Rule → paste raw URL of this file
# Based on: https://github.com/waelisa/Best-blocklist
EOF
    cat "$temp_clean" >> "$OUTPUT_FILE"

    local elapsed=$(($(date +%s) - start))
    ok "Output: $(format_number $cleaned_count) CIDR entries in ${elapsed}s"
    ok "File: ${OUTPUT_FILE}"

    [ -f "$STATS_FILE" ] && echo >&2 && cat "$STATS_FILE" >&2

    rm -f "$TEMP_RAW" "$temp_clean"
    echo >&2
    ok "Done"
}

# ============================================================================
# 入口函数
# ============================================================================
case "${1:-}" in
    -h|--help)
        echo "用法: $0"
        echo "构建 wael.txt（CIDR 格式），供 PeerBanHelper 订阅使用"
        exit 0 ;;
    -c|--clean)
        rm -rf "$WORK_DIR"/*
        echo "Cleaned $WORK_DIR"
        exit 0 ;;
esac

check_deps
build
