#!/bin/bash
# ============================================================================
# update_firewall.sh — 云厂商 ASN + 邻居网段 + P2P 黑名单
# ASN 数据来源于 RADb whois，P2P 数据聚合自三个上游源
# 基于 Wael Isa 的 Blocklist-builder.sh v1.1.4
# ============================================================================

# ============================================================================
# 配置区
# ============================================================================
ASNS=(
    "14061|DigitalOcean"
    "16509|AWS"
    "15169|Google_Cloud"
    "8075|Azure"
    "20473|Vultr"
    "31898|Oracle"
)

# 修改为 VPS 实际网段，未设置时保持 "-"
# 示例: NEIGHBOR_V4="203.0.113.0/24"  NEIGHBOR_V6="2001:db8::/32"
NEIGHBOR_V4="-"
NEIGHBOR_V6="-"

export PATH="/usr/sbin:/sbin:$PATH"

declare -A P2P_SOURCES=(
    ["Naunter_Mega"]="https://raw.githubusercontent.com/Naunter/BT_BlockLists/master/bt_blocklists.gz"
    ["mxdpeep_Comprehensive"]="https://raw.githubusercontent.com/mxdpeep/p2p-blocklist-creator/master/blocklist.p2p"
    ["eMule_Security"]="http://upd.emule-security.org/ipfilter.zip"
)

# ============================================================================
# 颜色与工具函数
# ============================================================================
if [[ -t 1 ]]; then
    RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
    BLUE='\033[1;34m'; CYAN='\033[1;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi

log() { echo -e "${BLUE}[INFO]${NC}  $1"; }
ok() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err() { echo -e "${RED}[ERR]${NC}   $1"; }
ln() { echo "------------------------------"; }

format_number() {
    echo "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

# ============================================================================
# IPv6 检测
# ============================================================================
check_v6() {
    if [ -f /proc/net/if_inet6 ] && [ "$(wc -l < /proc/net/if_inet6)" -gt 0 ]; then
        command -v ip6tables &>/dev/null && echo 1 || echo 0
    else
        echo 0
    fi
}

# ============================================================================
# 依赖检查
# ============================================================================
check_deps() {
    local missing=()
    for cmd in curl gunzip awk python3 ipset iptables whois; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        err "Missing: ${missing[*]}"
        err "Run: apt install -y curl gzip awk python3 ipset iptables iproute2 whois"
        exit 1
    fi
    ok "All dependencies found"
}

# ============================================================================
# P2P 下载
# ============================================================================
download_p2p_source() {
    local name="$1" url="$2" out="$3"
    echo -ne "\r  ${BLUE}▶${NC} $name... "
    if curl -sL --connect-timeout 15 --max-time 60 --retry 3 --retry-delay 2 "$url" -o "$out"; then
        if file "$out" | grep -q "gzip compressed"; then
            local tmp="${out}.gz"; mv "$out" "$tmp"
            gunzip -c "$tmp" > "$out" 2>/dev/null; rm -f "$tmp"
            echo -e "\r  ${GREEN}✓${NC} $name (gzip)"
        elif file "$out" | grep -q "Zip archive"; then
            local tmp="${out}.zip"; mv "$out" "$tmp"
            unzip -p "$tmp" > "$out" 2>/dev/null; rm -f "$tmp"
            echo -e "\r  ${GREEN}✓${NC} $name (zip)"
        else
            echo -e "\r  ${GREEN}✓${NC} $name"
        fi
        [ -s "$out" ] && return 0
    fi
    echo -e "\r  ${RED}✗${NC} $name"
    return 1
}

fetch_p2p_blocklist() {
    local work_dir="/tmp/pbh-work"
    local raw="${work_dir}/raw.tmp"
    local cidr_out="${work_dir}/cidr.tmp"

    mkdir -p "${work_dir}/cache"
    > "$raw"

    local ok=0 fail=0
    for name in "${!P2P_SOURCES[@]}"; do
        local url="${P2P_SOURCES[$name]}"
        local cache="${work_dir}/cache/$(echo "$url" | md5sum | cut -d' ' -f1).dat"
        if download_p2p_source "$name" "$url" "$cache"; then
            cat "$cache" >> "$raw"; ((ok++))
        else
            ((fail++))
        fi
    done

    if [ "$ok" -eq 0 ]; then
        err "All P2P sources failed, skipping P2P blocklist"
        rm -rf "$work_dir"
        return 1
    fi

    log "P2P raw lines: $(format_number $(wc -l < "$raw")) | $ok OK, $fail failed"

    local processed="${work_dir}/processed.tmp"

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
            if (s <= e) print name "," s "," e
        } else if (match(content, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/)) {
            split(substr(content, RSTART, RLENGTH), parts, "/")
            s = ip2dec(parts[1]); e = s + (2^(32-parts[2])) - 1
            print name "," s "," e
        }
    }' "$raw" | sort -t',' -k1,1 -k2,2n > "$processed"

    local range_count=$(wc -l < "$processed")

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
" > "$cidr_out"

    local final_count=$(wc -l < "$cidr_out")
    local savings=$((range_count - final_count))
    local pct=$((range_count > 0 ? (savings * 100 / range_count) : 0))

    log "P2P merged: $(format_number $final_count) CIDR entries ($pct% reduction)"

    # 批量加载到 ipset
    local loaded=$(wc -l < "$cidr_out")
    {
        echo "create bad_p2p_v4 hash:net family inet hashsize 65536 maxelem 1000000"
        awk '{print "add bad_p2p_v4 " $0}' "$cidr_out"
    } | ipset restore -exist 2>/dev/null

    ok "P2P loaded: $(format_number $loaded) CIDR entries into bad_p2p_v4"

    rm -rf "$work_dir"
    return 0
}

# ============================================================================
# ASN 黑名单更新
# ============================================================================
update_asn() {
    log "Fetching ASN route data..."

    local v4_add="/tmp/asn_v4_add.txt"
    local v6_add="/tmp/asn_v6_add.txt"
    true > "$v4_add"
    [ "$HAS_V6" = "1" ] && true > "$v6_add"

    for ITEM in "${ASNS[@]}"; do
        ASN="${ITEM%%|*}"
        NAME="${ITEM##*|}"

        timeout 15 whois -h whois.radb.net -- "-i origin AS$ASN" > /tmp/whois_$ASN.txt 2>/dev/null

        local V4=$(awk '/^route:/ {print $2}' /tmp/whois_$ASN.txt)
        echo "$V4" | while IFS= read -r ip; do
            [ -n "$ip" ] && echo "add bad_asn_v4 $ip"
        done >> "$v4_add"

        if [ "$HAS_V6" = "1" ]; then
            local V6=$(awk '/^route6:/ {print $2}' /tmp/whois_$ASN.txt)
            echo "$V6" | while IFS= read -r ip; do
                [ -n "$ip" ] && echo "add bad_asn_v6 $ip"
            done >> "$v6_add"
        fi

        V4_C=$(echo "$V4" | grep -c .)
        V6_C=$(echo "$V6" | grep -c .)
        log "  AS${ASN} ${NAME}: v4 ${V4_C} 段${HAS_V6:+, v6 ${V6_C} 段}"
    done

    rm -f /tmp/whois_*.txt

    # 批量加载 v4
    local total=$(wc -l < "$v4_add")
    if [ "$total" -gt 100 ]; then
        ipset flush bad_asn_v4 2>/dev/null
        ipset restore < "$v4_add" 2>/dev/null
        ok "ASN v4 loaded ($(format_number $total) entries)"
    else
        warn "ASN v4 too few ($total), skipping"
    fi

    # 批量加载 v6
    if [ "$HAS_V6" = "1" ]; then
        local total6=$(wc -l < "$v6_add")
        if [ "$total6" -gt 100 ]; then
            ipset flush bad_asn_v6 2>/dev/null
            ipset restore < "$v6_add" 2>/dev/null
            ok "ASN v6 loaded ($(format_number $total6) entries)"
        else
            warn "ASN v6 too few ($total6), skipping"
        fi
    fi

    rm -f "$v4_add" "$v6_add"
}

# ============================================================================
# iptables 规则部署
# ============================================================================
deploy_rules() {
    log "Deploying iptables rules..."

    # IPv4
    iptables -P INPUT ACCEPT
    iptables -F INPUT

    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    if [ "$NEIGHBOR_V4" != "-" ]; then
        iptables -A INPUT -p tcp --dport 443 -s "$NEIGHBOR_V4" -j DROP
        ok "Neighbor v4 blocked: $NEIGHBOR_V4"
    fi

    iptables -A INPUT -p tcp --dport 443 -m set --match-set bad_asn_v4 src -j DROP 2>/dev/null
    iptables -A INPUT -p tcp --dport 443 -m set --match-set bad_p2p_v4 src -j DROP 2>/dev/null
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    ok "IPv4 rules applied"

    # IPv6
    if [ "$HAS_V6" = "1" ]; then
        ip6tables -P INPUT ACCEPT
        ip6tables -F INPUT

        ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT

        if [ "$NEIGHBOR_V6" != "-" ]; then
            ip6tables -A INPUT -p tcp --dport 443 -s "$NEIGHBOR_V6" -j DROP
            ok "Neighbor v6 blocked: $NEIGHBOR_V6"
        fi

        ip6tables -A INPUT -p tcp --dport 443 -m set --match-set bad_asn_v6 src -j DROP 2>/dev/null
        ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
        ok "IPv6 rules applied"
    fi
}

# ============================================================================
# 规则持久化
# ============================================================================
persist() {
    mkdir -p /etc/iptables
    ipset save > /etc/iptables/ipsets 2>/dev/null
    iptables-save > /etc/iptables/rules.v4
    [ "$HAS_V6" = "1" ] && ip6tables-save > /etc/iptables/rules.v6
    ok "Rules persisted"
}

# ============================================================================
# 初始化 ipset
# ============================================================================
init_sets() {
    ipset create bad_asn_v4 hash:net family inet hashsize 4096 maxelem 500000 2>/dev/null
    [ "$HAS_V6" = "1" ] && ipset create bad_asn_v6 hash:net family inet6 hashsize 4096 maxelem 500000 2>/dev/null
    ipset create bad_p2p_v4 hash:net family inet hashsize 65536 maxelem 1000000 2>/dev/null
}

# ============================================================================
# 统计摘要
# ============================================================================
print_summary() {
    echo ""
    ln
    local asn_v4=$(ipset list bad_asn_v4 2>/dev/null | grep -c "^[0-9]")
    local p2p=$(ipset list bad_p2p_v4 2>/dev/null | grep -c "^[0-9]")

    echo "  ASN v4:     $(format_number $asn_v4) 条"
    echo "  P2P v4:     $(format_number $p2p) 条"
    echo "  Total v4:   $(format_number $((asn_v4 + p2p))) 条"
    if [ "$HAS_V6" = "1" ]; then
        local asn_v6=$(ipset list bad_asn_v6 2>/dev/null | grep -c "^[0-9a-f]")
        echo "  ASN v6:     $(format_number $asn_v6) 条"
    fi
    ln
}

# ============================================================================
# 主流程
# ============================================================================
main() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════${NC}"
    echo -e "${GREEN}  防火墙规则更新${NC}"
    echo -e "${CYAN}══════════════════════════════════════${NC}"
    echo ""

    HAS_V6=$(check_v6)
    [ "$HAS_V6" = "1" ] && ok "IPv6 detected" || warn "No IPv6, skipping v6 rules"
    check_deps
    init_sets

    echo ""
    ln
    echo -e "${GREEN}  ASN 黑名单${NC}"
    ln
    update_asn

    echo ""
    ln
    echo -e "${GREEN}  P2P 黑名单${NC}"
    ln
    fetch_p2p_blocklist

    echo ""
    ln
    echo -e "${GREEN}  部署规则${NC}"
    ln
    deploy_rules
    persist
    print_summary

    echo ""
    echo -e "${GREEN}Done.${NC}"
    echo ""
}

main "$@"
