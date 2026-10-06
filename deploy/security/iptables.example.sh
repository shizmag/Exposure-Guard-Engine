#!/usr/bin/env bash
# ExposureGuard Reference Egress Firewall Configuration (iptables)
#
# IMPORTANT: This is a reference script. Review and test in a staging environment before applying!
#
# Threat Model:
# Isolates external scanner workloads from internal VPC networks and cloud metadata services.

set -euo pipefail

# Ensure running with administrative permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root or with sudo" >&2
    exit 1
fi

EGRESS_CHAIN="EXPOSUREGUARD_EGRESS"

# Create or flush dedicated egress filtering chain
iptables -N "${EGRESS_CHAIN}" 2>/dev/null || iptables -F "${EGRESS_CHAIN}"

# 1. Allow established and related connections
iptables -A "${EGRESS_CHAIN}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 2. Block Cloud Instance Metadata Service (AWS/GCP/Azure/OpenStack)
iptables -A "${EGRESS_CHAIN}" -d 169.254.169.254/32 -j DROP
iptables -A "${EGRESS_CHAIN}" -d 169.254.0.0/16 -j DROP

# 3. Block RFC 1918 Private IPv4 address ranges
iptables -A "${EGRESS_CHAIN}" -d 10.0.0.0/8 -j DROP
iptables -A "${EGRESS_CHAIN}" -d 172.16.0.0/12 -j DROP
iptables -A "${EGRESS_CHAIN}" -d 192.168.0.0/16 -j DROP

# 4. Block Loopback
iptables -A "${EGRESS_CHAIN}" -d 127.0.0.0/8 -j DROP

# 5. Allow standard outbound DNS queries (UDP and TCP 53)
iptables -A "${EGRESS_CHAIN}" -p udp --dport 53 -j ACCEPT
iptables -A "${EGRESS_CHAIN}" -p tcp --dport 53 -j ACCEPT

# 6. Allow outbound HTTP and HTTPS inspection traffic
iptables -A "${EGRESS_CHAIN}" -p tcp -m multiport --dports 80,443 -j ACCEPT

echo "ExposureGuard reference egress firewall rules configured in chain ${EGRESS_CHAIN}."
