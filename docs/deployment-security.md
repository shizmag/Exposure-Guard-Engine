# ExposureGuard Deployment & Egress Security Specification

## 1. Threat Boundary & Network Architecture

ExposureGuard Engine executes outside-in security scans against untrusted, potentially adversarial targets. This document defines the exact network threat model and production requirements for deploying the engine standalone or as an ExposureGuard Cloud worker.

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Worker Host (Cloud VM / Bare Metal)                                   │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ExposureGuard Worker Container                                   │  │
│  │                                                                  │  │
│  │   ┌─────────────────────┐       ┌────────────────────────────┐   │  │
│  │   │ Native Go Engine    │       │ External Subprocesses      │   │  │
│  │   │ (DNS/TLS/HTTP/JS)   │       │ (httpx, katana, nuclei)    │   │  │
│  │   └──────────┬──────────┘       └─────────────┬──────────────┘   │  │
│  │              │                                │                  │  │
│  │              ▼                                ▼                  │  │
│  │     netguard.SafeDialer                OS Socket Layer           │  │
│  │    (blocks private/metadata)     (BYPASSES Go netguard!)         │  │
│  │              │                                │                  │  │
│  │              └───────────────┬────────────────┘                  │  │
│  │                              ▼                                   │  │
│  │                     Container eth0 (veth)                        │  │
│  └──────────────────────────────┬───────────────────────────────────┘  │
│                                 ▼                                      │
│                  Linux Host Network Namespace Filter                    │
│            [iptables / nftables egress enforcement]                    │
│                 │                                   │                  │
│                 ▼                                   ▼                  │
│          DROP: RFC1918                       ALLOW: Public Internet    │
│          DROP: 169.254.0.0/16                       (80, 443)          │
│          DROP: Loopback / CGNAT                                        │
│          DROP: Link-Local IPv6                                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The External Process Network Reality

A critical finding of our security audit is that **Go-level network guards cannot protect subprocesses**:

1. **Native Engine**: The native Go code strictly routes HTTP connections through `pkg/netguard.SafeDialer`. Every resolved IP is validated against `DefaultNetworkPolicy`, and connections are dialed directly to the validated IP literal to prevent DNS rebinding.
2. **External Subprocesses**: Tools like `httpx`, `katana`, and `nuclei` run as separate OS child processes (`os/exec`). They initialize their own Go `net.Dialer` and DNS resolvers. **They do not route traffic through ExposureGuard's `SafeDialer`.**
3. **Docker Default Network**: In default Docker bridge networking, outbound packets are routed through the Docker bridge gateway and forwarded via the host's default route. Standard Docker configurations **do not** drop traffic to link-local addresses (`169.254.0.0/16`) or RFC1918 private subnets.

> **Warning**: A standalone Docker container running `--mode owned` with external tools CANNOT guarantee cloud metadata isolation on its own. Network-level egress firewall rules are MANDATORY in production.

---

## 3. Mandatory Cloud Deployment Requirements

Before connecting ExposureGuard Engine workers to ExposureGuard Cloud, operators and infrastructure automation MUST implement three defense layers:

### Layer 1: Cloud Provider IMDSv2 Hop-Limit (Infrastructure)
On AWS EC2, GCP, and Azure, configure instance metadata service to enforce IMDSv2 and set the IP packet hop limit to 1. This prevents container bridge networks (which decrement TTL by 1) from reaching instance metadata:

```bash
# AWS CLI example: Enforce IMDSv2 with hop limit = 1
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxxxxxxxxxxxxxxxx \
    --http-tokens required \
    --http-put-response-hop-limit 1 \
    --http-endpoint enabled
```

### Layer 2: Container Egress Firewall (Host Network)
Production worker hosts must enforce egress filtering for all worker container network interfaces (`br-exposureguard` or `docker0`).

#### Reference `nftables` Configuration (`/etc/nftables/exposureguard.nft`):
```nftables
table inet exposureguard_filter {
    chain egress_filter {
        type filter hook forward priority 0; policy drop;

        # Allow established and related connections
        ct state established,related accept

        # Drop link-local and cloud metadata (IPv4 & IPv6)
        ip daddr 169.254.0.0/16 drop
        ip6 daddr fe80::/10 drop

        # Drop RFC1918 private subnets
        ip daddr 10.0.0.0/8 drop
        ip daddr 172.16.0.0/12 drop
        ip daddr 192.168.0.0/16 drop
        ip6 daddr fc00::/7 drop

        # Drop CGNAT and loopback
        ip daddr 100.64.0.0/10 drop
        ip daddr 127.0.0.0/8 drop
        ip6 daddr ::1/128 drop

        # Allow outbound DNS to trusted recursor only (e.g. 1.1.1.1, 8.8.8.8)
        udp dport 53 ip daddr { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4 } accept
        tcp dport 53 ip daddr { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4 } accept

        # Allow public outbound HTTP/HTTPS
        tcp dport { 80, 443 } accept
    }
}
```

#### Equivalent `iptables` Commands:
```bash
# Create dedicated egress isolation chain
iptables -N EXPOSUREGUARD_EGRESS

# Block Cloud Metadata
iptables -A EXPOSUREGUARD_EGRESS -d 169.254.0.0/16 -j DROP

# Block RFC1918 Private Ranges
iptables -A EXPOSUREGUARD_EGRESS -d 10.0.0.0/8 -j DROP
iptables -A EXPOSUREGUARD_EGRESS -d 172.16.0.0/12 -j DROP
iptables -A EXPOSUREGUARD_EGRESS -d 192.168.0.0/16 -j DROP

# Block CGNAT and Loopback
iptables -A EXPOSUREGUARD_EGRESS -d 100.64.0.0/10 -j DROP
iptables -A EXPOSUREGUARD_EGRESS -d 127.0.0.0/8 -j DROP

# Allow established/related traffic
iptables -A EXPOSUREGUARD_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow public web traffic
iptables -A EXPOSUREGUARD_EGRESS -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A EXPOSUREGUARD_EGRESS -p udp --dport 53 -j ACCEPT

# Default policy: drop anything else
iptables -A EXPOSUREGUARD_EGRESS -j DROP

# Apply chain to docker bridge interface
iptables -I FORWARD -i docker0 -j EXPOSUREGUARD_EGRESS
```

### Layer 3: Unprivileged Execution & Resource Constraints
The engine worker container must run with non-root user and dropped capabilities:
```bash
docker run --rm \
    --cap-drop=ALL \
    --read-only \
    --tmpfs /tmp/exposureguard:rw,noexec,nosuid,size=256m \
    --memory=2g \
    --cpus=2.0 \
    --pids-limit=100 \
    --security-opt=no-new-privileges:true \
    ghcr.io/exposureguard/exposureguard:<VERSION> \
    scan https://example.com --format jsonl
```

---

## 4. Controlled Testing with `--allow-private`

For controlled local tests, developer workstations, and test fixtures:
* Passing `--allow-private` or setting `EXPOSUREGUARD_ALLOW_PRIVATE=1` allows scanning loopback (`127.0.0.1`, `localhost`) and private RFC1918 addresses.
* **Cloud metadata (`169.254.0.0/16`, `metadata.google.internal`, `instance-data`) remains strictly blocked even when `--allow-private` is active.**
