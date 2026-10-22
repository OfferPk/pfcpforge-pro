# PFCPForge Pro v1.0.0 — Architecture & Engineering Manual

## 1\. Executive Summary: The Disaggregated 5G Core & 4G CUPS Dataplane

In 3GPP Release 14 (Control and User Plane Separation \- CUPS for 4G EPC) and 3GPP Release 15/16/17 (5G Standalone Core), the legacy monolithic architecture was split:

- **Control Plane Functions**: Session Management Function (**SMF**) in 5G, or PGW-C / SGW-C in 4G CUPS.  
- **User Plane Functions**: User Plane Function (**UPF**) in 5G, or PGW-U / SGW-U in 4G CUPS.

Connecting the control plane to the high-throughput user plane is the **N4 Interface** (in 5G) and **Sx Interface** (in 4G CUPS), which exclusively standardizes **PFCP (Packet Forwarding Control Protocol \- 3GPP TS 29.244)** over UDP port 8805\.

\+------------------------------------------------------------------+

| Version (3b=1) | Spare (2b) | FO (1b) | MP (1b) | S-bit (1b)     |

\+------------------------------------------------------------------+

|                    Message Type (8 bits)                         |

\+------------------------------------------------------------------+

|                    Message Length (16 bits)                      |

\+------------------------------------------------------------------+

|       Session Endpoint Identifier (SEID, 64 bits \- if S=1)       |

\+------------------------------------------------------------------+

|         Sequence Number (24 bits)        |     Spare (8 bits)    |

\+------------------------------------------------------------------+

|       Information Elements (IEs: Type 16b, Length 16b, Value)    |

\+------------------------------------------------------------------+

---

## 2\. The 4 Fundamental Rule Engines of PFCP

Every subscriber PDU Session established in the 5G UPF is governed by four interrelated tables installed dynamically by the SMF over N4:

### 2.1 Packet Detection Rule (PDR \- IE Type 56\)

Matches incoming packets against classification criteria defined in the **PDI (Packet Detection Information)**:

- **Source Interface**: Access (1), Core (2), SGi-LAN (3), or CP-function (4).  
- **Local F-TEID**: Fully Qualified Tunnel Endpoint Identifier allocated by the UPF for GTP-U encapsulation.  
- **Network Instance**: Data Network Name (DNN, e.g. `internet` or `ims`).  
- **UE IP Address**: Allocated IPv4 or IPv6 prefix.  
- **SDF Filter**: 5-tuple IP filter (protocol, source IP, source port, dest IP, dest port).  
- **Precedence**: Determines the exact evaluation order when multiple PDRs match.  
- **Outer Header Removal**: Strips outer GTP-U / UDP / IP headers from incoming uplink packets.

### 2.2 Forwarding Action Rule (FAR \- IE Type 108\)

Dictates what the UPF does once a packet matches a PDR:

- **Apply Action**: Bitmask containing `DROP` (0x01), `FORW` (0x02), `BUFF` (0x04), `NOCP` (0x08 \- Notify Control Plane), or `DUPL` (0x10 \- Duplicate for Lawful Interception).  
- **Forwarding Parameters**: Destination Interface (Access / Core / SGi-LAN), Network Instance, and **Outer Header Creation** (encapsulating GTP-U header with remote gNodeB TEID and IP).

### 2.3 QoS Enforcement Rule (QER \- IE Type 109\)

Enforces flow-level quality of service:

- **QFI (QoS Flow Identifier)**: Maps traffic to 5G 5QI classes (e.g. 5QI 1 for VoNR conversational voice, 5QI 9 for default internet).  
- **MBR (Maximum Bit Rate)**: Enforces token-bucket rate limits for uplink and downlink.  
- **GBR (Guaranteed Bit Rate)**: Reserves bandwidth for mission-critical bearers.  
- **Gate Status**: Allows dynamic opening or closing of uplink/downlink flow gates.

### 2.4 Usage Reporting Rule (URR \- IE Type 81\)

Collects billing and telemetry metrics:

- **Measurement Method**: Volume (bytes), Duration (time), or Event count.  
- **Reporting Triggers**: Periodic intervals, Volume Thresholds, Quota Exhaustion (for online charging with CHF / OCS), or PDU Session Termination.

---

## 3\. Operational Headaches & Vulnerabilities in 5G N4

1. **Downlink Buffering RAM Exhaustion (Paging Storms)**:  
   - When a 5G UE transitions to RRC-IDLE state, the UPF cannot immediately forward downlink packets. Instead, it must buffer them (`BUFF=1`) and send a Downlink Data Report (`NOCP=1`) to trigger SMF/AMF paging.  
   - If an attacker sends rapid bursts to millions of idle IoT or handset IPs, unconstrained UPF buffering consumes gigabytes of memory, triggering Linux kernel OOM killer panics on the DPDK dataplane.  
2. **Plaintext Control Plane Hijacking**:  
   - Because PFCP runs on UDP port 8805, unencrypted N4 links allow transport-layer eavesdroppers to inject forged `PFCP Session Modification Requests`, modifying FAR rules to redirect subscriber traffic to rogue GTP-U tunnel endpoints.  
3. **PDR Precedence Conflicts**:  
   - Overlapping PDR match criteria with identical precedence values lead to non-deterministic routing in high-speed hardware match engines.  
4. **F-SEID Collisions**:  
   - Unsynchronized or sequential 64-bit SEID allocations across distributed SMF clusters risk session context overwrites and billing leakage.

---

## 4\. 10-Point Zero-Trust 5G N4 / CUPS Security Rubric

1. **N4 Cryptographic Transport Encryption (TS 33.501) (12 pts)**: IPsec IKEv2 ESP or WireGuard tunnel on UDP 8805\.  
2. **F-SEID 64-Bit State Machine & Collision Isolation (12 pts)**: Cryptographically randomized 64-bit SEID with IP binding.  
3. **PDR Precedence Disambiguation & Overlap Filtering (10 pts)**: Strict hierarchy (Emergency \< IMS \< App \< Default).  
4. **Downlink Data Buffering & OOM Protection (10 pts)**: Explicit packet caps (\$\\le 50\\text{ pkts}\$) and timeout (\$\\le 5\\text{s}\$).  
5. **QER 5QI/QFI Bandwidth & Gate Enforcement (10 pts)**: Hardware token-bucket policing for MBR/GBR.  
6. **N4 Association Heartbeat & Recovery Timestamp (10 pts)**: 5–10s heartbeat with recovery timestamp resync.  
7. **URR Charging Telemetry & Quota Enforcement (10 pts)**: Multi-trigger volume/quota accounting.  
8. **Ingress PDI Interface Anti-IP Spoofing (9 pts)**: Verification that Access PDR matches allocated UE IP subnet.  
9. **SMF/UPF N4 Redundancy & Load-Balancing (9 pts)**: Multi-UPF pooling with dynamic weight-based steering.  
10. **Control Plane Policing (CoPP) for UDP 8805 (8 pts)**: Hardware rate-limiting against control-plane DDoS.