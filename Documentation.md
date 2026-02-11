# Packet Phantom v2.0.0 – Complete Documentation

**Professional-Grade Behavioral OS Fingerprinting & Network Testing Framework**

**Version:** 2.0.0  
**Author:** medaminkh-dev (Amine)  
**Last Updated:** February 2026

---

## Table of Contents

1. [Welcome](#welcome)
2. [Core Philosophy](#core-philosophy)
3. [Understanding OS Fingerprinting](#understanding-os-fingerprinting)
4. [The 9 Dimensions of Behavioral Analysis](#the-9-dimensions-of-behavioral-analysis)
5. [Signature Database v2: Architecture & Future](#signature-database-v2-architecture--future)
6. [Complete Usage Guide](#complete-usage-guide)
7. [Advanced Usage](#advanced-usage)
8. [API Reference](#api-reference)
9. [For Researchers & Academics](#for-researchers--academics)
10. [Troubleshooting](#troubleshooting)

---

## Welcome

Thank you for choosing Packet Phantom for your network reconnaissance and OS fingerprinting needs. This document provides comprehensive guidance for using, understanding, and extending this powerful tool.

### What is Packet Phantom?

Packet Phantom is a next-generation network reconnaissance framework that identifies operating systems through **behavioral analysis** rather than relying solely on signature databases. It sends carefully crafted network probes to targets and analyzes their responses across multiple dimensions—how they handle network stacks, timing characteristics, error conditions, and more.

### Why Behavioral Analysis?

Traditional port scanners like Nmap use primarily static signatures—"if window size is 65535, it's probably Windows." This approach is:
- ❌ Brittle – breaks when OS updates change behaviors
- ❌ Evadable – can be spoofed by sophisticated attackers
- ❌ Limited – can't fingerprint custom or embedded systems
- ❌ Outdated – signatures lag behind actual OS releases

Packet Phantom's behavioral approach is:
- ✅ Adaptive – understands *why* systems behave certain ways
- ✅ Harder to spoof – analyzes multiple correlated signals
- ✅ Extensible – new systems just need behavior patterns
- ✅ Current – adapts as OS implementations evolve

### Who Should Use This?

**Security Researchers** – Study TCP/IP stack implementations and OS-specific behaviors  
**Penetration Testers** – Comprehensive network reconnaissance before engagements  
**Network Administrators** – Asset inventory, rogue device detection, baseline establishment  
**Educators** – Teaching network protocols, socket programming, security fundamentals  
**Bug Bounty Hunters** – Deep network analysis for vulnerability research  

### Educational First, Powerful When Authorized

Packet Phantom defaults to **Educational Mode** (`--edu`), which enforces safe testing parameters:
- Rate limit: 100 packets/second (safe for local networks)
- Memory limit: 200MB
- Timeout values: conservative
- Perfect for learning and lab environments

For authorized testing, **Live Mode** (`--live`) unlocks the full power:
- Rate limit: 10,000 packets/second
- No artificial restrictions
- Designed for professional penetration testing
- Requires explicit opt-in with warnings

---

## Core Philosophy

### Three Principles

#### 1. **Transparency**
Every fingerprint includes a confidence score with a veto system. If multiple dimensions disagree about the OS, the tool clearly indicates uncertainty rather than guessing. This builds trust and prevents false positives.

#### 2. **Behavioral Analysis Over Database Lookup**
The tool doesn't ask "is this string in my database?" Instead it asks "does this system's behavior match the expected patterns?" This is more accurate and future-proof.

#### 3. **Community-Driven Signatures**
Individual JSON files, one per OS, enable community contributions. Anyone can add a signature without needing to understand the entire codebase. The planned CDN model means contributions benefit all users globally.

### Design Philosophy

```
┌─────────────────────────────────────────┐
│  Operating System Under Fingerprinting  │
│  (Windows Server 2022, Linux 5.15, etc) │
└────────────────┬────────────────────────┘
                 │
        ┌────────┴────────┐
        │  Send Probes    │
        │  Via Network    │
        └────────┬────────┘
                 │
        ┌────────▼──────────────────┐
        │  Receive Responses &      │
        │  Analyze 9 Dimensions     │
        │  • TCP signatures         │
        │  • IP behaviors           │
        │  • Timing patterns        │
        │  • Error responses        │
        │  • State machine          │
        │  • And 4 more...          │
        └────────┬──────────────────┘
                 │
        ┌────────▼──────────────┐
        │  Multi-Dimensional    │
        │  Confidence Scoring   │
        │  (with Veto System)   │
        └────────┬──────────────┘
                 │
        ┌────────▼──────────────┐
        │  Fingerprint Result   │
        │  OS: Linux 5.x        │
        │  Confidence: 0.94     │
        │  Details: ...         │
        └───────────────────────┘
```

---

## Understanding OS Fingerprinting

### What Gets Fingerprinted?

Packet Phantom can identify:

| Level | What's Identified | Examples |
|-------|------------------|----------|
| **OS Family** | Operating system type | Linux, Windows, macOS, Cisco, etc. |
| **Major Version** | Major release number | Windows 10 vs 11, Ubuntu 20 vs 22 |
| **Environment** | Physical or virtualized | VMware VM, AWS EC2, Docker container |
| **Device Type** | General role or purpose | Server, workstation, router, firewall |
| **Cloud Provider** | If applicable | AWS, Azure, Google Cloud, etc. |
| **Hardware Class** | General hardware type | Bare metal, hypervisor VM, container |
| **Services** | Open ports and services | Web server, SSH, database, etc. |

### What Can't Be Fingerprinted

Limitations are important to understand:

| Aspect | Status | Why |
|--------|--------|-----|
| **Exact patch level** | ❌ Limited | Too many combinations, frequent patches |
| **Specific application versions** | ❌ Limited | Application runs on OS, not part of OS |
| **User identity/credentials** | ❌ No | Fingerprinting doesn't read files |
| **System content** | ❌ No | Not connected to filesystem |
| **Behind sophisticated WAF/LB** | ⚠️ Unreliable | Appliance signature obscures true OS |
| **Spoofed systems** | ⚠️ Detectable | Behavioral analysis catches inconsistencies |

### Accuracy Expectations

Under ideal conditions (direct network access, no filtering):

| Scenario | Expected Accuracy |
|----------|-------------------|
| **Common OS on dedicated host** | 95%+ |
| **Common OS on standard cloud** | 85-90% |
| **Unusual/custom systems** | 70-85% |
| **Behind WAF/Load Balancer** | 60-75% |
| **Heavily firewalled network** | 50-70% |
| **Unknown/exotic OS** | 30-50% (best guess) |

---

## The 9 Dimensions of Behavioral Analysis

Packet Phantom's fingerprinting engine analyzes operating system behavior across **nine independent dimensions**. Each dimension provides signals that, when combined, create a highly accurate fingerprint.

### Dimension 1: Static TCP Signatures

**What it measures:** TCP header field values and options in responses.

**Why it matters:** Operating systems have different default configurations:
- **Window Size** – Linux often uses 64KB, Windows uses 65535
- **TCP Options** – MSS, Window Scaling, SACK, Timestamps vary
- **Initial Sequence Number (ISN)** – Randomization strategy differs
- **DF Bit (Don't Fragment)** – Set by default in some OS, not others

**Example Analysis:**
```
Probe: Send TCP SYN to port 80

Response From Linux System:
├─ Window: 64240
├─ MSS: 1460
├─ WScale: 7
├─ SACK: permitted
└─ Timestamp: present

Response From Windows System:
├─ Window: 65535
├─ MSS: 1460
├─ WScale: 8
├─ SACK: permitted
└─ Timestamp: present

Signal: Linux and Windows differ in window size and wscale.
```

**Confidence Contribution:** 20% (strong signal, but can be spoofed with kernel tweaking)

---

### Dimension 2: IP Layer Behavior

**What it measures:** How systems handle IP-layer behaviors and options.

**Why it matters:**
- **TTL (Time To Live)** – Linux starts at 64, Windows at 128, Cisco at 255
- **IP ID Sequencing** – Random, incremental, or zero-filled patterns
- **Fragmentation Handling** – How large packets are split
- **IP Options** – Loose source routing, record route, etc.

**Example Analysis:**
```
Multiple Probes Track IP Behavior:

Probe 1 Response: TTL=64
Probe 2 Response: TTL=63 (decremented as expected)
Probe 3 Response: TTL=62 (consistent pattern)

IP ID Sequence: 12345 → 12346 → 12347 (incremental)
OR
IP ID Sequence: 48291 → 5821 → 39402 (random)

Analysis:
• TTL=64 suggests Linux default
• Incremental IP ID suggests older Linux or specific config
• Random IP ID suggests modern system with good randomness
```

**Confidence Contribution:** 15% (moderately strong, TTL can be spoofed)

---

### Dimension 3: Temporal Dynamics

**What it measures:** How quickly and consistently systems respond.

**Why it matters:** Kernel scheduling and interrupt handling differ:
- **Response Time** – Time from probe sent to response received
- **Jitter** – Variation in response times across multiple probes
- **Clock Skew** – System's clock behavior under test
- **Scheduling Pattern** – Whether responses bunch or spread randomly

**Example Analysis:**
```
Send 10 identical probes to same port:

Linux System Response Times:
[2.3ms, 2.1ms, 2.4ms, 2.2ms, 2.3ms, 2.1ms, ...]
└─ Consistent (avg: 2.25ms, jitter: ±0.15ms)
└─ Signal: Efficient kernel scheduling

Windows System Response Times:
[5.2ms, 5.8ms, 4.9ms, 6.1ms, 5.3ms, 5.7ms, ...]
└─ Variable (avg: 5.5ms, jitter: ±0.55ms)
└─ Signal: Different interrupt handling

Embedded System Response Times:
[45ms, 48ms, 43ms, 47ms, 46ms, 44ms, ...]
└─ Slow but consistent (avg: 45.5ms, jitter: ±2ms)
└─ Signal: Limited processing power or different OS class
```

**Confidence Contribution:** 10% (weaker signal due to network variability)

---

### Dimension 4: Congestion Response

**What it measures:** How systems implement TCP congestion control algorithms.

**Why it matters:** Different OS use different algorithms:
- **Reno** – Classic algorithm, many older systems
- **CUBIC** – Linux modern default
- **BBR** – High-performance algorithm, newer systems
- **Vegas** – Window-based algorithm, some embedded systems

**Example Analysis:**
```
Send multiple packets with SYN flag set to same port:

System A Response Pattern:
├─ Accepts window size: 65535
├─ Handles repeated ACKs correctly
├─ Slowly increases window on subsequent probes
└─ Signal: Likely CUBIC congestion control (Linux modern)

System B Response Pattern:
├─ Accepts window size: 65535
├─ Window drops when duplicate data received
├─ Multiplicative decrease detected
└─ Signal: Likely Reno or NewReno algorithm

System C Response Pattern:
├─ Window size: 32768 (conservative)
├─ Responds consistently regardless of probe rate
└─ Signal: Likely VEGAS algorithm (unique timing-based approach)
```

**Confidence Contribution:** 12% (specialized signal)

---

### Dimension 5: Error Handling

**What it measures:** Responses to invalid, malformed, or RFC-violating packets.

**Why it matters:** OS differ in how strictly they enforce RFC standards:
- **Invalid TCP Flags** – What does system do with FIN+RST+SYN?
- **Out-of-Spec Values** – Window size 0? Port number 0?
- **Malformed IP Headers** – Bad checksum or invalid options
- **Protocol Violations** – Contradictory flags or states

**Example Analysis:**
```
Probe: Send packet with flags FIN+SYN+RST (all set)

Linux Response (Modern):
├─ Drops packet silently (ignores invalid flag combo)
└─ No response sent

Windows Response:
├─ Sends RST in response (attempts to reset)
└─ Signal: Stricter flag validation

BSD Response:
├─ May respond based on some flags (implementation-specific)
└─ Signal: Different RFC interpretation

Network Appliance Response:
├─ Sends ICMP error or blocks silently
└─ Signal: Security filter/WAF in front of true OS
```

**Confidence Contribution:** 8% (can indicate filtering, not just OS)

---

### Dimension 6: State Machine Behavior

**What it measures:** How systems manage TCP connection states.

**Why it matters:**
- **TCP Sequence Numbering** – Randomization quality and predictability
- **State Transitions** – How fast can connection go from SYN_RECV to ESTABLISHED?
- **TIME_WAIT Handling** – How long does system hold closed connections?
- **Out-of-Order Packet Handling** – Can system reassemble jumbled packets?

**Example Analysis:**
```
Track Connection Through States:

Test 1: Initial SYN
├─ Linux: ISN random, cryptographic quality ✓
├─ Old System: ISN sequential or predictable ✗

Test 2: Multiple SYN retransmits
├─ Linux: Backoff 1s → 3s → 9s
├─ Windows: Backoff 1s → 3s → 6s
├─ Embedded: Different backoff strategy

Test 3: TIME_WAIT state
├─ Check: Can new connection use same port?
├─ Linux: TIME_WAIT typically 60s
├─ Windows: TIME_WAIT typically 240s
└─ Signal: OS-specific TIME_WAIT duration
```

**Confidence Contribution:** 14% (strong signal, timing-dependent)

---

### Dimension 7: Side-Channel Leakage

**What it measures:** Subtle information leaks through timing, CPU cache effects, or other side-channels.

**Why it matters:** Even when systems try to respond identically, tiny timing differences reveal information:
- **Cache Timing** – How long operations take based on CPU cache state
- **Clock Skew** – Does system's clock drift at a rate that indicates hardware?
- **Interrupt Latency** – Time to handle network interrupt indicates CPU type
- **Cryptographic Timing** – Time-based attacks on HTTPS handshakes

**Example Analysis:**
```
Measure precise response times (in microseconds):

Intel i7 CPU (typical timing):
├─ Cache hit: ~50ns
├─ Cache miss: ~200ns
└─ Variance in response timing reveals cache behavior

ARM Processor (different characteristics):
├─ Cache hit: ~30ns
├─ Cache miss: ~150ns
└─ Different variance pattern

Virtual Machine:
├─ Timing highly variable (hypervisor scheduling)
├─ Jitter in 1-5ms range
└─ Signal: Likely virtualized
```

**Confidence Contribution:** 7% (advanced, noisy signal)

---

### Dimension 8: Hardware Artifacts

**What it measures:** Physical vs. virtual machine detection, hypervisor fingerprinting.

**Why it matters:** Reveals whether system is:
- Bare metal (real hardware)
- Virtualized (VMware, Hyper-V, KVM, Xen)
- Containerized (Docker, Kubernetes)
- Cloud-hosted (AWS, Azure, GCP)

**Example Analysis:**
```
Collect Hardware Artifact Signals:

Signal 1: CPU Brand String
├─ "GenuineIntel" → Likely real Intel CPU
├─ "QEMU" → Likely KVM virtual machine
├─ "VirtualApple" → Likely VMware on macOS
└─ "xen" → Likely Xen hypervisor

Signal 2: TSC (Time Stamp Counter) Behavior
├─ Stable, consistent rate → Bare metal
├─ Jumps or variable rate → Virtualized

Signal 3: MAC Address Prefixes
├─ 00:50:F2:* → Microsoft Hyper-V
├─ 00:0C:29:* → VMware
├─ 02:42:* → Docker containers
└─ 0A:00:27:* → Oracle VirtualBox

Signal 4: Response to Invalid Instructions
├─ Immediate SIGILL → Bare metal
├─ Emulated/caught → Virtualized
```

**Confidence Contribution:** 18% (very strong signal for env classification)

---

### Dimension 9: Adversarial Resistance

**What it measures:** How well system resists or falls for spoofing attempts.

**Why it matters:** Tests whether fingerprint is resilient:
- **Contradictory Signals** – Does system respond consistently?
- **Spoofing Attempts** – Can attacker fake the behavior?
- **Multiple Choice Test** – Probes designed to be answered uniquely per OS
- **Behavioral Consistency** – Do multiple probes agree on OS?

**Example Analysis:**
```
Adversarial Test: Try to make Linux look like Windows

Spoof 1: Set window size to 65535 (Windows value)
├─ This succeeded (Linux can do this)
└─ But TTL still 64 (not Windows' 128) – signal conflict detected!

Spoof 2: Set TTL to 128, change TCP options
├─ Spoofing partially successful
├─ But response timing still shows Linux characteristics
└─ Behavioral analysis catches inconsistency: "Likely spoofed system"

Veto System Activates:
├─ Dimension 1 says: "Windows signature" (window size)
├─ Dimension 2 says: "Linux signal" (TTL)
├─ Dimension 3 says: "Linux pattern" (response timing)
├─ Consensus: "Likely Linux, spoofing attempted"
└─ Confidence reduced: 0.65 (was 0.95 with consistent signals)
```

**Confidence Contribution:** 15% (critical for anti-spoofing)

---

### Combining All 9 Dimensions: Confidence Scoring

The magic happens when all dimensions combine:

```
Fingerprinting Results:

Dimension 1 (TCP Signatures):      85% Linux confidence
Dimension 2 (IP Behavior):         82% Linux confidence
Dimension 3 (Temporal):            78% Linux confidence
Dimension 4 (Congestion):          89% Linux confidence
Dimension 5 (Error Handling):      76% Linux confidence
Dimension 6 (State Machine):       91% Linux confidence
Dimension 7 (Side-Channel):        68% Linux confidence
Dimension 8 (Hardware):            92% Linux 5.x on bare metal
Dimension 9 (Adversarial):         88% No spoofing detected

Multi-Dimensional Analysis:
├─ Consensus: All 9 dimensions point to Linux 5.x
├─ Contradiction Check: None (all dimensions agree)
├─ Spoofing Attempt Detected: No
├─ Final Confidence: (85+82+78+89+76+91+68+92+88) / 9 = 84.4%
└─ Trust Level: GOOD – Confidence score > 0.80
```

---

## Signature Database v2: Architecture & Future

### What is the Signature Database?

The signature database stores **known behavioral patterns** for different operating systems. When Packet Phantom fingerprints a target, it compares observed behaviors against these known patterns.

### v2.0 Design: Individual JSON Files

Instead of a monolithic database, v2.0 uses **one JSON file per OS**:

```
signatures/v2/
├── Linux_5.x.json
├── Windows_10_11.json
├── macOS_12.json
├── FreeBSD_12.json
├── Cisco_IOS_15.json
├── AWS_EC2.json
├── Android_11_12.json
└── v2_schema.json (validation rules)
```

### Anatomy of a Signature File

```json
{
  "format_version": "2.0.0",
  "metadata": {
    "os": "Linux 5.x Series",
    "version": "2.0",
    "signature_version": "1.2",
    "author": "community-researcher@example.com",
    "created": "2026-01-15T10:30:00Z",
    "description": "Covers Linux kernel 5.10 through 5.15"
  },
  "dimensions": {
    "D1": "Static TCP Signatures (TTL, window, options)",
    "D2": "IP Layer Behavior (ID sequencing, fragmentation)",
    "D3": "Temporal Dynamics (response timing, jitter)",
    "D4": "Congestion Response (TCP CC algorithm)",
    "D5": "Error Handling (responses to invalid packets)",
    "D6": "State Machine (connection state transitions)",
    "D7": "Side-Channel Leakage (timing attacks, clock skew)",
    "D8": "Hardware Artifacts (VM detection, CPU type)",
    "D9": "Adversarial Resistance (spoofing detection)"
  },
  "structure": {
    "probe_responses": {
      "tcp_syn_ack": {
        "ttl": 64,
        "window_size": 64240,
        "options": ["MSS", "WScale", "SACK_Permitted", "Timestamp"],
        "df_bit": true,
        "mss": 1460,
        "wscale": 7,
        "sack_permitted": true,
        "timestamp": true,
        "ecn": false
      },
      "tcp_syn_ack_filtered": {
        "drop_probability": 0.0,
        "reset_probability": 0.0,
        "response_patterns": ["direct_response"]
      },
      "icmp_echo": {
        "ttl": 64,
        "response_rate": 1.0,
        "payload_echo": true
      },
      "udp_closed": {
        "icmp_unreachable": true,
        "icmp_type": 3,
        "icmp_code": 3
      }
    },
    "temporal": {
      "response_time_ms": {
        "min": 1.5,
        "max": 5.0,
        "mean": 2.5,
        "stddev": 0.8
      },
      "jitter_pattern": "normal",
      "retransmit_timing": [1000, 3000, 9000]
    },
    "behavioral_patterns": {
      "congestion_control": "cubic",
      "initial_sn_randomness": "cryptographic",
      "time_wait_duration": 60,
      "ack_timeout": 5.0
    },
    "hardware_detection": {
      "vm_indicators": 0.02,
      "likely_virtualized": false,
      "hypervisor_hints": []
    }
  },
  "confidence_factors": {
    "tcp_signatures": 0.85,
    "ip_behavior": 0.82,
    "temporal": 0.78,
    "congestion": 0.89,
    "error_handling": 0.76,
    "state_machine": 0.91,
    "side_channel": 0.68,
    "hardware": 0.92,
    "adversarial": 0.88
  }
}
```

### Why Individual Files?

| Advantage | Impact |
|-----------|--------|
| **Easy Contributions** | Someone can add Linux_5.16.json without touching other files |
| **Version Control** | Git diff shows exactly what changed in one signature |
| **CDN Distribution** | Serve only needed signatures, not entire database |
| **Parallel Development** | Multiple contributors work on different OS simultaneously |
| **Selective Updates** | Update one OS signature without re-releasing entire DB |

### Schema Validation

Every signature is validated against `v2_schema.json` using JSON Schema standard:

```python
import jsonschema

signature = load_json("signatures/v2/Linux_5.x.json")
schema = load_json("signatures/v2_schema.json")

try:
    jsonschema.validate(instance=signature, schema=schema)
    print("✓ Signature is valid")
except jsonschema.ValidationError as e:
    print(f"✗ Validation failed: {e.message}")
```

This prevents malformed signatures from entering the database.

### Future v2.1: Integrity Hashing

Each signature will include SHA256 hash of its contents:

```json
{
  "metadata": {
    "signature_hash": "sha256:a1b2c3d4e5f6...",
    "hash_timestamp": "2026-02-10T15:30:00Z"
  }
}
```

**Benefits:**
- ✅ Detect tampering or corruption
- ✅ Verify authenticity from CDN
- ✅ Enable cryptographic verification

### Future v3.0: CDN Distribution

```
User runs: sudo pp os deep -t target.com

Packet Phantom:
  1. Checks local cache for Linux signatures
  2. If missing or outdated:
     - Fetches from CDN: https://cdn.packet-phantom.org/v2/Linux_5.x.json
     - Verifies SHA256 hash
     - Caches locally for future use
  3. Proceeds with fingerprinting
```

This gives the best of both worlds:
- **Offline capability** – Already cached signatures work
- **Fresh data** – New signatures available automatically
- **Bandwidth efficient** – Only download needed signatures

---

## Complete Usage Guide

### Installation Recap

#### Option 1: Clone & Run

```bash
git clone https://github.com/medaminkh-dev/packet-phantom.git
cd packet-phantom
pip install -r requirements.txt
sudo python3 packet_phantom.py --help
```

#### Option 2: Setup.py Installation

```bash
git clone https://github.com/medaminkh-dev/packet-phantom.git
cd packet-phantom
sudo pip install -e .
sudo pp --help  # Now available system-wide as 'pp'
```

### General Command Structure

```bash
pp [COMMAND] [OPTIONS]
```

### Commands Overview

| Command | Purpose | Mode |
|---------|---------|------|
| `scan` | Port scanning | Default |
| `os` | OS fingerprinting | Reconnaissance |
| `discover` | Network discovery | Reconnaissance |
| `sniff` | Packet sniffing | Passive |
| `flood` | Flood attacks | Testing (authorized only) |
| `shell` | Interactive shell | Interactive |
| `api` | Start API server | Server |

### Operating Modes

#### Educational Mode (Default - Safe)

```bash
# All of these use educational mode by default
sudo pp scan -t 192.168.1.1
sudo pp scan -t 192.168.1.1 --edu
sudo pp scan -t 192.168.1.1 --mode edu
```

**Features:**
- ✅ Rate limit: 100 packets/second
- ✅ Memory limit: 200MB
- ✅ Safe timeouts
- ✅ Perfect for learning

#### Live Mode (Advanced - Authorized Only)

```bash
# Requires explicit --live flag
sudo pp scan -t 192.168.1.1 --live

# Or with --mode
sudo pp scan -t 192.168.1.1 --mode live
```

**Features:**
- ⚠️ Rate limit: 10,000 packets/second
- ⚠️ No artificial restrictions
- ⚠️ Designed for authorized penetration testing
- ⚠️ Use only on systems/networks you own or have permission to test

### OS Fingerprinting: Complete Guide

#### Quick Fingerprinting

```bash
# Fast, minimal probes (~10 seconds)
sudo pp os quick -t 192.168.1.100
```

**Output:**
```
OS Fingerprinting Results - Quick Mode
======================================
Target: 192.168.1.100
Probes Sent: 5
Responses: 5

Results:
├─ Operating System: Linux 5.x
├─ Confidence: 0.89 (GOOD)
├─ Device Type: Server
├─ Environment: Physical hardware
│
├─ Dimension Scores:
│  ├─ TCP Signatures: 0.85
│  ├─ IP Behavior: 0.82
│  ├─ Temporal: 0.78
│  └─ Hardware: 0.92
│
└─ Recommendations:
   └─ For higher accuracy, try: pp os deep -t 192.168.1.100
```

#### Deep Fingerprinting

```bash
# Comprehensive analysis (~30-60 seconds)
sudo pp os deep -t 192.168.1.100
```

**Output includes:**
- All 9 dimensional analysis
- Detailed per-dimension breakdown
- Confidence scoring with veto checks
- Service detection
- Virtualization identification
- Hardware classification

#### Forensic Analysis

```bash
# Exhaustive analysis (~2-5 minutes)
sudo pp os forensic -t 192.168.1.100
```

**Special forensic features:**
- Exhaustive probe set (20+ probes)
- Side-channel analysis
- CPU architecture detection
- Timing-based analysis
- Entropy measurements
- Advanced spoofing detection

### Port Scanning Examples

#### Basic Scanning

```bash
# Scan default ports (80, 443)
sudo pp scan -t 192.168.1.1

# Scan specific ports
sudo pp scan -t 192.168.1.1 -p 22,80,443,3306

# Scan port range
sudo pp scan -t 192.168.1.1 -p 1-1000
```

#### Subnet Scanning

```bash
# Scan entire subnet
sudo pp scan -t 192.168.1.0/24 -p 80,443

# Scan CIDR range
sudo pp scan -t 10.0.0.0/16 -p 80,443

# Scan IP range
sudo pp scan -t "192.168.1.1-192.168.1.50" -p 80,443
```

#### Performance Tuning

```bash
# Adjust packet rate (packets per second)
sudo pp scan -t 192.168.1.0/24 -p 80,443 -r 1000

# Use threads for parallelism
sudo pp scan -t 192.168.1.0/24 -p 80,443 -T 20

# Set timeout for responses
sudo pp scan -t 192.168.1.1 -p 80,443 --timeout 10
```

#### Output Formats

```bash
# JSON output
sudo pp scan -t 192.168.1.1 -p 80,443 --format json -o results.json

# CSV output
sudo pp scan -t 192.168.1.1 -p 80,443 --format csv -o results.csv

# HTML report
sudo pp scan -t 192.168.1.1 -p 80,443 --format html -o report.html

# PCAP capture
sudo pp scan -t 192.168.1.1 -p 80,443 --format pcap -o traffic.pcap
```

### Network Discovery

```bash
# Discover active hosts
sudo pp discover -t 192.168.1.0/24

# Save to JSON
sudo pp discover -t 192.168.1.0/24 -o hosts.json --format json

# With OS fingerprinting
sudo pp discover -t 192.168.1.0/24 --fingerprint deep
```

### Packet Sniffing

```bash
# Sniff on interface
sudo pp sniff -i eth0

# Sniff and save to PCAP
sudo pp sniff -i eth0 -o capture.pcap

# Sniff specific protocol
sudo pp sniff -i eth0 --filter "tcp port 80"

# Sniff and display
sudo pp sniff -i eth0 --display
```

### Interactive Shell

```bash
# Start interactive shell
sudo pp shell

# Then available commands:
# syn <target> <port> [count]     - Send SYN packet
# udp <target> <port> <data>      - Send UDP packet
# icmp <target> <type> <data>     - Send ICMP packet
# flood <target> <port> <rate>    - Start flood
# stats                           - Show statistics
# quit                            - Exit
```

---

## Advanced Usage

### Evasion Techniques

Evasion helps bypass network filters, IDS/IPS, and WAF systems:

#### TTL Randomization

```bash
# Enable TTL evasion
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion ttl

# Specific TTL range
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion ttl --ttl-range 56-64
```

**How it works:**
- TTL value randomized within specified range
- IDS may miss patterns based on fixed TTL
- Still passes through normal networks

#### TCP Option Scrambling

```bash
# Scramble TCP options
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion options
```

**What changes:**
- TCP option order randomized
- Option padding inserted
- Still functionally identical packets

#### IP Fragmentation

```bash
# Fragment packets
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion fragmentation

# Specify MTU
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion fragmentation --mtu 1200
```

**Effect:**
- Large packets split into fragments
- Some IDS struggle with reassembly
- Useful against packet inspection rules

#### Padding Injection

```bash
# Add random padding
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion padding

# Specific padding size
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion padding --padding 100
```

#### Combining Techniques

```bash
# Use multiple evasion methods
sudo pp scan -t 192.168.1.1 -p 80,443 \
  --evasion ttl,options,fragmentation,padding
```

### Custom Configurations

Create custom config file:

```json
{
  "general": {
    "default_port": 443,
    "default_ttl": 56,
    "timeout": 10.0
  },
  "security": {
    "rate_limits": {
      "default_rate": 1000,
      "max_rate": 10000
    }
  },
  "evasion": {
    "enabled": true,
    "ttl_mode": "random",
    "ttl_range": {"min": 56, "max": 64}
  }
}
```

Use it:
```bash
sudo pp scan -t 192.168.1.1 --config custom_config.json
```

### API Server Mode

Start HTTP API server:

```bash
# Start API on port 8080
sudo pp api --port 8080

# Test with curl
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "ports": [80, 443],
    "mode": "quick"
  }'
```

### Scripting & Integration

#### Python Integration

```python
from packet_phantom.core.os_fingerprint import OSFingerprinter
from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2

# Initialize fingerprinter
db = SignatureDatabaseV2("signatures/v2/")
fingerprinter = OSFingerprinter(signature_db=db)

# Fingerprint target
result = fingerprinter.fingerprint(
    target_ip="192.168.1.1",
    probe_depth="deep",
    timeout=30.0
)

# Access results
print(f"OS: {result.os_name}")
print(f"Confidence: {result.confidence}")
print(f"Device Type: {result.device_type}")
for dimension, score in result.dimensional_scores.items():
    print(f"  {dimension}: {score:.2%}")
```

#### JSON Output Processing

```bash
# Scan and save JSON
sudo pp scan -t 192.168.1.0/24 -p 80,443 \
  --format json -o scan_results.json

# Process with jq
cat scan_results.json | jq '.results[] | select(.port == 80) | .status'

# Extract open hosts
cat scan_results.json | jq '.results[] | select(.status == "open") | .ip' -r
```

#### Integration with Other Tools

```bash
# Export for Metasploit
sudo pp os deep -t 192.168.1.1 --format metasploit -o msfconsole_input.txt

# Export for Nessus
sudo pp discover -t 192.168.1.0/24 --format nessus -o nessus_targets.txt

# Pipe to other tools
sudo pp scan -t 192.168.1.1 --format json | jq . | grep open_ports
```

---

## API Reference

### Command-Line Interface (CLI) API

#### Global Options

```
-t, --target ADDR          Target IP, hostname, or CIDR
-p, --ports PORTS          Ports to scan (comma-separated or range)
-r, --rate RATE            Packets per second (default: 100 in edu mode)
-T, --threads NUM          Number of worker threads
-o, --output FILE          Output file path
-of, --format FMT          Output format (json, csv, html, pcap)
-v, --verbose              Verbose output
-s, --silent               Silent mode (no output except results)
--timeout SEC              Response timeout
--retry NUM                Retry attempts
--edu                      Educational mode (default, safe)
--live                     Live mode (authorized testing, higher limits)
--help                     Show help
--version                  Show version
```

#### Scan Command

```bash
pp scan [OPTIONS]
```

**Specific Options:**
- `--probe-type TYPE` – Probe types: syn, ack, fin, rst, icmp, udp, all
- `--timing PROFILE` – Timing profile: paranoid, sneaky, polite, normal, aggressive, insane
- `--randomize` – Randomize port order
- `--exclude-ports PORTS` – Ports to exclude from scan

#### OS Command

```bash
pp os {quick|deep|forensic} [OPTIONS]
```

**Analysis Levels:**
- `quick` – Fast analysis (10 seconds), ~80% accuracy
- `deep` – Comprehensive (30-60 seconds), ~90% accuracy
- `forensic` – Exhaustive (2-5 minutes), ~95% accuracy

**Specific Options:**
- `--probe-depth {quick,deep,forensic}` – Override default
- `--use-custom FILE` – Use custom signature database
- `--save-probes FILE` – Save sent probes for replay
- `--analyze-only FILE` – Analyze saved probe responses

#### Discover Command

```bash
pp discover -t SUBNET [OPTIONS]
```

**Specific Options:**
- `--fingerprint {quick,deep,forensic}` – Also fingerprint discovered hosts
- `--port-scan PORT[,PORT]` – Scan specific ports on discovered hosts
- `--save-hosts FILE` – Save discovered hosts list

#### Sniff Command

```bash
pp sniff -i INTERFACE [OPTIONS]
```

**Specific Options:**
- `--filter EXPR` – BPF filter expression (e.g., "tcp port 80")
- `--display` – Print captured packets to screen
- `--hex` – Display payload in hexadecimal
- `--pcap FILE` – Save to PCAP file

### Python API

#### OSFingerprinter Class

```python
from packet_phantom.core.os_fingerprint import OSFingerprinter

fingerprinter = OSFingerprinter()
result = fingerprinter.fingerprint(target_ip, probe_depth="deep")

# Result attributes
result.os_name                # e.g., "Linux 5.x"
result.os_vendor              # e.g., "Linux"
result.os_version             # e.g., "5.15"
result.device_type            # e.g., "server"
result.confidence             # 0.0 to 1.0
result.dimensional_scores     # Dict of 9 dimensions
result.is_virtualized         # True/False
result.hypervisor_type        # e.g., "KVM", "VMware", None
result.spoofing_detected      # True/False
```

#### SignatureDatabaseV2 Class

```python
from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2

db = SignatureDatabaseV2("signatures/v2/")
db.load_all_signatures()
signature = db.get_signature("Linux_5.x")
all_sigs = db.list_signatures()
```

---

## For Researchers & Academics

### Extensibility

Packet Phantom is designed for academic research and extension:

#### Adding Custom Probes

```python
from packet_phantom.core.probe_engine import Probe, ProbeType

# Define custom probe
custom_probe = Probe(
    name="IPv6_ECN_Probe",
    probe_type=ProbeType.TCP_SYN,
    target_port=80,
    timeout=5.0,
    retry_count=1,
    payload=b'\x00' * 40  # Custom payload
)

# Add to fingerprinter's probe set
fingerprinter.add_custom_probe(custom_probe)
```

#### Custom Behavioral Analysis

```python
from packet_phantom.core.behavioral_analyzer import BehavioralAnalyzer

class CustomAnalyzer(BehavioralAnalyzer):
    def analyze_custom_dimension(self, probe_responses):
        # Implement custom analysis
        # Return confidence score 0.0 to 1.0
        score = self.compute_score(probe_responses)
        return score

# Use in fingerprinting
fingerprinter.add_analyzer(CustomAnalyzer())
```

#### Custom Signature Format

While JSON is standard, researchers can implement custom parsers:

```python
from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2

class CustomFormatDB(SignatureDatabaseV2):
    def load_signature(self, signature_path):
        if signature_path.endswith('.xml'):
            # Custom XML parser
            return self.load_xml_signature(signature_path)
        elif signature_path.endswith('.yaml'):
            # Custom YAML parser
            return self.load_yaml_signature(signature_path)
        else:
            # Fall back to standard JSON
            return super().load_signature(signature_path)
```

### Research Applications

#### 1. TCP/IP Stack Analysis

Study how operating systems implement TCP/IP protocols:

```bash
# Collect behavioral data on multiple OS versions
for os in Linux_5.10 Linux_5.15 Windows_10 Windows_11; do
  sudo pp os forensic -t $os_host --save-probes $os.json
done

# Analyze differences
python3 analyze_stacks.py Linux_5.10.json Linux_5.15.json
```

#### 2. Network Security Research

Use Packet Phantom for security research papers:

```
Research Question: How detectable are cloud instances?

Methodology:
1. Fingerprint 100 instances on each major cloud (AWS, Azure, GCP)
2. Record all dimensional scores
3. Analyze variance and clustering
4. Publish findings

Results: CloudProvider[X] shows distinctive pattern in Dimension 5
         (error handling), allowing identification with 94% accuracy
```

#### 3. Anomaly Detection

Train machine learning models on behavioral signatures:

```python
from packet_phantom import fingerprinter
import sklearn

# Collect training data
training_samples = []
for target in known_systems:
    result = fingerprinter.fingerprint(target, probe_depth="deep")
    features = result.dimensional_scores
    training_samples.append(features)

# Train classifier
clf = sklearn.ensemble.RandomForestClassifier()
clf.fit(training_samples, labels)

# Detect anomalies
target_result = fingerprinter.fingerprint(unknown_target)
target_features = target_result.dimensional_scores
is_anomaly = clf.decision_function(target_features) < threshold
```

### Academic Publications

Packet Phantom provides excellent material for research papers:

**Sample Topics:**
- "Behavioral OS Fingerprinting: Beyond Static Signatures" – fingerprinting methodology
- "TCP/IP Stack Fingerprinting Under Adversarial Conditions" – evasion techniques
- "Detecting Virtualization Through Behavioral Analysis" – hardware artifact detection
- "Machine Learning for Network Reconnaissance" – ML-based analysis
- "Side-Channel Leakage in Network Protocol Implementations" – timing attacks

**Available Artifacts for Citations:**
- Signature database with 50+ OS signatures
- Probe sequences and response datasets
- Behavioral analysis algorithms
- Performance benchmarks and comparison data

### Contributing Research

Researchers can contribute new findings:

1. **Behavioral Models** – New proof of behavioral analysis technique
2. **Signature Datasets** – Large-scale OS fingerprint collections
3. **Optimization Techniques** – Faster or more accurate probing
4. **Evasion Methods** – New ways to bypass IDS/WAF
5. **Hardware Detection** – Improved virtualization identification

---

## Troubleshooting

### Common Issues

#### Permission Denied / Not Root

```
Error: Permission denied (need root)
```

**Solution:**
```bash
# Raw socket operations require root
sudo pp scan -t 192.168.1.1
# OR
sudo python3 packet_phantom.py scan -t 192.168.1.1
```

#### Network Unreachable

```
Error: Network unreachable
```

**Diagnosis:**
```bash
# Check network connectivity
ping -c 1 192.168.1.1

# Check routing
route -n | grep 192.168.1.0

# Verify interface
ip addr show

# Check firewall
sudo iptables -L
```

**Solution:** Ensure target is reachable and firewall allows outbound packets.

#### Timeout / No Responses

```
Error: Response timeout - 0/5 probes received
```

**Causes & Solutions:**

| Cause | Solution |
|-------|----------|
| Target offline | Verify IP is reachable with `ping` |
| Firewall blocking | Check firewall rules on target |
| No route to target | Verify routing with `route` or `traceroute` |
| Rate limiting | Reduce rate: `--rate 50` |
| Probe timing too short | Increase timeout: `--timeout 30` |

**Diagnostic:**
```bash
# Test with verbose mode
sudo pp scan -t 192.168.1.1 --verbose

# Try longer timeout
sudo pp scan -t 192.168.1.1 --timeout 30

# Try reduced rate
sudo pp scan -t 192.168.1.1 --rate 10

# Check with tcpdump
sudo tcpdump -i eth0 -w debug.pcap
sudo pp scan -t 192.168.1.1 &
# Then analyze debug.pcap in Wireshark
```

#### Inaccurate Results

```
Result shows: Windows 10 (confidence: 0.45 - POOR)
```

**Reasons & Solutions:**

| Reason | Solution |
|--------|----------|
| Filtering by WAF/LB | Try deep analysis: `pp os deep ...` |
| Cloud environment | Expect lower accuracy, check hardware dimension |
| Spoofed system | Check "Spoofing Detected" field, try forensic mode |
| Unknown OS | May not be in signature database |
| Network noise | Reduce rate, increase timeout |

**Diagnostic:**
```bash
# Try deeper analysis
sudo pp os deep -t target

# Check dimensional scores
sudo pp os forensic -t target

# Try without filters if possible
# Try direct connection instead of through firewall
# Compare with Nmap: nmap -O target (for reference)
```

#### Out of Memory

```
Error: Allocation failure - out of memory
```

**Cause:** Too many targets or threads.

**Solution:**
```bash
# Reduce thread count
sudo pp scan -t 192.168.0.0/16 -T 5  # Instead of -T 50

# Process in smaller batches
for subnet in 192.168.{0..3}.0/24; do
  sudo pp scan -t $subnet
done

# Check memory usage
ps aux | grep pp
free -h
```

#### Evasion Not Working

```
Scan still detected by IDS despite --evasion
```

**Considerations:**
- Evasion helps but isn't guaranteed to bypass all systems
- Modern IDS use multiple detection methods
- Behavioral anomalies may be detected even with evasion
- Some networks inspect deeply regardless of packet structure

**Verify evasion is enabled:**
```bash
# Check verbose output
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion ttl -v

# Capture traffic to see changes
sudo tcpdump -i eth0 -w with_evasion.pcap &
sudo pp scan -t 192.168.1.1 --evasion ttl
# Compare TTL values in capture
```

### Performance Issues

#### Slow Scanning

```bash
# Speed up with adjustments
sudo pp scan -t 192.168.1.0/24 \
  -r 5000 \           # Increase rate to 5000 pkt/s
  -T 20 \             # Use 20 threads
  --timeout 3         # Reduce timeout to 3 seconds
```

#### High CPU Usage

```bash
# Reduce parallelism
sudo pp scan -t 192.168.1.1 -T 2  # Only 2 threads

# Use batch engine instead of async
sudo pp scan -t 192.168.1.1 --engine batch
```

#### High Memory Usage

```bash
# Reduce batch size
sudo pp scan -t 192.168.1.1 --batch-size 32  # Default 64

# Process incrementally
for i in {1..254}; do
  pp scan -t 192.168.1.$i -p 80,443
done
```

### Debugging

Enable debug output:

```bash
# Very verbose output
sudo pp scan -t 192.168.1.1 -v

# Even more verbose
sudo pp scan -t 192.168.1.1 -vv

# Debug logs to file
sudo pp scan -t 192.168.1.1 --debug-log /tmp/debug.log
```

Save probes for analysis:

```bash
# Save what was sent
sudo pp os deep -t 192.168.1.1 --save-probes probes.json

# Analyze probe details
python3 -c "import json; print(json.dumps(json.load(open('probes.json')), indent=2))"
```

Capture network traffic:

```bash
# In one terminal
sudo tcpdump -i eth0 -w traffic.pcap &

# In another
sudo pp scan -t 192.168.1.1

# Analyze later
wireshark traffic.pcap
```

---

## Summary: The Packet Phantom Difference

Packet Phantom stands apart from traditional network tools through:

1. **Behavioral Analysis** – Not just signature matching, but understanding *why* systems behave as they do
2. **9-Dimensional Analysis** – Multiple correlated signals reduce false positives
3. **Honest About Confidence** – Clear confidence scores with veto system prevents overconfidence
4. **Community-Ready** – Individual JSON signatures enable global contributions
5. **Future-Proof Architecture** – CDN-ready design scales with community growth
6. **Educational Foundation** – Safe defaults while powerful when authorized
7. **Research-Friendly** – Extensible Python API for custom analysis

---

## Additional Resources

- **GitHub Repository:** [medaminkh-dev/packet-phantom](https://github.com/medaminkh-dev/packet-phantom)
- **Issue Tracker:** Report bugs and request features
- **Discussions:** Ask questions and share ideas
- **Wiki:** Community knowledge base and examples

---

## License & Attribution

Packet Phantom is an open-source project. Please respect licenses and attribution requirements.

**Contributing?** See [README.md](README.md#contributing) for guidelines.

---

**Happy fingerprinting! Use responsibly and ethically.**

**Version 2.0.0** | **Last Updated: February 2026**
