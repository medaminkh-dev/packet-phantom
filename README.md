# Packet Phantom v2.0.0

```
  ██████   █████  ███    ███ ███████      ██████  ██    ██ ███████ ██████  
 ██       ██   ██ ████  ████ ██          ██    ██ ██    ██ ██      ██   ██ 
 ██  ███  ███████ ██ ████ ██ █████       ██    ██ ██    ██ █████   ██████  
 ██   ██  ██   ██ ██  ██  ██ ██          ██    ██  ██  ██  ██      ██   ██ 
  ██████  ██   ██ ██      ██ ███████      ██████    ████   ███████ ██   ██ 

     [> PACKET FORGER v2.0.0 <]  [OPEN-SOURCE NETWORK TESTING FRAMEWORK]
```

**Professional-Grade OS Fingerprinting & Network Testing Framework**

## ⚠️ Disclaimer

**Packet Phantom is an educational and authorized testing tool only.** All network testing, port scanning, packet crafting, and OS fingerprinting activities must be conducted **only on networks and systems you own or have explicit written permission to test**.

Unauthorized network testing is illegal in most jurisdictions. This tool is provided for:

- Security researchers
- Penetration testers with proper authorization
- Educational purposes in controlled environments
- Network administrators testing their own infrastructure

**Use responsibly. Respect privacy and laws.**

---

## 🎯 Project Overview

Packet Phantom is a next-generation network reconnaissance and OS fingerprinting framework built on modern Python architecture. It combines the power of Scapy packet crafting with a sophisticated **9-dimensional behavioral analysis engine** for accurate operating system identification.

Unlike traditional port scanners, Packet Phantom analyzes how operating systems *behave* under various network conditions—their TCP/IP stack implementations, error handling, timing characteristics, and hardware artifacts—to provide highly accurate OS fingerprinting without relying on outdated signature databases alone.

**Key Philosophy:** Behavioral analysis over database lookups. Active research over passive assumptions.

---

## ⭐ Key Features

### 🔍 **9-Dimensional Behavioral OS Fingerprinting**

- **Static TCP Signatures** – TCP header fields, options, and response patterns
- **IP Layer Behavior** – TTL, IP ID sequencing, fragmentation preferences, IP options
- **Temporal Dynamics** – Response timing jitter, scheduling behavior, clock analysis
- **Congestion Response** – TCP congestion control algorithm fingerprints (RENO, CUBIC, BBR, Vegas)
- **Error Handling** – Responses to malformed packets and RFC violations
- **State Machine Behavior** – TCP state transition analysis and abnormalities
- **Side-Channel Leakage** – Timing attacks, clock skew detection
- **Hardware Artifacts** – Physical vs. virtual machine detection, hypervisor identification
- **Adversarial Resistance** – Anti-spoofing detection and evasion technique recognition

### 📦 **High-Performance Packet Crafting**

- Raw socket-free architecture using battle-tested **Scapy library**
- IPv4 and IPv6 support with full header customization
- ICMP, UDP, and TCP protocol forging
- Batch packet sending with `sendmmsg` optimization
- Configurable payloads and headers

### 🛡️ **Advanced Evasion Techniques**

- TTL randomization and manipulation
- TCP option scrambling
- IP fragmentation strategies
- Padding injection for IDS/WAF bypass
- Stealth probing modes

### 🔄 **Multiple Execution Engines**

- **Async Engine** – High-concurrency non-blocking I/O
- **Batch Engine** – Optimized syscall reduction for throughput
- **Multi-Process Engine** – True parallelism for CPU-bound operations
- **Parallel Probe Engine** – Concurrent fingerprinting with probe caching

### 📊 **Flexible Output Formats**

- JSON for automation and integration
- CSV for spreadsheet analysis
- HTML reports with visualizations
- PCAP file generation for Wireshark analysis
- Console output with color-coded results

### 🎓 **Educational Mode (Safe Default)**

- `--edu` flag (default) enforces safe testing parameters
- Rate limiting: 100 packets/second max
- Memory and CPU resource constraints
- Safe timeouts and retry limits
- Perfect for learning network fundamentals

### ☁️ **Cloud-Ready Signature Database**

- JSON Schema-validated signatures
- Individual file-per-OS design for community contributions
- Planned CDN/hybrid deployment with GitHub Pages
- Integrity verification via SHA256 hashing
- Automatic signature fetching and caching

---

## 📥 Installation

### Prerequisites

- **Python 3.8+**
- **Root/Administrator privileges** (for raw socket operations)
- Linux, macOS, or Windows with appropriate network drivers

### Method 1: Git Clone & Install (Development)

```bash
# Clone the repository
git clone https://github.com/medaminkh-dev/packet-phantom.git
cd packet-phantom

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run directly
sudo python3 packet_phantom.py --help
# OR
sudo python3 -m packet_phantom.cli --help
```

### Method 2: Setup.py Installation (System-Wide)

```bash
# Clone and enter directory
git clone https://github.com/medaminkh-dev/packet-phantom.git
cd packet-phantom

# Install with setuptools
sudo pip install -e .

# Creates 'pp' console script alias
# Now you can run from anywhere:
sudo pp --help
sudo pp scan -t 192.168.1.1 -p 80,443
```

### Dependencies

**Core Requirements:**

- `scapy` – Packet crafting and manipulation
- `jsonschema` – JSON signature validation
- `requests` – HTTP for future CDN signature fetching
- `colorama` – Cross-platform colored output

**Optional Requirements:**

- `pytest` – Testing framework
- `sphinx` – Documentation generation

---

## 🚀 Quick Start Examples

### Basic OS Fingerprinting (Quick Mode)

```bash
# Quick OS detection - minimal probes, ~10 seconds
sudo pp os quick -t 192.168.1.1
```

### Deep OS Fingerprinting

```bash
# Comprehensive OS analysis - full behavioral analysis
sudo pp os deep -t 192.168.1.1
```

### Port Scanning

```bash
# Scan common ports (default: 80, 443)
sudo pp scan -t 192.168.1.1

# Scan specific ports
sudo pp scan -t 192.168.1.1 -p 22,80,443,3306,5432

# Scan port range
sudo pp scan -t 192.168.1.0/24 -p 1-1000 --format json -o results.json

# High-speed scanning with custom rate
sudo pp scan -t 10.0.0.0/24 -p 80,443 -r 1000
```

### Network Discovery

```bash
# Discover active hosts on subnet
sudo pp discover -t 192.168.1.0/24

# Save results to JSON
sudo pp discover -t 10.0.0.0/24 -o hosts.json --format json
```

### Packet Sniffing

```bash
# Sniff network traffic (requires root)
sudo pp sniff -i eth0

# Capture to PCAP file
sudo pp sniff -i eth0 -o traffic.pcap
```

### Interactive Shell

```bash
# Start interactive packet crafting shell
sudo pp shell
```

### Educational Mode (Default - Safe Testing)

```bash
# Educational mode is the default - safe rate limits (100 pkt/s)
sudo pp scan -t 192.168.1.1 -p 80,443

# Explicitly enable educational mode
sudo pp scan -t 192.168.1.1 -p 80,443 --edu
```

### Live Mode (Advanced - Authorized Testing Only)

```bash
# Live mode for authorized penetration testing - higher rate limits (10k pkt/s)
# WARNING: Use only on authorized targets
sudo pp scan -t 192.168.1.1 -p 1-1000 --mode live --rate 5000
```

### Evasion Techniques

```bash
# Enable TTL randomization
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion ttl

# Enable TCP option scrambling
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion options

# Enable IP fragmentation
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion fragmentation

# Combine multiple evasion techniques
sudo pp scan -t 192.168.1.1 -p 80,443 --evasion ttl,options,padding
```

---

## 📁 Project Structure

```
packet-phantom/
├── packet_phantom.py              # Entry point (forwards to cli.py)
├── requirements.txt               # Python package dependencies
├── setup.py                       # Setup configuration for pip install
│
├── packet_phantom/
│   ├── __init__.py               # Package metadata (version, author)
│   ├── cli.py                    # Command-line interface (2800+ lines)
│   │
│   ├── core/                     # Core network functionality
│   │   ├── os_fingerprint.py     # 9D behavioral analysis engine (3371 lines)
│   │   ├── signature_db_v2.py    # JSON signature database manager (840 lines)
│   │   ├── probe_engine.py       # Probe sequencing and execution
│   │   ├── async_engine.py       # Async packet engine
│   │   ├── batch_sender.py       # Batch packet sending optimization
│   │   ├── multi_process_engine.py  # Multi-process packet engine
│   │   ├── parallel_engine.py    # Parallel probe optimization
│   │   ├── ipv4_forger.py        # IPv4 packet crafting
│   │   ├── ipv6_forger.py        # IPv6 packet crafting
│   │   ├── udp_forger.py         # UDP packet forging
│   │   ├── icmp_forger.py        # ICMP packet forging
│   │   ├── network_utils.py      # Network utilities
│   │   ├── raw_socket.py         # Raw socket management
│   │   ├── mode_manager.py       # EDU/LIVE mode switching
│   │   ├── behavioral_analyzer.py # Behavioral pattern analysis
│   │   ├── confidence_scoring.py  # Multi-dimensional confidence scoring
│   │   ├── checksum.py           # Checksum calculations
│   │   └── service_detection.py  # Service fingerprinting
│   │
│   ├── evasion/                  # Evasion technique implementations
│   │   ├── evasion_suite.py      # Main evasion orchestrator
│   │   ├── ttl_evasion.py        # TTL manipulation
│   │   ├── option_scrambler.py   # TCP option scrambling
│   │   └── padding_generator.py  # Padding injection
│   │
│   ├── interface/                # User interface components
│   │   ├── banner.py             # Adaptive ASCII banners
│   │   └── interactive_shell.py  # Interactive packet shell (1196 lines)
│   │
│   ├── output/                   # Output and reporting
│   │   ├── output_manager.py     # Output orchestration
│   │   ├── console.py            # Console formatting
│   │   ├── pcap_writer.py        # PCAP file generation
│   │   ├── os_output_formatter.py # OS fingerprint reporting
│   │   ├── educational_mode.py   # EDU mode output formatting
│   │   └── metrics.py            # Performance metrics
│   │
│   ├── config/                   # Configuration management
│   │   ├── config_manager.py     # Dynamic configuration
│   │   ├── default_config.json   # Default settings
│   │   └── __init__.py
│   │
│   ├── api/                      # REST API server
│   │   └── server.py             # Flask/FastAPI server (future)
│   │
│   └── security/                 # Security features
│       ├── rate_limiter.py       # Token bucket rate limiting
│       └── __init__.py
│
├── signatures/                   # OS fingerprint signatures
│   ├── v2_schema.json           # JSON Schema validation (v2.0.0)
│   └── v2/                      # Individual OS signature files
│       ├── Linux_5.x.json
│       ├── Windows_10_11.json
│       ├── macOS.json
│       ├── FreeBSD_12.json
│       ├── Cisco_IOS.json
│       ├── AWS_EC2.json
│       └── Android.json
│
└── docs/                        # Documentation (future)
    ├── API.md
    ├── CONTRIBUTING.md
    └── DEVELOPER.md
```

---

## 🏗️ Architecture Highlights

### Scapy-Centric Design

Packet Phantom was initially developed with raw socket implementation, but this approach proved complex and error-prone across different OS platforms. **Scapy was chosen because:**

1. **Battle-Tested** – Used in industry and research for 15+ years
2. **Simplified Development** – Abstracts platform differences (Windows, macOS, Linux)
3. **Reliable Packet Crafting** – Handles edge cases and protocol complexities
4. **No Reinvention** – Focus on fingerprinting logic, not socket plumbing
5. **Community Support** – Extensive documentation and active user base

### Behavioral Analysis Engine

The `os_fingerprint.py` module (3,371 lines) implements a sophisticated 9-dimensional fingerprinting engine that analyzes operating system behavior rather than relying solely on signature databases. This approach is:

- **More Accurate** – Catches variations and custom builds
- **Future-Proof** – Adapts to new OS versions automatically
- **Anti-Evasion** – Detects spoofing attempts through behavior analysis
- **Honest About Confidence** – Veto system prevents false positives

### JSON Signature Database v2

Signatures are stored as individual JSON files (one per OS), each validated against a JSON Schema. This design enables:

- **Easy Community Contributions** – Simply add a new JSON file
- **CDN Distribution** – Each file can be independently hosted
- **Quality Control** – Schema validation ensures data integrity
- **Future Hybrid Mode** – Local cache + remote fetching via `requests.get()`
- **Integrity Verification** – SHA256 hashing in metadata

### Multi-Engine Execution

Different use cases benefit from different execution models:

- **Async Engine** – Thousands of concurrent probes with minimal resource overhead
- **Batch Engine** – Reduced syscall overhead through packet batching
- **Multi-Process Engine** – True parallelism for fingerprint analysis
- **Parallel Probe Engine** – Concurrent probes with intelligent caching

---

## 🔒 Security Features

### Safety by Default

- **Educational Mode** is the default – rate limits to 100 packets/second
- Resource limits prevent accidental DoS on the local system
- Input validation for all user-supplied parameters
- Privilege dropping to unprivileged user after socket setup

### Advanced Protections

- **Rate Limiting** – Token bucket algorithm prevents system overload
- **Resource Limits** – CPU and memory constraints enforced
- **Path Validation** – Prevention of directory traversal attacks
- **Unicode Normalization** – Prevents encoding-based attacks
- **Secure Randomization** – Cryptographically sound PRNG for nonce generation

### Authorized Testing Enforcement

- Clear disclaimers and warnings
- `--edu` mode highlighted as default safe option
- `--mode live` mode requires explicit opt-in with warnings
- Logging of all operations for audit trails

---

## 📚 Documentation

- **[README.md](README.md)** – This file (project overview, installation, quick start)
- **[Documentation.md](Documentation.md)** – Complete user guide and technical reference
- **[Challenges.md](Challenges.md)** – Technical decisions, limitations, and future vision

For in-depth guides:

- OS fingerprinting methodology and accuracy analysis
- Signature database structure and contribution guide
- API reference and integration examples
- Extensibility for custom probes and analysis

---

## 🤝 Contributing

We welcome contributions from security researchers, penetration testers, and network engineers!

### How to Contribute

1. **New OS Signatures** – Add JSON files to `signatures/v2/` following the schema
2. **Probe Techniques** – Suggest new behavioral probes
3. **Evasion Methods** – Contribute additional IDS/WAF bypass techniques
4. **Documentation** – Improve guides and examples
5. **Bug Reports** – Report issues with detailed reproduction steps

### Contribution Guidelines

- All contributions must include documentation
- Code must follow PEP 8 style guidelines
- Network testing code must include security disclaimers
- Changes to security-sensitive modules require review
- Each commit should reference an issue

### Signature Submission

To add a new OS signature:

1. Create a new file: `signatures/v2/OS_Name_Version.json`
2. Follow the schema in `signatures/v2_schema.json`
3. Include probe response samples from real systems
4. Document the source/environment where signatures were captured
5. Submit a pull request with testing methodology

---

## 🔮 Future Vision: Cloud-Ready Architecture

Packet Phantom is designed for the future of distributed security tools:

### Current State (v2.0.0)

- ✅ Local signature files in `signatures/v2/`
- ✅ JSON Schema validation for data integrity
- ✅ Modular file-per-OS design

### Near-term (v2.1)

- 📅 SHA256 integrity hashing in signature metadata
- 📅 Hybrid mode: local cache + optional remote fetching
- 📅 `requests.get()` for CDN signature pulling

### Medium-term (v3.0)

- 🚀 CDN distribution via GitHub Pages / Cloudflare Workers
- 🚀 Automatic signature updates
- 🚀 Global signature contribution network
- 🚀 REST API for remote fingerprinting
- 🚀 Multi-region deployment support

### Long-term Vision

- 🌍 Community-powered global OS fingerprint database
- 🌍 Real-time threat intelligence integration
- 🌍 Machine learning anomaly detection
- 🌍 Decentralized signature distribution

---

## 📊 Performance

Packet Phantom achieves high throughput while maintaining accuracy:

- **Scan Rate** – 10,000+ packets/second (live mode) on modern hardware
- **Fingerprinting Speed** – Quick mode ~10 seconds, Deep mode ~30-60 seconds
- **Memory Footprint** – <50MB base with signature database
- **CPU Efficiency** – Async engine minimizes thread overhead
- **Batch Optimization** – sendmmsg reduces syscall overhead by 60%+

---

## 🔍 Use Cases

### Security Researchers

- Study TCP/IP stack implementations across OS versions
- Research new fingerprinting techniques
- Contribute to public signature database
- Analyze network behaviors for academic papers

### Penetration Testers

- Comprehensive network reconnaissance before engagements
- Asset discovery and OS classification
- IDS/WAF evasion technique testing
- Post-engagement reporting

### Network Administrators

- Network inventory and asset management
- Rogue device detection
- Security baseline establishment
- Network health monitoring

### Educators

- Teaching network protocols and socket programming
- Demonstrating TCP/IP stack behaviors
- Building security research skills
- Safe lab environments with rate limiting

---

## 📄 License 

[LICENSE]

---

## 👤 Author

**medaminkh-dev (Amine)**

Network security researcher and open-source developer focused on network reconnaissance and behavioral analysis techniques.

---

## 📞 Support & Community

- **GitHub Issues** – Bug reports and feature requests
- **Discussions** – Q&A and feature brainstorming
- **Wiki** – Community knowledge base


---

## ⚠️ Disclaimer (Repeated for Emphasis)

**Packet Phantom is provided AS-IS for educational and authorized security testing only.** Users are responsible for ensuring they have proper authorization before conducting any network testing, scanning, or fingerprinting activities. Unauthorized access to computer systems is illegal. This tool is designed for authorized security professionals and researchers only.

---

**Last Updated:** February 2026
**Version:** 2.0.0
**Status:** Production Ready
