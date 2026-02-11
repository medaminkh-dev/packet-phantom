"""
Educational Mode for Packet Phantom God OS Fingerprinting.

This module provides learner-friendly explanations and step-by-step
walkthroughs of OS fingerprinting concepts and results.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class Lesson:
    """Represents an educational lesson."""
    title: str
    content: str
    code_example: Optional[str]
    try_yourself: Optional[str]
    related_probe: str


class EducationalExplainer:
    """Generate educational content for OS fingerprinting."""
    
    def __init__(self):
        self.lessons = self._load_lessons()
    
    def _load_lessons(self) -> Dict[str, Lesson]:
        """Load all educational lessons."""
        return {
            'tcp_syn_80': Lesson(
                title="TCP SYN Probe - The Handshake Starter",
                content="""When we send a TCP SYN packet to port 80, we're initiating 
a TCP three-way handshake. The target responds with SYN-ACK if the port is open.
This response reveals the operating system's TCP stack behavior - specifically:
- TTL (Time to Live): How many hops the response can survive
- Window Size: The buffer size for receiving data
- TCP Options: Like MSS (Maximum Segment Size) and SACK permitted""",
                code_example="""# What we're sending:
packet = IP(dst=target)/TCP(dport=80, flags='S', options=[('MSS', 1460)])

# What we look for in response:
# - TTL: Usually 64 for Linux, 128 for Windows
# - Window: Often 5840 (Linux) or 65535 (Windows)
# - Options: Timestamp, SACK, etc.""",
                try_yourself="Try scanning different OS types and compare their TTL values:\n"
                            "- Linux VMs: TTL ~64\n"
                            "- Windows VMs: TTL ~128\n"
                            "- Cisco routers: TTL ~255",
                related_probe='tcp_syn_80'
            ),
            'icmp_echo': Lesson(
                title="ICMP Echo Request - Network Latency Measurement",
                content="""ICMP echo request (ping) measures round-trip time and reveals:
- Network latency to the target
- Whether the target is reachable
- TTL behavior in ICMP responses (often different from TCP TTL)
- Response consistency (jitter)""",
                code_example="""# Send ICMP echo
packet = IP(dst=target, ttl=64)/ICMP(type=8, code=0, id=1234)/b'DATA'

# Analyze:
# - Response time tells us network distance
# - Consistent responses = stable network
# - Inconsistent = possible load balancing or congestion""",
                try_yourself="Measure jitter on different network types:\n"
                            "- Local network: < 1ms jitter\n"
                            "- Internet: 5-50ms jitter\n"
                            "- Satellite: 500ms+ jitter",
                related_probe='icmp_echo'
            ),
            'ttl_analysis': Lesson(
                title="TTL Analysis - Guessing the OS Family",
                content="""TTL (Time to Live) is a hop counter that prevents packets 
from circulating forever. Different OS families use different default TTLs:
- Linux/Unix: 64
- Windows: 128  
- Cisco: 255
- Some firewalls: 32

But wait! This isn't reliable - VMs often inherit host TTL, and some OS 
implementations are configurable. That's why we use multiple dimensions!""",
                code_example="""# Observed TTL → Guessed hops
observed_ttl = 54
# Assuming typical 64 initial TTL:
hops = 64 - observed_ttl  # = 10 hops away

# But the target might not use 64:
# Linux: ~64, Windows: ~128, Cisco: ~255
# We combine with other clues (window size, options)""",
                try_yourself="Check what happens to TTL through routers:\n"
                            "1. Ping your default gateway\n"
                            "2. Ping 8.8.8.8\n"
                            "3. Compare the TTL differences",
                related_probe='tcp_syn_80'
            ),
            'tcp_window_size': Lesson(
                title="TCP Window Size - Buffer Insights",
                content="""The TCP Window Size tells us about the receive buffer of the
operating system. This is one of the most distinctive fingerprints:
- 5840: Classic Linux kernel (pre-2.6)
- 65535: Windows with window scaling enabled
- 14600: Modern Linux with fast open
- 32768: Older BSD systems

Window size changes between OS versions and can reveal virtualization!""",
                code_example="""# Common window sizes and their meanings:
WINDOW_SIZES = {
    5840: "Classic Linux",
    65535: "Windows (w/ scaling)",
    14600: "Modern Linux",
    32768: "BSD variants",
    4128: "Windows XP era",
    8192: "Generic/small buffer"
}""",
                try_yourself="Test different targets and record their window sizes:\n"
                            "- Virtual machines\n"
                            "- Cloud instances\n"
                            "- Physical servers\n"
                            "- Network devices",
                related_probe='tcp_syn_80'
            ),
            'tcp_options': Lesson(
                title="TCP Options - Stack Capabilities",
                content="""TCP Options are additional features that OS stacks can support.
The order and presence of options is highly distinctive:
- MSS (Maximum Segment Size): Fragmentation prevention
- Window Scaling: Large buffer support
- SACK (Selective ACK): Efficient loss recovery
- Timestamps: Round-trip measurement
- EOL (End of List): Option terminator

Different OS stacks include different options in different orders!""",
                code_example="""# Common option patterns:
LINUX_TYPICAL = ['MSS', 'Timestamp', 'SACK', 'Window Scaling', 'EOL']
WINDOWS_TYPICAL = ['MSS', 'Window Scaling', 'SACK', 'Timestamp', 'EOL']
FREEBSD_TYPICAL = ['MSS', 'Timestamp', 'SACK', 'EOL']""",
                try_yourself="Compare option lists from different OS:\n"
                            "1. Scan a Linux server\n"
                            "2. Scan a Windows server\n"
                            "3. Note the differences in option order",
                related_probe='tcp_syn_80'
            ),
            'tcp_syn_ack': Lesson(
                title="SYN-ACK Response - The Fingerprint Goldmine",
                content="""The SYN-ACK response packet is where most OS fingerprinting 
information comes from. It's the target's first response in the TCP handshake,
and it contains:
- Initial TTL value (set by OS)
- Default window size (OS-specific)
- TCP options (stack features)
- DF (Don't Fragment) flag behavior
- ECN (Explicit Congestion Notification) support

These combine to create a unique fingerprint!""",
                code_example="""# Analyzing SYN-ACK response:
response_fields = {
    'ttl': observed_ttl,
    'window': window_size,
    'options': option_list,
    'df': dont_fragment_flag,
    'mss': maximum_segment_size
}

# Each field adds to fingerprint confidence
# Multiple matching fields = higher confidence""",
                try_yourself="Create a fingerprint for your own system:\n"
                            "1. Run a fingerprint scan against localhost\n"
                            "2. Record all SYN-ACK fields\n"
                            "3. Compare with documentation",
                related_probe='tcp_syn_80'
            ),
            'udp_closed_port': Lesson(
                title="UDP Closed Port Response - ICMP Insights",
                content="""When we send a UDP packet to a closed port, the target
should respond with an ICMP Port Unreachable message. The behavior here
reveals:
- Firewall presence (blocked ICMP = filtered)
- Rate limiting (how many ICMP messages allowed)
- ICMP rate limiting reveals network policy
- Some OS include specific data in ICMP responses""",
                code_example="""# Expected behavior for closed UDP port:
# 1. Send UDP packet to closed port
# 2. Target sends ICMP type=3, code=3 (Port Unreachable)
# 3. ICMP contains original UDP header + 8 bytes payload

# No response =可能被防火墙阻止
# Rate limited responses =企业网络
# Immediate response =本地系统""",
                try_yourself="Test UDP fingerprinting:\n"
                            "1. Send UDP to closed port\n"
                            "2. Check for ICMP response\n"
                            "3. Measure response time",
                related_probe='udp_closed_port'
            ),
            'tcp_rst': Lesson(
                title="TCP RST - Closed Port Behavior",
                content="""When connecting to a closed TCP port, the target sends
a RST (Reset) packet. The RST behavior varies by OS:
- RST flags and data
- TCP sequence number handling
- RST rate limiting
- Some OS send payload in RST (unusual!)""",
                code_example="""# RST packet characteristics:
# - Flags: RST only
# - Sequence: ACK of received sequence
# - Window: Usually 0
# - Some embedded systems send data in RST""",
                try_yourself="Compare RST responses:\n"
                            "1. Scan a closed port on Linux\n"
                            "2. Scan a closed port on Windows\n"
                            "3. Compare RST packet details",
                related_probe='tcp_rst'
            )
        }
    
    def explain_probe(self, probe_name: str) -> Optional[Lesson]:
        """Get educational content for a probe."""
        return self.lessons.get(probe_name)
    
    def explain_fingerprint_dimension(self, dimension: str, value: Any) -> str:
        """Explain what a fingerprint dimension means."""
        explanations = {
            'ttl': lambda v: f"""TTL (Time to Live) of {v} suggests the target is 
using a typical {self._guess_os_from_ttl(v)} stack. TTL decrements 
by 1 at each router hop.""",
            'window_size': lambda v: f"""TCP Window Size of {v} indicates the 
receive buffer. Common values:
- 5840: Classic Linux
- 65535: Windows with scaling
- 14600: Modern systems""",
            'options': lambda v: f"""TCP Options ({v}) reveal the stack's capabilities:
- Timestamp: Most modern OS
- SACK: Selective Acknowledgment support
- MSS: Maximum Segment Size negotiation""",
            'mss': lambda v: f"""MSS (Maximum Segment Size) of {v} tells us 
the maximum TCP payload the target can receive without fragmentation.
Common values: 1460 (Ethernet), 1400 (VPN), 536 (older networks)""",
            'df_bit': lambda v: f"""Don't Fragment flag is {'set' if v else 'not set'}.
This affects how the OS handles packets larger than MTU.""",
            'jitter': lambda v: f"""Jitter of {v:.2f}ms indicates timing consistency.
{'Low jitter = stable network' if v < 5 else 'Higher jitter = variable latency'}""",
            'response_time': lambda v: f"""Response time of {v:.2f}ms suggests
{'local network' if v < 10 else 'remote/internet connection'}."""
        }
        
        key = str(dimension).lower().replace(' ', '_')
        if key in explanations:
            return explanations[key](value)
        return f"Analysis of {dimension} with value {value}: Characteristic fingerprint pattern."
    
    def _guess_os_from_ttl(self, ttl: int) -> str:
        """Guess OS family from TTL value."""
        if ttl <= 32:
            return "embedded/Firewall"
        elif ttl <= 64:
            return "Linux/Unix-like"
        elif ttl <= 96:
            return "Linux VM on Windows host"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 192:
            return "Network device (Cisco)"
        else:
            return "Unusual/Unknown"
    
    def generate_probe_explanation(self, 
                                  probe_name: str,
                                  response: Dict[str, Any],
                                  is_correct: bool) -> str:
        """Generate step-by-step explanation of probe analysis."""
        lesson = self.lessons.get(probe_name)
        if not lesson:
            return f"No educational content available for {probe_name}"
        
        explanation = f"""
## {lesson.title}

{lesson.content}

### What We Observed:
"""
        for key, value in response.items():
            explanation += f"- {key}: {value}\n"
        
        explanation += """
### Understanding the Results:

"""
        if is_correct:
            explanation += """**Great match!** This response closely matches 
known patterns for this operating system. Combined with other probes, 
we can be highly confident in the identification."""
        else:
            explanation += """**Partial match** - The response has some 
characteristics matching expected patterns but also differences. 
Forensic mode would provide more detailed analysis."""
        
        explanation += f"""

### Try It Yourself:

{lesson.try_yourself}

### Code Example:

```
{lesson.code_example}
```
"""
        return explanation
    
    def get_summary_for_learner(self, 
                              detected_os: str,
                              confidence: float,
                              key_fingerprints: List[Dict[str, Any]]) -> str:
        """Generate a learner-friendly summary."""
        confidence_desc = "very high" if confidence > 90 else "high" if confidence > 70 else "moderate" if confidence > 50 else "low"
        
        summary = f"""
# OS Detection Result

## Detected Operating System
**{detected_os}** ({confidence:.0f}% confidence - {confidence_desc} confidence level)

## What Does This Mean?

The system has analyzed network responses from the target and matched them
against known fingerprint patterns. The confidence level tells us how certain
we are about this identification.

## Key Fingerprints Found

The following characteristics were observed and matched:

"""
        
        for i, fp in enumerate(key_fingerprints, 1):
            name = fp.get('name', 'Unknown')
            value = fp.get('value', 'N/A')
            explanation = self.explain_fingerprint_dimension(name, value)
            # Clean up markdown for table
            explanation = explanation.replace('**', '')
            explanation = explanation.replace('\n', ' ')
            explanation = ' '.join(explanation.split())
            if len(explanation) > 100:
                explanation = explanation[:97] + '...'
            
            summary += f"{i}. **{name}**: {value}\n   - {explanation}\n"
        
        summary += f"""

## Learning Path

Want to learn more about OS fingerprinting? Here's what to explore next:

### Beginner Topics
- [x] TCP three-way handshake
- [x] ICMP protocol
- [x] TTL and network hops

### Intermediate Topics
- [ ] TCP options and their meanings
- [ ] Window scaling and buffers
- [ ] ICMP rate limiting

### Advanced Topics
- [ ] Passive OS fingerprinting
- [ ] Virtualization detection
- [ ] Firewall identification

## Practice Suggestions

1. **Scan your own systems** - Try fingerprinting different VMs and compare results
2. **Cloud vs Physical** - Compare cloud instances with physical servers
3. **Different OS versions** - See how fingerprint changes between versions
4. **Network devices** - Try fingerprinting routers and switches

---
*Generated by Packet Phantom God Educational Mode*
"""
        return summary
    
    def get_probe_sequence_explanation(self) -> str:
        """Explain the typical probe sequence."""
        return """
# Understanding the Probe Sequence

OS fingerprinting uses multiple probes to build a complete picture:

## 1. TCP SYN Probe (Port 80/443)
Sends a SYN packet to start TCP handshake. Target responds with SYN-ACK
containing TTL, window size, and TCP options.

## 2. ICMP Echo Probe (Ping)
Sends ICMP echo request. Target responds with ICMP echo reply.
Measures response time and TTL behavior.

## 3. TCP RST Probe (Closed Port)
Sends SYN to closed port. Target should respond with RST.
Analyzes RST packet characteristics.

## 4. UDP Probe (Closed Port)
Sends UDP to closed port. Target should respond with ICMP Port Unreachable.
Tests ICMP rate limiting and firewall behavior.

## 5. TCP ACK Probe
Sends ACK to open port. Used to test firewall stateful inspection.
Responses indicate firewall filtering rules.

## Why Multiple Probes?

No single probe is definitive. Each adds confidence to our identification:

- **D1 (Static TCP)**: Base fingerprint from SYN-ACK
- **D2 (TCP Behavior)**: How stack handles multiple probes
- **D3 (Temporal)**: Timing patterns reveal network behavior
- **D4 (ICMP)**: ICMP response diversity
- **D5 (Error Handling)**: How errors are handled
- **D6 (UDP)**: UDP/ICMP patterns
- **D7 (TLS)**: TLS handshake fingerprint
- **D8 (Hardware)**: Virtualization/physical detection

By combining all dimensions, we achieve accurate OS identification!
"""
    
    def get_glossary(self) -> str:
        """Get a glossary of terms used in fingerprinting."""
        return """
# OS Fingerprinting Glossary

## Basic Terms

**TTL (Time to Live)**: A hop counter that limits packet lifetime.
Decrements by 1 at each router. Default values vary by OS.

**MSS (Maximum Segment Size)**: Largest TCP payload without fragmentation.
Usually 1460 on Ethernet networks.

**Window Size**: TCP receive buffer size. Highly OS-specific.

**SYN/ACK**: Second packet in TCP three-way handshake.
Contains key fingerprinting information.

**RST (Reset)**: TCP control packet indicating connection termination.

## Advanced Terms

**Jitter**: Variation in packet arrival time. High jitter indicates
unstable network conditions.

**TCP Options**: Additional TCP header features like timestamps,
SACK, window scaling, etc.

**ICMP Type/Code**: Identifies ICMP message purpose.
Type 3, Code 3 = Port Unreachable.

**TCP Sequence Number**: Incremental number tracking data flow.
Initial sequence number patterns can be OS-specific.

**MTU (Maximum Transmission Unit)**: Largest packet size on network path.
Affects fragmentation behavior.

## Fingerprinting Dimensions

**D1 - Static TCP**: TCP SYN-ACK response analysis
**D2 - TCP Behavior**: Response patterns under load
**D3 - Temporal**: Timing and jitter analysis
**D4 - ICMP**: ICMP response patterns
**D5 - Error Handling**: Error response behavior
**D6 - UDP**: UDP/ICMP interaction patterns
**D7 - TLS**: TLS handshake fingerprinting
**D8 - Hardware**: Virtualization detection
"""
