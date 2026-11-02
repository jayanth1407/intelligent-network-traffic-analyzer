# Project 2 — Interview Preparation

## 60-second project introduction
"I developed an Intelligent Network Traffic Analyzer using Python and Streamlit. It analyzes packet metadata from CSV datasets or authorized PCAP captures. I used Scapy for basic packet parsing, Pandas for data processing and Plotly for traffic visualizations. The application summarizes TCP, UDP, DNS, ICMP, HTTP and HTTPS traffic and highlights suspicious patterns such as SYN-scan-like activity, unusually high DNS query volume and packet-rate bursts. It provides an investigation dashboard and downloadable reports. The detection is heuristic, so alerts require validation and are not treated as confirmed attacks."

## Architecture
PCAP/CSV -> Scapy parser or Pandas loader -> data validation -> metadata analytics
-> heuristic indicators -> severity labels -> Streamlit dashboard -> CSV/TXT exports

## Key concepts
- Packet: a formatted unit of data carried by a network.
- PCAP: a file format commonly used to store captured network packets.
- TCP: connection-oriented transport protocol.
- UDP: connectionless transport protocol.
- DNS: translates domain names to IP addresses.
- ICMP: network control and diagnostic messaging protocol.
- Port: logical endpoint associated with a transport service.
- SYN: TCP flag used to initiate a connection.
- SOC: Security Operations Center, where security events are monitored and investigated.
- False positive: benign activity incorrectly flagged as suspicious.

## Likely questions
1. What does your project do?
It analyzes packet metadata, visualizes traffic patterns and flags heuristic indicators that may deserve security investigation.

2. What is Wireshark?
Wireshark is a packet protocol analyzer used to inspect network traffic. My application provides a dashboard and simple event-level analytics; it is not a replacement for Wireshark's full protocol dissection.

3. What is a PCAP file?
A file containing captured network packets, often used for troubleshooting and security analysis.

4. Why did you use Scapy?
Scapy can read packet captures and extract protocol and header metadata in Python.

5. What is a TCP SYN?
A TCP control flag normally used to begin the connection handshake.

6. How do you identify possible port scanning?
The demo groups SYN-only TCP events by source IP and flags sources reaching at least 15 distinct destination ports. This is only a heuristic and can have false positives.

7. How do you identify unusual DNS activity?
The demo counts DNS query events per source IP and flags sources with at least 30 query events in the capture.

8. What is a false positive?
A normal event incorrectly flagged as suspicious. For example, a vulnerability scanner or monitoring tool may generate traffic that resembles a scan.

9. Does the system block suspicious traffic?
No. It is a passive analysis prototype. It does not block traffic or change network devices.

10. Can it analyze real network traffic?
It can parse authorized PCAP captures containing supported packet metadata. Results depend on what the capture contains and where it was collected.

11. What are the limitations?
The heuristics use fixed demonstration thresholds, parsing is basic, encrypted payloads are not inspected, and capture visibility affects detection. Alerts need contextual validation.

12. How would you improve it?
Add configurable baselines, richer protocol dissection, time-window tuning, alert acknowledgement, user authentication, audit logging and integration with approved SIEM/NOC telemetry.

## Demo checklist
- [ ] Start app with bundled sample traffic.
- [ ] Explain protocol distribution.
- [ ] Show traffic timeline and top source IPs.
- [ ] Explain one scan-like indicator and one DNS-volume indicator.
- [ ] Open packet explorer.
- [ ] Export CSV and security report.
- [ ] State clearly that bundled data is synthetic and thresholds are illustrative.
