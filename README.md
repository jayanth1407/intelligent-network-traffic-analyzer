# Intelligent Network Traffic Analyzer & Intrusion Monitor

A defensive Python/Streamlit application for packet metadata analysis, protocol analytics and heuristic suspicious-pattern detection.

## Features
- Bundled synthetic packet-event dataset for an immediate demo.
- Upload packet-event CSV files.
- Upload PCAP/PCAPNG captures and parse basic IP, TCP, UDP, ICMP and DNS metadata using Scapy.
- Protocol distribution, packet-rate timeline, top talkers and traffic volume charts.
- Heuristic indicators for possible TCP SYN port-scan patterns, high DNS query volume and packet-rate bursts.
- Alert classification and packet-level investigation table.
- CSV export and text investigation report.
- Filters by protocol, severity and source IP.

## Run on Windows / VS Code
Python 3.10+ recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks virtual environment activation, run:
```powershell
py -m pip install -r requirements.txt
py -m streamlit run app.py
```

Open the local URL shown by Streamlit, normally `http://localhost:8501`.

## Data sources
### Bundled sample
`data/sample_packet_events.csv` includes 2,400 synthetic packet-event rows with intentionally injected examples of scan-like SYN traffic and high DNS query volume. It is synthetic and not captured from a real network.

### CSV upload
Required columns:
`timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_length, tcp_flags, dns_query`

### PCAP upload
Scapy parses basic IP/IPv6, TCP, UDP, ICMP and DNS metadata. Install `requirements.txt` to enable PCAP support. Only inspect captures you own or are authorized to analyze.

## Detection logic
- Possible SYN scan: a source IP sends SYN-only TCP packets to at least 15 distinct destination ports in the selected capture.
- High DNS query volume: at least 30 DNS query events from one source in the capture.
- Packet-rate burst: at least 100 packet events from one source in a one-minute bucket.
- High severity is assigned to possible SYN scan events; Medium to DNS-volume and packet-rate burst indicators.

These thresholds are illustrative heuristics, not universal security rules. False positives are possible. Validate with full capture context and other authorized telemetry.

## Architecture
Packet capture / CSV -> parsing and validation -> packet metadata normalization
-> heuristic analysis -> Streamlit / Plotly dashboard -> CSV and text report

## Limitations and safe use
- This tool is a monitoring and analysis prototype; it does not block traffic, exploit hosts, scan networks or modify devices.
- PCAP parsing extracts basic metadata only; it is not full protocol dissection.
- Detection depends on capture point, visibility, sampling and network context.
- An alert is an investigation lead, not proof of compromise.
- Use only captures you own or have explicit permission to inspect.

## Suggested demo
1. Run with the bundled sample traffic.
2. Show protocol distribution and packet-rate timeline.
3. Open Threat indicators and explain the synthetic scan-like pattern and DNS burst.
4. Use Packet explorer to inspect event metadata.
5. Download CSV and the investigation report.
6. Explain how a SOC analyst would validate an alert using firewall, endpoint, DNS and NOC telemetry.
