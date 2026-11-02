from pathlib import Path
from datetime import datetime
import io
import ipaddress
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

st.set_page_config(page_title="Network Traffic Intelligence", page_icon="🛡️", layout="wide")

REQUIRED = ["timestamp","src_ip","dst_ip","protocol","src_port","dst_port","packet_length","tcp_flags","dns_query"]
PROTO_COLORS = {"TCP":"#38bdf8","UDP":"#a78bfa","DNS":"#fbbf24","ICMP":"#fb7185","HTTP":"#34d399","HTTPS":"#60a5fa","Other":"#94a3b8"}

st.markdown("""
<style>
.stApp {background:#0a1220;}
[data-testid="stMetric"] {background:linear-gradient(145deg,#17243a,#111b2d);border:1px solid #2b405d;padding:15px;border-radius:13px;}
[data-testid="stMetricLabel"] {color:#a9bad1;}
[data-testid="stMetricValue"] {color:#f4f8ff;}
.hero {background:linear-gradient(110deg,#132b49,#18243a 60%,#1b2c43);border:1px solid #2a486c;border-radius:16px;padding:20px 24px;margin-bottom:18px;}
.hero h1 {margin:0;color:#f4f8ff;font-size:1.85rem;}
.hero p {margin:7px 0 0;color:#b8c9df;}
.note {color:#9eb0c7;font-size:.84rem;}
</style>
""",unsafe_allow_html=True)

st.markdown("""
<div class="hero">
<h1>🛡️ Network Traffic Intelligence & Intrusion Monitor</h1>
<p>Packet analytics · Protocol inspection · Suspicious-pattern detection · Security reporting</p>
</div>
""",unsafe_allow_html=True)

def classify_protocol(pkt):
    if pkt.haslayer(DNS): return "DNS"
    if pkt.haslayer(TCP):
        port = int(pkt[TCP].dport)
        if port == 80: return "HTTP"
        if port == 443: return "HTTPS"
        return "TCP"
    if pkt.haslayer(UDP): return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    return "Other"

def parse_pcap(file_obj):
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed. Install requirements.txt to analyze PCAP files.")
    packets = rdpcap(file_obj)
    rows = []
    for pkt in packets:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            continue
        proto = classify_protocol(pkt)
        sport = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (int(pkt[UDP].sport) if pkt.haslayer(UDP) else 0)
        dport = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (int(pkt[UDP].dport) if pkt.haslayer(UDP) else 0)
        flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else ""
        query = ""
        if pkt.haslayer(DNS) and pkt[DNS].qd and pkt[DNS].qr == 0:
            try: query = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            except Exception: query = ""
        rows.append({
            "timestamp": datetime.fromtimestamp(float(pkt.time)),
            "src_ip":src,"dst_ip":dst,"protocol":proto,
            "src_port":sport,"dst_port":dport,
            "packet_length":int(len(pkt)),"tcp_flags":flags,"dns_query":query
        })
    return pd.DataFrame(rows)

def normalize_data(data):
    missing = [c for c in REQUIRED if c not in data.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    d = data.copy()
    d["timestamp"] = pd.to_datetime(d["timestamp"],errors="coerce")
    for c in ["src_port","dst_port","packet_length"]:
        d[c] = pd.to_numeric(d[c],errors="coerce")
    d = d.dropna(subset=["timestamp","src_ip","dst_ip","protocol","packet_length"])
    d["protocol"] = d["protocol"].astype(str).str.upper()
    d["tcp_flags"] = d["tcp_flags"].fillna("").astype(str)
    d["dns_query"] = d["dns_query"].fillna("").astype(str)
    d["src_port"] = d["src_port"].fillna(0).astype(int)
    d["dst_port"] = d["dst_port"].fillna(0).astype(int)
    d["packet_length"] = d["packet_length"].clip(lower=0).astype(int)
    if len(d)<1:
        raise ValueError("No valid packet records found.")
    return d.sort_values("timestamp").reset_index(drop=True)

def analyze_traffic(d):
    d = d.copy()
    # SYN-only indicators, used as a heuristic rather than a conclusion.
    d["is_syn"] = d["tcp_flags"].str.contains("S",case=False,regex=False) & ~d["tcp_flags"].str.contains("A",case=False,regex=False)
    d["is_dns_query"] = (d["protocol"]=="DNS") & (d["dns_query"].str.len()>0)
    d["is_private_source"] = d["src_ip"].apply(lambda x: ipaddress.ip_address(x).is_private if is_ip(x) else False)
    # Source IP -> distinct destination ports in the selected capture.
    port_counts = d[d["is_syn"]].groupby("src_ip")["dst_port"].nunique()
    scan_sources = set(port_counts[port_counts>=15].index)
    # DNS query volume per source
    dns_counts = d[d["is_dns_query"]].groupby("src_ip").size()
    dns_burst_sources = set(dns_counts[dns_counts>=30].index)
    # Packet-rate burst per source: max packets in any one-minute bucket.
    minute = d.assign(minute=d["timestamp"].dt.floor("min")).groupby(["src_ip","minute"]).size()
    burst_sources = set(minute[minute>=100].index.get_level_values(0))
    d["potential_port_scan"] = d["src_ip"].isin(scan_sources) & d["is_syn"]
    d["dns_volume_flag"] = d["src_ip"].isin(dns_burst_sources) & d["is_dns_query"]
    d["traffic_burst_flag"] = d["src_ip"].isin(burst_sources)
    d["alert_reason"] = ""
    d.loc[d["potential_port_scan"],"alert_reason"] = "Possible TCP SYN port-scan pattern"
    d.loc[d["dns_volume_flag"],"alert_reason"] = "High DNS query volume"
    d.loc[d["traffic_burst_flag"],"alert_reason"] = d.loc[d["traffic_burst_flag"],"alert_reason"].apply(
        lambda x: (x+"; " if x else "")+"High packet-rate burst"
    )
    d["severity"] = np.select(
        [
            d["potential_port_scan"],
            d["dns_volume_flag"] | d["traffic_burst_flag"]
        ],
        ["High","Medium"],
        default="Normal"
    )
    return d, scan_sources, dns_burst_sources, burst_sources

def is_ip(value):
    try: ipaddress.ip_address(str(value)); return True
    except ValueError: return False

def sample_data():
    return pd.read_csv(Path(__file__).parent/"data"/"sample_packet_events.csv")

with st.sidebar:
    st.header("⚙️ Capture & analysis")
    source_mode = st.radio("Data source",["Bundled sample traffic","Upload CSV","Upload PCAP"])
    upload = None
    if source_mode=="Upload CSV":
        upload = st.file_uploader("Upload packet-events CSV",type=["csv"])
    elif source_mode=="Upload PCAP":
        upload = st.file_uploader("Upload packet capture",type=["pcap","pcapng","cap"])
        if not SCAPY_AVAILABLE:
            st.warning("Scapy is unavailable. Install project requirements to enable PCAP parsing.")
    st.divider()
    st.caption("All detection rules are heuristic indicators for investigation, not proof of compromise.")

try:
    if source_mode=="Bundled sample traffic":
        raw = sample_data()
    elif upload is None:
        st.info("Upload a CSV or PCAP file, or select Bundled sample traffic.")
        st.stop()
    elif source_mode=="Upload CSV":
        raw = pd.read_csv(upload)
    else:
        raw = parse_pcap(upload)
    data = normalize_data(raw)
except Exception as e:
    st.error(f"Could not load traffic data: {e}")
    st.stop()

data, scan_sources, dns_sources, burst_sources = analyze_traffic(data)

with st.sidebar:
    st.subheader("Investigation filters")
    protocols = ["All"] + sorted(data["protocol"].unique().tolist())
    selected_protocol = st.selectbox("Protocol",protocols)
    severities = ["All","High","Medium","Normal"]
    selected_severity = st.selectbox("Alert classification",severities)
    src_options = ["All"] + sorted(data["src_ip"].astype(str).unique().tolist())
    selected_src = st.selectbox("Source IP",src_options)
    min_time, max_time = data["timestamp"].min(), data["timestamp"].max()
    st.caption(f"Capture range: {min_time} to {max_time}")

filtered = data.copy()
if selected_protocol!="All": filtered=filtered[filtered["protocol"]==selected_protocol]
if selected_severity!="All": filtered=filtered[filtered["severity"]==selected_severity]
if selected_src!="All": filtered=filtered[filtered["src_ip"]==selected_src]
if filtered.empty:
    st.warning("No packets match the selected filters.")
    st.stop()

total_packets = len(filtered)
total_bytes = int(filtered["packet_length"].sum())
unique_sources = filtered["src_ip"].nunique()
unique_destinations = filtered["dst_ip"].nunique()
alert_packets = int((filtered["severity"]!="Normal").sum())
high_alerts = int((filtered["severity"]=="High").sum())

st.subheader("Security operations overview")
a,b,c,d,e,f = st.columns(6)
a.metric("Packets analyzed",f"{total_packets:,}")
b.metric("Traffic volume",f"{total_bytes/1024/1024:.2f} MB")
c.metric("Source IPs",f"{unique_sources:,}")
d.metric("Destination IPs",f"{unique_destinations:,}")
e.metric("Alert packets",f"{alert_packets:,}")
f.metric("High alerts",f"{high_alerts:,}")

tab1,tab2,tab3,tab4 = st.tabs(["📈 Traffic analytics","🚨 Threat indicators","🔎 Packet explorer","📄 Reports & exports"])

with tab1:
    left,right=st.columns(2)
    with left:
        st.markdown("#### Protocol distribution")
        p = filtered.groupby("protocol",as_index=False).size().rename(columns={"size":"packets"})
        fig=px.pie(p,names="protocol",values="packets",hole=.58,color="protocol",color_discrete_map=PROTO_COLORS)
        fig.update_layout(height=350,margin=dict(l=10,r=10,t=20,b=10))
        st.plotly_chart(fig,use_container_width=True)
    with right:
        st.markdown("#### Packet volume over time")
        timeline=filtered.set_index("timestamp").resample("1min").size().rename("packets").reset_index()
        fig=px.area(timeline,x="timestamp",y="packets",labels={"timestamp":"Time","packets":"Packets/min"})
        fig.update_layout(height=350,margin=dict(l=10,r=10,t=20,b=10))
        st.plotly_chart(fig,use_container_width=True)
    left,right=st.columns(2)
    with left:
        st.markdown("#### Top source IPs")
        top=filtered.groupby("src_ip",as_index=False).size().nlargest(12,"size").rename(columns={"size":"packets"})
        fig=px.bar(top,x="packets",y="src_ip",orientation="h")
        fig.update_layout(height=360,margin=dict(l=10,r=10,t=20,b=10),yaxis={"categoryorder":"total ascending"})
        st.plotly_chart(fig,use_container_width=True)
    with right:
        st.markdown("#### Protocol and traffic volume")
        proto=filtered.groupby("protocol",as_index=False).agg(packets=("packet_length","count"),bytes=("packet_length","sum"))
        fig=px.bar(proto,x="protocol",y="bytes",color="protocol",color_discrete_map=PROTO_COLORS)
        fig.update_layout(height=360,margin=dict(l=10,r=10,t=20,b=10),showlegend=False)
        st.plotly_chart(fig,use_container_width=True)

with tab2:
    st.markdown("#### Potential suspicious activity")
    alert_data=filtered[filtered["severity"]!="Normal"].copy()
    if alert_data.empty:
        st.success("No heuristic alerts in the current selection.")
    else:
        summary=alert_data.groupby(["src_ip","severity","alert_reason"],as_index=False).agg(
            packets=("timestamp","count"),destinations=("dst_ip","nunique"),first_seen=("timestamp","min"),last_seen=("timestamp","max")
        ).sort_values(["severity","packets"],ascending=[True,False])
        st.dataframe(summary,use_container_width=True,hide_index=True)
        st.markdown("#### Alert event details")
        st.dataframe(alert_data[["timestamp","severity","src_ip","dst_ip","protocol","src_port","dst_port","packet_length","alert_reason"]].head(500),
                     use_container_width=True,hide_index=True)
    st.caption("High = possible SYN scan heuristic. Medium = high DNS volume or packet-rate burst. Investigate with capture context; these are not confirmed incidents.")

with tab3:
    st.markdown("#### Packet-level event explorer")
    st.dataframe(filtered[["timestamp","src_ip","dst_ip","protocol","src_port","dst_port","packet_length","tcp_flags","dns_query","severity","alert_reason"]].head(1000),
                 use_container_width=True,hide_index=True)
    st.caption("The bundled data is synthetic. Uploaded PCAP parsing extracts basic IP/TCP/UDP/DNS metadata only.")

with tab4:
    st.markdown("#### Export investigation results")
    csv_bytes=filtered.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download filtered packet analysis CSV",data=csv_bytes,
                       file_name="network_traffic_analysis.csv",mime="text/csv")
    report=f"""NETWORK TRAFFIC INTELLIGENCE REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
================================================
Packets analyzed: {total_packets}
Total bytes: {total_bytes}
Unique source IPs: {unique_sources}
Unique destination IPs: {unique_destinations}
Potential alert packets: {alert_packets}
High severity packets: {high_alerts}

Potential scan sources: {', '.join(sorted(scan_sources)) or 'None'}
High DNS volume sources: {', '.join(sorted(dns_sources)) or 'None'}
Traffic burst sources: {', '.join(sorted(burst_sources)) or 'None'}

Detection methodology:
- SYN-only packets grouped by source IP and distinct destination ports.
- DNS query volume grouped by source IP.
- Packet-rate bursts grouped into one-minute windows.
- Heuristic severity classification.

Limitations:
- Heuristic indicators are not proof of compromise.
- Results depend on capture visibility and sampling.
- This prototype does not block traffic or change network devices.
- Validate alerts with endpoint, firewall, DNS and NOC telemetry.
"""
    st.download_button("⬇️ Download security investigation report",data=report.encode(),
                       file_name="network_security_report.txt",mime="text/plain")

st.divider()
st.markdown('<p class="note">Defensive monitoring prototype. Use only packet captures you own or are authorized to inspect. Detection is heuristic and does not automatically block or modify network traffic.</p>',unsafe_allow_html=True)
