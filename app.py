import streamlit as st
import requests
import re

def extract_sender_ips(email_headers):
    ip_pattern = re.compile(r'\[([\d\.]+)\]')
    return list(set(ip_pattern.findall(email_headers)))

# Fetches Tor exit nodes with details
@st.cache_data(ttl=3600)
def get_tor_exit_nodes():
    response = requests.get("https://check.torproject.org/exit-addresses")
    exit_nodes = {}
    if response.ok:
        entries = response.text.split('ExitNode ')
        for entry in entries[1:]:
            lines = entry.splitlines()
            node_id = lines[0]
            published = lines[1].split(" ", 1)[1]
            last_status = lines[2].split(" ", 1)[1]
            exit_address = lines[3].split(" ", 1)[1]
            exit_nodes[exit_address] = {
                "node_id": node_id,
                "published": published,
                "last_status": last_status,
                "exit_address": exit_address
            }
    return exit_nodes

def ip_geolocation(ip):
    res = requests.get(f"http://ip-api.com/json/{ip}")
    return res.json() if res.ok else {}

# Streamlit UI
st.title("📧 Enhanced Email Header Analyzer")

headers = st.text_area("Paste Email Headers Here:", height=300)

if st.button("Analyze"):
    ips = extract_sender_ips(headers)
    tor_nodes = get_tor_exit_nodes()

    if ips:
        for ip in ips:
            st.subheader(f"IP Address: {ip}")

            # Geolocation Info
            geo = ip_geolocation(ip)
            st.write("**Geolocation Information:**")
            st.json(geo)

            # Tor/VPN Check
            if ip in tor_nodes:
                st.write("🚩 **Tor Exit Node Detected!**")
                st.write("**Tor Node Information:**")
                st.json(tor_nodes[ip])
            else:
                st.write("✅ **Not a known Tor Exit Node.**")

    else:
        st.error("No IP addresses found in headers!")
