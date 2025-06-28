import streamlit as st
import requests
import re

def extract_sender_ips(email_headers):
    ip_pattern = re.compile(r'\[([\d\.]+)\]')
    return list(set(ip_pattern.findall(email_headers)))

def check_tor(ip):
    response = requests.get("https://check.torproject.org/exit-addresses")
    return 'Tor Exit Node' if ip in response.text else 'Non-Tor/VPN unknown'

def ip_geolocation(ip):
    res = requests.get(f"http://ip-api.com/json/{ip}")
    return res.json() if res.ok else {}

st.title("📧 Email Header Analyzer")

headers = st.text_area("Paste Email Headers Here:")

if st.button("Analyze"):
    ips = extract_sender_ips(headers)
    if ips:
        for ip in ips:
            st.subheader(f"Analysis for IP: {ip}")
            geo = ip_geolocation(ip)
            st.json(geo)
            tor_status = check_tor(ip)
            st.write(f"VPN/Tor Check: {tor_status}")
    else:
        st.error("No IP addresses found in headers!")
