import streamlit as st
import requests
import re

# ----------------- Utility Functions -----------------
def extract_sender_ips(email_headers):
    ip_pattern = re.compile(r'\[([\d\.]+)\]')
    return list(set(ip_pattern.findall(email_headers)))

def extract_user_agents(email_headers):
    user_agent_lines = re.findall(r"(User-Agent|X-Mailer): (.+)", email_headers, re.IGNORECASE)
    return [f"{key}: {value}" for key, value in user_agent_lines]

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

# ----------------- Cavalier OSINT Integration -----------------
def cavalier_email_osint(email):
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
    params = {"email": email}
    response = requests.get(url, params=params)
    if response.ok:
        return response.json()
    else:
        return {"error": response.text}

def cavalier_username_osint(username):
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
    params = {"username": username}
    response = requests.get(url, params=params)
    if response.ok:
        return response.json()
    else:
        return {"error": response.text}

# ----------------- Streamlit UI -----------------
st.set_page_config(page_title="Email Threat Analyzer", page_icon="📧")
st.title("📧 Enhanced Email Threat Analyzer")
st.markdown("Analyze email headers, extract IPs, check for Tor usage, and run deeper OSINT checks.")

headers = st.text_area("📥 Paste Email Headers Here:", height=300)

with st.expander("🔍 Optional: Check for OSINT Exposure"):
    email_input = st.text_input("Email Address")
    username_input = st.text_input("Username")

if st.button("Analyze"):
    # --- Header Analysis ---
    ips = extract_sender_ips(headers)
    user_agents = extract_user_agents(headers)
    tor_nodes = get_tor_exit_nodes()

    if ips:
        for ip in ips:
            st.subheader(f"🌐 IP Address: {ip}")

            geo = ip_geolocation(ip)
            st.write("**📍 Geolocation Information:**")
            st.json(geo)

            if ip in tor_nodes:
                st.error("🚩 Tor Exit Node Detected!")
                st.write("**Tor Node Metadata:**")
                st.json(tor_nodes[ip])
            else:
                st.success("✅ Not a known Tor Exit Node.")

    else:
        st.warning("⚠️ No IP addresses found in headers.")

    if user_agents:
        st.subheader("🖥️ Detected User-Agents:")
        for ua in user_agents:
            st.code(ua)
    else:
        st.info("ℹ️ No User-Agent or X-Mailer headers found.")

    # --- OSINT Section ---
    if email_input:
        st.subheader(f"🧠 OSINT Check for Email: {email_input}")
        osint_email_data = cavalier_email_osint(email_input)
        st.json(osint_email_data)

    if username_input:
        st.subheader(f"🧠 OSINT Check for Username: {username_input}")
        osint_username_data = cavalier_username_osint(username_input)
        st.json(osint_username_data)

# ----------------- Footer -----------------
st.markdown("---")
st.markdown("🔧 Developed by **Prakash** | Powered by [Hudson Rock - Cavalier]")
