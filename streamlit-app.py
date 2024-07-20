import streamlit as st
import threading
import time
from scapy.all import get_if_list
from sniffers import start_sniffing, get_packets_df

# Function to start packet sniffing in a separate thread
def sniff_packets(interface):
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

# Streamlit UI
st.title("Network Sniffer")
st.sidebar.title("Controls")

# List available network interfaces
interfaces = get_if_list()
selected_interface = st.sidebar.selectbox("Select the network interface to sniff:", interfaces)

if st.sidebar.button("Start Sniffing"):
    st.sidebar.write(f"Sniffing started on {selected_interface}...")
    sniff_packets(selected_interface)

# Display captured packets
st.write("Captured Packets")
while True:
    packets_df = get_packets_df()
    if not packets_df.empty:
        st.write(packets_df)
    time.sleep(1)
