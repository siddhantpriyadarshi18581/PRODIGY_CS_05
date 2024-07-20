from scapy.all import sniff, Ether
import pandas as pd

# Initialize a list to hold captured packets
packets_list = []

def packet_callback(packet):
    # Extract necessary packet information
    if packet.haslayer(Ether):
        eth = packet.getlayer(Ether)
        packet_info = {
            "Source MAC": eth.src,
            "Destination MAC": eth.dst,
            "Protocol": eth.type,
            "Length": len(packet)
        }
        packets_list.append(packet_info)

# Function to start packet sniffing
def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=0)

# Convert packets to DataFrame for Streamlit
def get_packets_df():
    return pd.DataFrame(packets_list)
