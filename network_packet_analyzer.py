from scapy.all import sniff, IP, TCP, UDP
import datetime

# Define a dictionary to hold protocol statistics
protocol_stats = {
    "TCP": 0,
    "UDP": 0,
    "Other": 0
}

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if protocol == 6:  # TCP
            protocol_name = "TCP"
            protocol_stats["TCP"] += 1
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
            protocol_stats["UDP"] += 1
        else:
            protocol_name = "Other"
            protocol_stats["Other"] += 1

        print(f"Timestamp: {timestamp}")
        print(f"IP Source: {ip_src}")
        print(f"IP Destination: {ip_dst}")
        print(f"Protocol: {protocol_name}")

        if TCP in packet:
            print(f"Payload: {bytes(packet[TCP].payload)}")
        elif UDP in packet:
            print(f"Payload: {bytes(packet[UDP].payload)}")
        print("="*40)

        # Log packet details to a file
        with open("packet_log.txt", "a") as f:
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"IP Source: {ip_src}\n")
            f.write(f"IP Destination: {ip_dst}\n")
            f.write(f"Protocol: {protocol_name}\n")
            if TCP in packet:
                f.write(f"Payload: {bytes(packet[TCP].payload)}\n")
            elif UDP in packet:
                f.write(f"Payload: {bytes(packet[UDP].payload)}\n")
            f.write("="*40 + "\n")

def main():
    print("Starting network packet analyzer...")
    sniff(prn=packet_callback, store=0)

def print_statistics():
    print("\nSummary Statistics:")
    print(f"Total TCP Packets: {protocol_stats['TCP']}")
    print(f"Total UDP Packets: {protocol_stats['UDP']}")
    print(f"Total Other Packets: {protocol_stats['Other']}")
    print(f"Total Packets: {sum(protocol_stats.values())}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_statistics()
        print("Packet capture stopped.")
