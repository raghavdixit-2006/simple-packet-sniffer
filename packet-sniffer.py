from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime
import os

banner = '''

██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ███████╗██╗███╗   ██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    ██╔════╝██║████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║       ███████╗██║██╔██╗ ██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       ╚════██║██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       ███████║██║██║ ╚████║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

                                                                                created by- Raghav Dixit                                                                                                
                                                                                                          
'''
os.system("clear")

print(banner)

while True:
    save_input = input("Do you want to save the packet capture to a log file? To exit press 'e'\n(y/n/e): ").strip().lower()
    
    if save_input == "y":
        SAVE_TO_FILE = True
        LOG_FILE = input("Please enter the file name without any spaces: ").strip()
        LOG_FILE = f"{LOG_FILE}.log"
        break
    elif save_input == "n":
        SAVE_TO_FILE = False
        break
    elif save_input == "e":
        exit()
    else:
        print("Invalid input. Please enter 'y' or 'n'.")
        
        

os.system("clear")

print(banner)

print(f"Saving status = '{save_input}'\n")

def packet_callback(packet):
    """Processes captured packets and logs details if enabled."""
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        info = "N/A"

        if packet.haslayer(TCP):
            protocol = "TCP"
            info = f"Ports: {packet[TCP].sport} -> {packet[TCP].dport}, Flags: {packet[TCP].flags}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            info = f"Ports: {packet[UDP].sport} -> {packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            info = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"

        log_entry = f"{timestamp:<19} {src_ip:<15} {dst_ip:<15} {protocol:<10} {info}\n"

        print(log_entry, end="")

        if SAVE_TO_FILE:
            with open(LOG_FILE, "a") as f:
                f.write(log_entry)

header = f"{'Date & Time':<19} {'Source':<15} {'Destination':<15} {'Protocol':<10} {'Info'}\n"
separator = "-" * 80 + "\n"

print(header + separator)

if SAVE_TO_FILE:
    with open(LOG_FILE, "w") as f:
        f.write(header + separator)

sniff(prn=packet_callback, store=False)
