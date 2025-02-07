
# 🛡 Python Packet Sniffer

A simple **packet sniffer** built using Python and **Scapy** that captures network packets and displays them in a structured format. Users can choose whether to **save** the captured packets to a log file.

## 🚀 Features
- Captures **TCP, UDP, ICMP, and other IP packets**.
- Displays packets in a structured format:

- **Optional Logging**: Users can choose to save captured packets to a file.
- **Handles Invalid Input**: Asks for valid input if the user enters anything other than `y` or `n` or `e`.

---

## 🛠 Installation
### **1️⃣ Install Dependencies**
Ensure you have Python 3 installed and install Scapy:

```bash/powershell
pip install scapy
```
### **2️⃣ Clone the Repository**
```bash
git clone https://github.com/raghavdixit-2006/packet-sniffer.git
cd simple-packet-sniffer
```

---

## ▶️ Usage
Run the script with **administrator/root privileges** (required for packet sniffing).
### 💻 Windows (Run as Admin)
```powershell
python packet-sniffer.py
```

### 🐧 Linux/macOS
```bash
sudo python3 packet-sniffer.py
```

---

## 📜 Example Output
### 🔹 User Input
```bash


██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ███████╗██╗███╗   ██╗███████╗███████╗███████╗██████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    ██╔════╝██║████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║       ███████╗██║██╔██╗ ██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       ╚════██║██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       ███████║██║██║ ╚████║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

                                                                                created by- Raghav Dixit 

Do you want to save the packet capture to a log file? To exit press 'e'
(y/n/e): y
Please enter the file name without any spaces: packet
```
### 🔹 Terminal Output
```nigex


██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ███████╗██╗███╗   ██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    ██╔════╝██║████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║       ███████╗██║██╔██╗ ██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       ╚════██║██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       ███████║██║██║ ╚████║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

                                                                                created by- Raghav Dixit  

Saving data = 'y'

Date & Time         Source        Destination       Protocol   Info
--------------------------------------------------------------------------------
2025-02-06 14:30:15 192.168.1.10  192.168.1.1      TCP        Ports: 443 → 51234, Flags: S
2025-02-06 14:30:16 192.168.1.5   8.8.8.8          UDP        Ports: 53 → 54789
2025-02-06 14:30:17 192.168.1.20  192.168.1.255    ICMP       Type: 8, Code: 0
```
### 🔹 Log File Output (packets.log if logging enabled)
```nigex
Date & Time         Source        Destination       Protocol   Info
--------------------------------------------------------------------------------
2025-02-06 14:30:15 192.168.1.10  192.168.1.1      TCP        Ports: 443 → 51234, Flags: S
2025-02-06 14:30:16 192.168.1.5   8.8.8.8          UDP        Ports: 53 → 54789
```

---

## ⚠️ Requirements & Notes
- Requires Python 3.x.
- Must be run as **root/admin** for packet sniffing.
- Works on Windows, macOS, and Linux.

## 📄 License
- This project is licensed under the MIT License.

## 🤝 Contributing
- Pull requests are welcome! Feel free to submit issues or improvements.

## ⭐️ Show Your Support
 - If you like this project, please  **⭐️ Star the repo** on GitHub!

