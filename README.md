# TR3YES — Tactical Operations Center (Local SOC/EDR)

**TR3YES** is a lightweight Security Operations Center (SOC) and Endpoint Detection and Response (EDR) engine engineered in Go. Designed for native deployment in Windows environments, it provides real-time network telemetry, Deep Packet Inspection (DPI), and integrated SOAR (Security Orchestration, Automation, and Response) capabilities without relying on heavyweight commercial agents.

---

## 🏗️ Architecture: The Triple Sensor Engine

TR3YES core operations run on concurrent Go routines feeding a unified forensic audit log (`tr3yes_splunk_audit.json`), capturing real-time telemetry across three independent inspection sensors:

1. **Host-Based Sensor (HIDS):** Analyzes kernel socket tables via native OS utilities (`netstat`) to detect established TCP connections, performing reverse DNS lookups and identifying outbound exfiltration vectors (MITRE ATT&CK: `T1049`).
2. **TLS/SNI Inspector (TSHARK):** Intercepts encrypted traffic during the initial TLS 1.2/1.3 Handshake phase, extracting Server Name Indication (SNI) attributes to reveal destination domains without breaking SSL/TLS encryption (MITRE ATT&CK: `T1071.001`).
3. **Raw Packet Capture (TCPDUMP / BPF):** Leverages Berkeley Packet Filter (BPF) sockets via Npcap/Wireshark to monitor raw DNS traffic (Port 53) in search of covert tunnels or Command and Control (C2) beacons (MITRE ATT&CK: `T1040`).

---

## Core Capabilities

- **Native SOAR Automation:** Automated containment through live firewall rule injection (`netsh advfirewall`), instantly applying inbound/outbound drop rules on malicious endpoints.
- **Threat Intelligence (CTI):** Real-time IP address enrichment leveraging the VirusTotal v3 REST API.
- **Secure Tactical Dashboard:** Modern Single Page Application (SPA) served over strict TLS 1.3, equipped with native CSRF mitigation, session hardening, and cryptographic token validation.

---

## 🛠️ Prerequisites & Installation

1. **Go (Golang)** (v1.22 or higher)
2. **Wireshark & Npcap** (Ensure WinPcap API-compatible mode is enabled during installation).

Clone and initialize the repository:

```bash
git clone [https://github.com/tolotelin99/tr3yes.git](https://github.com/tolotelin99/tr3yes.git)
cd tr3yes
⚙️ Configuration & Environment Variables
Configure the required execution parameters in your terminal prior to launch:

Bash
# [REQUIRED] VirusTotal API key for CTI enrichment and SOAR intelligence
export VT_API_KEY="your_virustotal_api_key_here"

# [OPTIONAL] Network interface index to audit (e.g., 1, 5)
export TR3YES_IFACE="5"

# [OPTIONAL] Static authentication token (if omitted, an ephemeral token is generated in console)
export TR3YES_TOKEN="secure_access_token_123"
## Execution
Run the SOC server with elevated administrative privileges:

Bash
go run cmd/core/main.go
Access the secure tactical interface in your browser at:

https://127.0.0.1:8443/

📄 License
Distributed under the MIT License. See LICENSE for more information.
