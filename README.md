# 🌐 Computer Networking & Subnetting Suite

> A modern, interactive web application built for network engineers, systems administrators, students, and educators. Combines powerful IPv4 & IPv6 subnet calculators, VLSM & FLSM planners, interactive TCP handshake & DNS resolution animations, 7-layer OSI model explorer, searchable port database, network security guide, hardware encyclopedia, and subnetting practice quiz.

---

## ✨ Features Overview (18 Complete Modules)

### 🧮 1. IPv4 Subnet Calculator & Visualizer
- **Complete Address Breakdown**: Calculates Network Address, Broadcast Address, First Usable Host, Last Usable Host, Subnet Mask, Wildcard Mask, Total Addresses, and Usable Host Count.
- **Bit-Level Breakdown**: 32-bit binary representation showing network bits (teal) vs host bits (amber) with decimal octet mappings.
- **Dynamic Topology Diagram**: Interactive SVG diagram showing Router, Switches, and Host nodes.
- **IP Intelligence Badges**:
  - **Class Identifier**: Class A, Class B, Class C, Class D (Multicast), Class E (Experimental).
  - **Scope Identifier**: Private (RFC 1918), Public Unicast, APIPA (`169.254.x.x`), Loopback (`127.0.0.1`), Carrier-Grade NAT (`100.64.0.0/10`), Limited Broadcast.

### 📐 2. Subnet Planner (VLSM & FLSM)
- **Variable Length Subnet Masking (VLSM)**: Allocates custom subnets for varying host count requirements using optimal block sizes.
- **Fixed Length Subnet Masking (FLSM)**: Divides a base network into equal-sized subnets based on requested subnet count.
- **SVG Architecture Diagrams**: Rendered network topology showing subnet division across switches.

### 🌌 3. IPv6 Toolkit
- **Subnet Info**: Expanded/compressed IPv6 formatting, 128-bit hextet breakdown (network vs host bits), total address calculation using BigInt math.
- **Sub-Prefix Planner**: IPv6 VLSM planner to divide a base IPv6 block into sub-prefixes (`/48`, `/56`, `/64`).
- **Address Type Classifier**: Auto-detects Loopback (`::1`), Link-Local (`fe80::/10`), Unique Local (`fc00::/7`), Multicast (`ff00::/8`), Global Unicast (`2000::/3`), Documentation (`2001:db8::/32`), Teredo, 6to4, NAT64.
- **IPv6 Quick Reference**: Comprehensive prefix length guide (`/128` to `/3`).

### 🤝 4. TCP 3-Way Handshake Animation
- **Interactive Handshake Animation**: Step-by-step visual animation (`CLOSED` → `SYN` → `SYN-ACK` → `ACK` → `ESTABLISHED`).
- **Controls**: `Prev`, `Auto Play`, `Next`, `Reset`.
- **Packet Details**: Displays sequence numbers (`SEQ`), acknowledgment numbers (`ACK`), window size (`WIN`), and TCP control flags.

### 📦 5. Protocol Stack Encapsulation Visualizer
- Visualizes data payload wrapping layer-by-layer down the stack: Application → Transport (TCP Header) → Network (IP Header) → Data Link (Ethernet Frame) → Physical (Bits).

### 🏗️ 6. OSI 7-Layer Model Explorer
- Interactive 7-layer OSI model stack (Physical to Application).
- Highlights PDU types (Bits, Frame, Packet, Segment, Data), associated protocols, hardware devices, and layer responsibilities.

### 🔌 7. Searchable Port Directory
- Searchable reference of well-known ports (20, 21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, etc.) with protocol type (TCP/UDP), category, and security descriptions.

### 🌐 8. Interactive DNS Resolution Simulator
- Visual query path simulation showing how domain names (`www.example.com`) are resolved step-by-step: `Client` → `Local Recursive Resolver` → `Root Server (.)` → `TLD Server (.com)` → `Authoritative Server` → `IP Result`.

### 🛡️ 9. Network Security Overview
- Educational cards explaining Firewalls (Stateless vs Stateful vs NGFW), VPNs (IPsec/OpenVPN/WireGuard), NAT/PAT, IDS vs IPS, ARP Spoofing & Mitigation, SSL/TLS & HTTPS Encryption.

### 📟 10. Network Device Encyclopedia
- Hardware guide covering Routers, L2/L3 Switches, Firewalls, Wireless Access Points, Gateways, Hubs, and NICs with OSI layer operation levels and functions.

### ⚡ 11. IPv4 vs IPv6 Side-by-Side Comparison Matrix
- Detailed protocol comparison table contrasting address length, format, total capacity, header size (20–60B vs fixed 40B), addressing modes, host auto-config (DHCP vs SLAAC), IPSec native support, NAT dependency, and packet fragmentation.

### 🎯 12. Subnetting Quiz / Practice Challenge Mode
- Practice problem generator for CCNA/Network+ exam prep.
- Generates random IPs and CIDRs to test Network Address, Broadcast Address, Subnet Mask, First Host, and Host Count.
- Tracks score, streak counter, instant answer feedback, and step-by-step solution explanations.

### 📥 13. Export Calculation Report
- Export formatted calculation summaries to **Copy Text** or **Download `.txt` File**.

---

## 🛠️ Technology Stack

- **Frontend Library**: React 19
- **Build Tool**: Vite 8
- **Styling**: Vanilla CSS with HSL dark-mode color palette (`#0a0e14` background), flexbox/grid layouts, glassmorphism cards
- **Typography**: Google Fonts (*Inter* for UI & *JetBrains Mono* for IP data)
- **Visualizations**: Pure React Inline SVG Graphics & Animations (Zero external chart dependency)

---

## ⚙️ Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18.0.0 or higher)
- `npm` or `yarn`

### Installation & Running Locally

```bash
# 1. Clone the repository
git clone https://github.com/your-username/subnet-calculator.git

# 2. Navigate into the project folder
cd subnet-calculator

# 3. Install dependencies
npm install

# 4. Start the development server
npm run dev
```

Open your browser and navigate to **`http://localhost:5173/`**.

---

## 📂 Project Structure

```
subnet-calculator/
├── src/
│   ├── SubnetToolkit.jsx   # Core 18-module networking component
│   ├── App.jsx             # Main application wrapper
│   ├── index.css           # Global dark theme tokens & styling
│   └── main.jsx            # Application entry point
├── public/                 # Static assets
├── index.html              # HTML template with Google Fonts imports
├── package.json            # Dependencies and scripts
└── README.md               # Project documentation
```

---

## 📜 License

This project is licensed under the **MIT License**. Feel free to use, modify, and distribute it for educational or commercial purposes.
