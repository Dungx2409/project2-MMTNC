# 🌐 SDN Network Implementation — CSE 461 Project 2

> **Software-Defined Networking with OpenFlow, Mininet & POX Controller**  
> University of Washington · CSE 461: Computer Networks · Spring 2025

---

## 📌 Overview

This project implements a full Software-Defined Networking (SDN) stack using the **OpenFlow protocol**, progressing from basic network emulation to a dynamic L3 router with ARP learning. Built on **Mininet** (network emulator) and **POX** (OpenFlow controller), the project demonstrates how decoupling the control plane from the data plane enables programmable, policy-driven networks.

**Key concepts demonstrated:**
- L2 switching & L3 routing via flow table rules
- Stateful ARP handling and dynamic route learning
- Fine-grained traffic filtering (firewall policies)
- Multi-switch topology management with a centralized controller

---

## 🏗️ Architecture

```
[h10 @ 10.0.1.10]──{s1}──\
[h20 @ 10.0.2.20]──{s2}──{cores21}──{dcs31}──[serv1 @ 10.0.4.10]
[h30 @ 10.0.3.30]──{s3}──/    │
                               │
                [hnotrust1 @ 172.16.10.100]
```

The **core switch (`cores21`)** acts as an L3 router — the focal point of all inter-subnet traffic. Edge switches (`s1`, `s2`, `s3`, `dcs31`) handle L2 forwarding within subnets.

---

## 🔧 Project Structure

```
project2/
├── part1/
│   ├── part1.py              # Custom Mininet topology (1 switch, 4 hosts)
│   └── screenshots/          # iperf, dump, pingall outputs
│
├── part2/
│   ├── part2controller.py    # L2 static firewall (ICMP/ARP allow, drop rest)
│   └── screenshots/
│
├── part3/
│   ├── part3controller.py    # Multi-switch L3 routing + security policies
│   └── screenshots/
│
└── part4/
    ├── part4controller.py    # Dynamic L3 router with ARP learning
    └── screenshots/
```

---

## 🚀 Getting Started

### Prerequisites

- [Multipass](https://multipass.run/) — VM management
- Ubuntu VM with **Mininet** and **POX** pre-installed

### Setup

```bash
# Launch VM
multipass shell cse461

# Run Part 1 topology
sudo -E mn --custom 461_mininet/topos/part1.py --topo=part1

# Run Parts 2–4 (in separate terminals)
# Terminal 1: Start POX controller
sudo ~/pox/pox.py misc.part2controller

# Terminal 2: Start Mininet
sudo python ~/461_mininet/topos/part2.py
```

---

## 📋 Implementation Details

### Part 1 — Mininet Topology
Built a custom 4-host, 1-switch star topology using Mininet's Python API. Verified connectivity with `pingall`, measured throughput with `iperf`, and inspected the network state with `dump`.

### Part 2 — L2 Firewall (POX Controller)

Implemented a stateless packet filter on a single switch using OpenFlow flow rules:

| Src IP     | Dst IP     | Protocol | Action  |
|------------|------------|----------|---------|
| any IPv4   | any IPv4   | ICMP     | ✅ Allow |
| any        | any        | ARP      | ✅ Allow |
| any IPv4   | any IPv4   | —        | ❌ Drop  |

Rules are installed as **flow table entries** at startup (not per-packet), ensuring the switch handles traffic autonomously without controller involvement on every packet.

### Part 3 — Multi-Switch L3 Router

Extended the controller to manage a 5-switch topology with inter-subnet routing. Key design decisions:

- **Edge switches** (`s1`, `s2`, `s3`, `dcs31`): flood within subnet
- **Core switch** (`cores21`): strict per-port forwarding rules based on destination IP
- **Security policy** enforced at `cores21`:
  - `hnotrust1` → `serv1`: **all IP blocked**
  - `hnotrust1` → internal hosts: **ICMP blocked**, IP allowed

### Part 4 — Dynamic L3 Router with ARP Learning

Transformed `cores21` into a fully functional L3 router:

- **ARP interception**: controller responds to ARP requests on behalf of gateway IPs (`10.0.{N}.1`) without flooding
- **Dynamic learning**: snoops ARP traffic to build an IP→MAC→port mapping table
- **Flow rule installation**: once an L3 path is learned, installs forwarding rules directly into `cores21`'s flow table for all future traffic
- **L2 header rewriting**: rewrites src/dst MAC for cross-subnet forwarding
- Retains all L3 security policies from Part 3

> **Why do some pings fail initially in Part 4?**  
> The router installs flow rules *after* learning the destination via ARP. The first ping triggers ARP resolution and rule installation — subsequent pings use the cached flow rule and succeed.

---

## 🔍 Key Technical Concepts

| Concept | Implementation |
|---|---|
| **OpenFlow flow rules** | `of.ofp_flow_mod()` with match/action pairs |
| **ARP handling** | Controller intercepts, generates synthetic replies |
| **L2 → L3 routing** | MAC rewrite + port-based forwarding at core switch |
| **Dynamic learning** | ARP snooping to build IP↔MAC↔port table at runtime |
| **Firewall policy** | Priority-ordered flow rules; unmatched = drop |

---

## 📸 Results

| Test | Part 2 | Part 3 | Part 4 |
|------|--------|--------|--------|
| `pingall` (internal hosts) | ✅ | ✅ | ✅ |
| `pingall` (hnotrust → internal) | — | ❌ Blocked | ❌ Blocked |
| `iperf` (IP traffic) | ❌ Blocked | ✅ (authorized) | ✅ (authorized) |
| `iperf hnotrust → serv1` | — | ❌ Blocked | ❌ Blocked |

---

## 🛠️ Technologies

- **Mininet** — Software network emulator
- **POX** — Python-based OpenFlow controller
- **OpenVSwitch (OVS)** — Software-defined switch implementation
- **OpenFlow 1.0** — Controller-switch communication protocol
- **Multipass** — Lightweight VM for isolated environment

---

## 👥 Team

| Name | UW NetID |
|------|----------|
| Luong Van Dung| 23127353 |
| Nguyen Phan Hung Linh | 23127081 |

---

## 📚 References

- [Mininet Walkthrough](http://mininet.org/walkthrough/)
- [POX Documentation](https://noxrepo.github.io/pox-doc/html/)
- [OpenFlow 1.0 Specification](https://opennetworking.org/wp-content/uploads/2013/04/openflow-spec-v1.0.0.pdf)
- [OpenFlow Tutorial — Learning Switch with POX](https://github.com/mininet/openflow-tutorial/wiki/Create-a-Learning-Switch)
