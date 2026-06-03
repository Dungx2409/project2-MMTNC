# 🌐 SDN Network Implementation — CSE 461 Project 2

> **Software-Defined Networking with OpenFlow, Mininet & POX Controller**  
> University of Washington · CSE 461: Computer Networks · Spring 2025  
> Team: **linhnph05** · **MMTNC**

---

## 📌 Overview

This project implements a full **Software-Defined Networking (SDN)** stack using the OpenFlow protocol — progressing from basic network emulation to a dynamic L3 router with ARP learning. Built on **Mininet** (network emulator) and **POX** (OpenFlow controller), it demonstrates how decoupling the control plane from the data plane enables programmable, policy-driven networks.

**Core skills demonstrated:**
- Designing and emulating custom network topologies in Mininet
- Writing OpenFlow controllers in Python (POX) to manage flow tables
- Implementing L2 firewalls and L3 routing with fine-grained traffic policies
- Building a dynamic ARP-learning router without static route configuration

---

## 🗂️ Repository Structure

```
project2-MMTNC/
│
├── 461_mininet/
│   ├── topos/
│   │   ├── part1.py          # Custom 4-host, 1-switch star topology
│   │   ├── part2.py          # Provided — single switch + firewall topology
│   │   ├── part3.py          # Provided — multi-floor company network
│   │   └── part4.py          # Provided — routed network (no static ARP)
│   │
│   └── pox/
│       ├── part2controller.py  # L2 static firewall
│       ├── part3controller.py  # Multi-switch L3 router + security policies
│       └── part4controller.py  # Dynamic L3 router with ARP learning
│
└── README.md
```

---

## 🏗️ Network Architecture

### Parts 1–2: Simple Topology
```
[h1]─────{s1}─────[h2]
[h3]────/    \────[h4]
```

### Parts 3–4: Company Network
```
[h10 @ 10.0.1.10/24] ──{s1}──\
[h20 @ 10.0.2.20/24] ──{s2}──{cores21}──{dcs31}──[serv1 @ 10.0.4.10/24]
[h30 @ 10.0.3.30/24] ──{s3}──/    │
                                   │
                    [hnotrust1 @ 172.16.10.100/24]
```

The **core switch (`cores21`)** acts as an L3 router — all inter-subnet traffic flows through it. Edge switches (`s1`, `s2`, `s3`, `dcs31`) flood within their subnets.

---

## 🚀 Running the Project

### Prerequisites
- [Multipass](https://multipass.run/) with the CSE 461 Ubuntu VM
- Mininet and POX pre-installed in the VM

### Part 1 — Mininet Topology
```bash
sudo -E mn --custom 461_mininet/topos/part1.py --topo=part1
```

### Parts 2–4 — POX Controller + Mininet (run in separate terminals)
```bash
# Terminal 1: launch the POX controller
sudo ~/pox/pox.py misc.part2controller   # swap part number as needed

# Terminal 2: launch Mininet
sudo python 461_mininet/topos/part2.py
```

---

## 📋 Implementation

### Part 1 — Custom Mininet Topology
Built a 4-host, 1-switch star topology using Mininet's Python API. Verified with `pingall`, measured throughput with `iperf`, and inspected state with `dump`.

---

### Part 2 — L2 Static Firewall (`part2controller.py`)

Installed flow rules at startup so the switch handles traffic autonomously — **no per-packet controller involvement**.

| Src IP   | Dst IP   | Protocol | Action   |
|----------|----------|----------|----------|
| any IPv4 | any IPv4 | ICMP     | ✅ Allow |
| any      | any      | ARP      | ✅ Allow |
| any IPv4 | any IPv4 | —        | ❌ Drop  |

Result: `pingall` succeeds within subnets; `iperf` (TCP/UDP) is blocked.

---

### Part 3 — Multi-Switch L3 Router (`part3controller.py`)

Extended the controller to manage 5 switches with inter-subnet routing:

- **Edge switches** (`s1`, `s2`, `s3`, `dcs31`): flood within subnet (`OFPP_FLOOD`)
- **Core switch** (`cores21`): strict per-port forwarding keyed on destination IP

Security policy enforced at `cores21`:

| Source        | Destination       | Traffic | Rule      |
|---------------|-------------------|---------|-----------|
| `hnotrust1`   | `serv1`           | All IP  | ❌ Block  |
| `hnotrust1`   | `h10/h20/h30`     | ICMP    | ❌ Block  |
| `hnotrust1`   | `h10/h20/h30`     | IP      | ✅ Allow  |
| internal hosts | any              | any     | ✅ Allow  |

---

### Part 4 — Dynamic L3 Router with ARP Learning (`part4controller.py`)

Transformed `cores21` into a fully functional L3 router — **zero static routes at startup**.

**How it works:**

1. **ARP interception** — Controller intercepts ARP requests and replies on behalf of gateway IPs (`10.0.{N}.1`), preventing broadcast flooding across subnets.
2. **Dynamic learning** — Snoops ARP traffic to build an `IP → MAC → port` mapping table at runtime.
3. **Flow rule installation** — Once a destination is learned, installs a forwarding rule directly into `cores21`'s flow table. All subsequent traffic to that destination is hardware-switched (no controller involvement).
4. **L2 header rewriting** — Rewrites src/dst MAC for every cross-subnet hop.

All L3 security policies from Part 3 are preserved.

> **Why do some pings fail initially?**  
> The first packet to an unknown destination triggers ARP resolution and flow rule installation. Once the route is learned, all subsequent packets hit the flow table directly and succeed.

---

## 🔍 Key Technical Concepts

| Concept | Where Applied |
|---|---|
| `ofp_flow_mod` — install flow rules | Parts 2, 3, 4 |
| Priority-based rule matching | Part 2 firewall |
| Per-port IP forwarding (no flood) | Part 3 & 4 `cores21` |
| ARP generation by controller | Part 4 |
| IP↔MAC↔port dynamic learning | Part 4 |
| L2 MAC rewrite for L3 routing | Part 4 |

---

## ✅ Test Results Summary

| Test | Part 2 | Part 3 | Part 4 |
|------|:------:|:------:|:------:|
| `pingall` — internal hosts | ✅ | ✅ | ✅ |
| `pingall` — hnotrust → internal | — | ❌ Blocked | ❌ Blocked |
| `iperf` — authorized IP traffic | ❌ Blocked | ✅ | ✅ |
| `iperf` — hnotrust → serv1 | — | ❌ Blocked | ❌ Blocked |
| `iperf` — hnotrust → h10 (IP) | — | ✅ | ✅ |

---

## 🛠️ Technologies

- **[Mininet](https://github.com/mininet/mininet)** — Software network emulator
- **[POX](https://noxrepo.github.io/pox-doc/html/)** — Python OpenFlow controller
- **OpenVSwitch (OVS)** — Software-defined switch
- **OpenFlow 1.0** — Controller–switch protocol
- **Multipass** — Lightweight Ubuntu VM

---

## 📚 References

- [Mininet Walkthrough](http://mininet.org/walkthrough/)
- [POX Documentation](https://noxrepo.github.io/pox-doc/html/)
- [OpenFlow 1.0 Specification](https://opennetworking.org/wp-content/uploads/2013/04/openflow-spec-v1.0.0.pdf)
- [OpenFlow Tutorial — Learning Switch](https://github.com/mininet/openflow-tutorial/wiki/Create-a-Learning-Switch)
