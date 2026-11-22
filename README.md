# ICMP Flood (Ping Flood) Attack Detection with Suricata IDS

A hands-on lab project demonstrating how to detect an **ICMP Flood (Ping Flood) Denial-of-Service attack** using **Suricata IDS** with custom-written detection rules, and a custom Python attack script used to simulate the attack.

---

## 📌 Project Overview

This project simulates a basic ICMP flood DoS attack against a target host and demonstrates how a properly tuned Suricata IDS instance can detect the attack in real time using custom signatures.

**Attack simulated:** ICMP Echo Request (ping) flood
**Detection engine:** Suricata 7.0.10 (IDS mode)
**Attack tool:** Custom Python script (`flood.py`) using `pythonping`
**Detection method:** Two custom Suricata rules using `detection_filter` thresholds

---

<img width="1672" height="941" alt="Suricata ICMP Flood Detection Diagram" src="https://github.com/user-attachments/assets/82df4813-bded-49aa-bcb3-77c0e1249b4e" />

## 🧱 Architecture

```
 ┌────────────────────┐            ICMP Echo Requests            ┌─────────────────────────┐
 │   Attacker Machine   │ ─────────────────────────────────────▶ │     Target / Sensor       │
 │  (Windows) │                 (flood.py / pythonping)          │   Kali Linux + Suricata   │
 │                      │                                         │   10.186.209.136 (eth0)   │
 └────────────────────┘                                          └─────────────────────────┘
                                                                              │
                                                                              ▼
                                                                   Suricata fast.log / console
                                                                   ICMP FLOOD ATTACK alerts
```

| Role | Host | OS |
|------|------|----|
| Attacker | — | Windows (VS Code) |
| Victim / Sensor | `10.186.209.136` | Kali Linux |
| Network | `10.186.209.0/24` | — |

---

## ✨ Features

- Custom Suricata detection rules for ICMP flood activity (burst + sustained thresholds)
- Lightweight Python-based ICMP flood generator for controlled testing
- Suricata configuration tuned with correct `HOME_NET` for the test subnet
- Verified configuration using `suricata -T` before deployment
- Live alert capture showing successful detection of the simulated attack

---

## 📂 Project Structure

```
.
├── README.md                  # This file
├── documentation.md           # Full step-by-step write-up of the lab
├── flood.py                   # Python ICMP flood attack script (attacker side)
├── pingflood.rules            # Custom Suricata detection rules
└── /etc/suricata/suricata.yaml  # Suricata config (HOME_NET + rule-files updated)
```

---

## ⚙️ Prerequisites

- Kali Linux (or any Linux host) with **Suricata 7.x** installed
- Network interface in IDS/monitor mode (`eth0` used in this lab)
- Python 3.12+ with the `pythonping` module on the attacker machine
- Root/sudo access on the Suricata host

---

## 🚀 Quick Start

1. Clone/copy this project to your Suricata host.
2. Place `pingflood.rules` in a location such as `/home/kali/pingflood.rules`.
3. Register the rule file and set `HOME_NET` in `/etc/suricata/suricata.yaml` (see `documentation.md`).
4. Test the configuration:
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml -i eth0
   ```
5. Start Suricata:
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   ```
6. From the attacker machine, run the flood script:
   ```bash
   python flood.py
   ```
7. Watch the Suricata console/log for `ICMP FLOOD ATTACK DETECTED` alerts.

See **documentation.md** for the complete, detailed walkthrough with explanations of every step and each rule.

---

## ✅ Result

Suricata successfully detected the simulated ICMP flood using both custom rules, logging high-frequency ICMP Echo traffic from the attacker IP toward the monitored host as an **Attempted Denial of Service**.

---

## ⚠️ Disclaimer

This project was built strictly for an isolated lab/training environment. Only run the attack script against systems you own or have explicit authorization to test.

---

## 👤 Author

Femi Awoyomi — Cybersecurity (GRC & Offensive Security)
