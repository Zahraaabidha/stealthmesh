**_*_*Adaptive Stealth Communication & Decentralized Cyber Defense****

StealthMesh is a decentralized cybersecurity framework designed for MSMEs.
It provides stealth communication, distributed anomaly detection, peer alerts, deception routing, and autonomous micro-containment without requiring centralized SOC infrastructure_._

🚀 **Objective**

Build a lightweight, affordable, and resilient cyber-defense mesh where each node:

Communicates through encrypted, stealth-enabled channels

Detects anomalies locally

Shares alerts with peers

Executes deception and micro-containment actions

Reports status to a FastAPI dashboard backend
**
**Core Components
Mesh Core (mesh_core/)****

Encrypted node-to-node communication

Key rotation, padding, timing jitter, cover traffic

Basic routing abstraction (direct communication)
****
**Defense Engine (defense_engine/)******

Local detection (rules + optional ML)

Alert broadcasting

Containment logic (local + network-wide)

Deception routing to decoy services

**Dashboard (dashboard/backend/)**

FastAPI backend for:

Node status

Alerts

Containment actions

**Simulations (simulations/)**

Port scans, brute-force attempts, lateral movement tests
