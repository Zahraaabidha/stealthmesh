StealthMesh
Adaptive Stealth Communication & Decentralized Cyber Defense Framework

Academic Year: AY2025–26

StealthMesh is a decentralized cybersecurity framework designed for MSMEs (Micro, Small & Medium Enterprises) that lack the resources to deploy advanced security systems.
This project implements stealth networking, anomaly detection, deception routing, and autonomous micro-containment, forming a lightweight but powerful defense system capable of resisting modern cyber threats.

The entire system runs with local Python processes (no containers required) and exposes a FastAPI-based dashboard backend to monitor alerts, nodes, and containment actions.

🚨 Problem

Modern attacks such as reconnaissance scans, brute-force intrusions, and lateral movement overwhelm small industries that do not have:

A centralized Security Operations Center (SOC)

Moving Target Defense (MTD) systems

Enterprise-grade detection tools

This results in high vulnerability across the supply chain.

🎯 Objective

To build a plug-and-play, decentralized cyber-defense mesh that provides:

End-to-end encrypted communication between nodes

Stealth traffic (polymorphic keys, padding, jitter, cover messages)

Local rule-based and optional ML-based anomaly detection

Peer-to-peer alert sharing

Autonomous micro-containment (quarantine decisions)

Decoy routing for attacker deception

A FastAPI-powered dashboard for visibility

All without specialized hardware, containers, or complex infrastructure.

🧩 System Architecture (Based on Phases 1–7)
Phase 1 – Architecture, Configuration & Setup

Project structure with separate modules

YAML-based node configuration files

Documentation of architecture and threat model

Phase 2 – Mesh Communication Core

Python socket / asyncio based node-to-node communication

AES-GCM / ChaCha20 encryption via cryptography

Basic routing abstraction for direct and future multi-hop communication

Multi-node operation using multiple terminals (no Docker)

Phase 3 – Stealth Layer

Dynamic key rotation (“polymorphic encryption”)

Random packet padding

Timing jitter to obfuscate traffic patterns

Cover/decoy traffic generator

Phase 4 – Detection & Peer Alerts

Local anomaly detection rules

Optional ML (Isolation Forest) for anomaly scoring

Alert broadcasting to peers via the mesh

Phase 5 – Deception & Micro-Containment

Local containment logic

Network-wide collaborative quarantine

Simple decoy/redirect services for attacker misdirection

Simulated firewall behavior implemented directly in Python

Phase 6 – Dashboard Backend

Built using FastAPI

Endpoints:

/nodes – Node statuses

/alerts – Distributed alerts

/actions – Containment/deception actions

Node agents periodically POST updates to the dashboard

Phase 7 – Attack Simulations & Evaluation

Port-scan simulators

Brute-force attempt generators

Lateral movement simulators

Evaluation metrics:

Detection latency

Containment time

False positive/negative rates
