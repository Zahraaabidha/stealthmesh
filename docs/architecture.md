# StealthMesh – Architecture

## Core Components

- **NodeAgent**
  - Loads node configuration from `config/*.yaml`
  - Exposes:
    - `listen_host`, `listen_port`
    - `peers`
    - `key_paths`
  - Orchestrates internal components.

- **MeshCore**
  - Handles node-to-node communication and routing.

- **StealthLayer**
  - Applies obfuscation, padding, and traffic shaping to messages.

- **DefenseEngine**
  - Monitors activity and triggers detection / response logic.

- **Local Policy**
  - Configuration and rules that guide how the node behaves.

## Block Diagram

NodeAgent → [MeshCore, StealthLayer, DefenseEngine, LocalPolicy]

Conceptually:

- NodeAgent calls into MeshCore for networking.
- Messages in/out pass through StealthLayer.
- DefenseEngine observes behavior and events.
- Local policy defines thresholds, rules, and actions.

## Dashboard Backend

- Runs separately from the nodes.
- Purpose: **visualization and telemetry only** (status, alerts, metrics).
- Does **not** directly control or command nodes.
- Nodes remain autonomous; dashboard is read-only from a control perspective.
