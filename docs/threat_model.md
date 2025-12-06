# StealthMesh – Threat Model

## Assets

- **Endpoints**
  - Machines where NodeAgent is running (workstations, servers).
- **Internal Services**
  - Services reachable through the mesh that we want to protect or hide.
- **Mesh Metadata & Keys**
  - Node IDs, peer lists, routing info.
  - Cryptographic key material and config files.

## Attacker Capabilities

The attacker can:

- Scan the network (internal or external).
- Perform brute-force attempts on exposed services.
- Compromise at least one internal node.
- Move laterally once a node is compromised.

## Simulated Attacks

1. **Port Scan**
   - Attacker runs port scans against node listen ports.
   - Goal: discover active nodes and services.

2. **Brute-Force Authentication**
   - Attacker repeatedly tries passwords/keys against a protected service.
   - Goal: gain unauthorized access.

3. **Compromised Internal Node**
   - Assume one node is taken over.
   - Attacker uses it to:
     - Enumerate peers.
     - Explore routes and internal services.
     - Attempt lateral movement through the mesh.
