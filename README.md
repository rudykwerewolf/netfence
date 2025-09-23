# NetFence

**NetFence** is a TUI-based firewall and NAT manager for Linux, built on top of **nftables**. It provides a user-friendly interface similar to `nmtui` and also comes with CLI utilities for scripting and automation.

---

## Features

* **Interactive TUI**

  * Manage firewall rules through a text-based UI.
  * Menu-driven navigation, inspired by `nmtui`.
  * Real-time preview of the generated `nftables` ruleset.

* **Firewall Rules**

  * Add, list, and remove rules in INPUT, OUTPUT, and FORWARD chains.
  * Define rules by protocol, action (ACCEPT/DROP), interfaces, ports, CIDRs, and ICMP types.

* **Default Policies**

  * Configure default policies (ACCEPT/DROP) for INPUT, FORWARD, and OUTPUT.

* **NAT and Port Forwarding**

  * Manage SNAT/DNAT and MASQUERADE rules.
  * Automatic FORWARD acceptance for DNAT rules.

* **Persistence**

  * Rules are stored in an embedded SQLite database (`/etc/firewall.db`).
  * On reboot, rules can be reapplied automatically.

* **Audit Logging**

  * All changes (who/when/what) are logged in the database.

* **Export/Import**

  * Export full configuration to YAML for Git review.
  * Import configurations back from YAML snapshots.

* **RBAC (Role-Based Access Control)**

  * Users can be assigned roles: `admin`, `operator`, `viewer`.
  * Restricts who can change defaults, add rules, or apply rulesets.

---

## Requirements

* Linux system with `nftables`
* Go >= 1.24
* SQLite3 (handled via embedded driver `modernc.org/sqlite`)

Optional:

* `musl-tools` for fully static builds

---

## Installation

Clone the repository and build:

```bash
git clone https://github.com/rudykwerewolf/netfence.git
cd netfence
go build -o netfence ./cmd/netfence
```

For a static build (via musl):

```bash
CGO_ENABLED=1 CC=musl-gcc go build -ldflags="-linkmode external -extldflags -static" -o netfence ./cmd/netfence
```

Install system-wide:

```bash
sudo install -m 0755 netfence /usr/local/bin/
```

---

## Quick Start

Start the TUI:

```bash
sudo netfence
```

List current firewall rules via CLI:

```bash
sudo netfence list
```

Add a new rule (example: allow SSH):

```bash
sudo netfence add-rule --chain input --proto tcp --ports 22 --action accept --enabled
```

Block ICMP:

```bash
sudo netfence add-rule --chain input --proto icmp --action drop --enabled --comment "Drop ping"
```

Apply rules:

```bash
sudo netfence apply
```

---

## Documentation

For detailed CLI usage and examples, see [USAGE.md](USAGE.md).

---

