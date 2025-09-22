# NetFence

`NetFence` is a **TUI-based firewall and NAT manager** for Linux, built on top of `iptables`.
It provides an interface similar to `nmtui`, allowing administrators to manage firewall rules, NAT, port forwarding, and forwarding policies interactively.

---

## Features

* **NAT Rules**
  Add and manage MASQUERADE/SNAT rules through a simple form.

* **Port Forwarding**
  Configure DNAT (port forwarding) with automatic MASQUERADE and forwarding acceptance.

* **Forwarding Rules**
  Manage rules in the `FORWARD` chain (useful when default policy is `DROP`).

* **Firewall Rules**
  Manage rules in the `INPUT`, `OUTPUT`, and `FORWARD` chains.

* **System Options**

  * Enable or check IPv4 forwarding status.
  * Persist rules using `netfilter-persistent`.

* **Active Rules View**
  Browse active rules grouped by:

  * NAT Rules
  * Port Forwarding Rules
  * Forwarding Rules
  * Firewall Rules

---

## Requirements

* Linux with `iptables` installed
* `netfilter-persistent` (for saving rules)
* Go 1.20+

Install dependencies on Debian/Ubuntu:

```bash
apt update
apt install -y iptables iptables-persistent golang
```

---

## Build

Clone the repo and build:

```bash
go build -o netfence main.go
```

---

## Usage

Run the program:

```bash
sudo ./fwctl
```

You will see a **text-based menu** with options to manage NAT, port forwarding, forwarding, and firewall rules. Navigate with **arrows** and confirm with **Enter**.

---

## Menu Overview

* **Active Rules**
  View currently active rules, separated into NAT, Port Forwarding, Forwarding, and Firewall.

* **Add NAT Rule**
  Add a MASQUERADE rule for outgoing traffic via a specific interface.

* **Add Port Forwarding**
  Forward external ports to internal hosts. The tool automatically adds DNAT, MASQUERADE, and FORWARD rules.

* **Add Forwarding Rule**
  Configure traffic forwarding between interfaces or networks (useful if your FORWARD policy is `DROP`).

* **Add Firewall Rule**
  Create INPUT/OUTPUT/FORWARD rules with specific protocols, addresses, and ports.

* **System**

  * Enable IPv4 forwarding.
  * Check current forwarding status.

* **Save & Exit**
  Save all rules to persist across reboots.

* **Exit without saving**
  Quit without persisting changes.

---

## Notes

* All actions are applied immediately through `iptables`.
* Persist your configuration with **Save & Exit** to keep it after reboot.
* If your `FORWARD` chain policy is set to `ACCEPT`, explicit forwarding rules may not be required.
* For stricter setups (policy `DROP`), configure Forwarding rules explicitly.

---
