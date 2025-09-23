# NetFence Usage Guide

This document describes how to use **NetFence** from both the CLI and the TUI.

---

## TUI (Interactive Interface)

Launch the TUI:

```bash
sudo netfence
```

### Main Menu

* **Firewall Rules** – View, add, or remove firewall rules.
* **Default Policies** – Configure INPUT, FORWARD, and OUTPUT policies.
* **NAT & Port Forwarding** – Manage SNAT, MASQUERADE, and DNAT rules.
* **Preview / Apply Ruleset** – Preview the generated `nftables` rules and apply them.
* **Exit** – Close the program.

Navigation is similar to `nmtui`:

* Use **arrow keys** to move between menu items and fields.
* Use **Tab** to switch between buttons.
* Press **Enter** to confirm selections.

---

## CLI Commands

### Show Firewall Rules

```bash
netfence list
```

Example output:

```
ID  CHAIN   PROTO  ACTION  ENABLED  IN_IF  OUT_IF  PORTS   SRC           DST   ICMP  COMMENT
1   input   tcp    accept  true     eth0   -       [22]    0.0.0.0/0    -     -     Allow SSH
2   input   icmp   drop    true     -      -       -       -            -     -     Drop ping
```

Filter only enabled rules:

```bash
netfence list --enabled
```

---

### Show / Set Default Policies

Show defaults:

```bash
netfence defaults
```

Example output:

```
CHAIN    POLICY
input    accept
forward  accept
output   accept
```

Set defaults:

```bash
netfence set-defaults --input drop --forward drop --output accept
```

---

### Add Rule

Allow SSH:

```bash
netfence add-rule --chain input --proto tcp --ports 22 --action accept --enabled --comment "Allow SSH"
```

Drop ICMP:

```bash
netfence add-rule --chain input --proto icmp --action drop --enabled --comment "Drop ping"
```

---

### Delete Rule

Delete rule with ID 2:

```bash
netfence del-rule 2
```

---

### Export / Import Configuration

Export rules and defaults to YAML:

```bash
netfence export --file ruleset.yaml
```

Import back:

```bash
netfence import --file ruleset.yaml
```

---

### Preview Ruleset

Preview generated nftables rules:

```bash
netfence dryrun
```

---

### Apply Ruleset

Apply current ruleset:

```bash
netfence apply
```

---

## Notes

* Database is stored in `/etc/firewall.db`.
* Audit log records who changed what and when.
* RBAC:

  * **admin** – full access.
  * **operator** – can add/delete rules and apply.
  * **viewer** – read-only access.
