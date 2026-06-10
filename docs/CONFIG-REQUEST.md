# What we need from you: one real SBC config per vendor

**Why this is the unlock.** The validator is built end-to-end on five vendors,
but two of the deepest checks, **routing (domain G)** and **security /
access-control (domain S)**, are only *firing* for AudioCodes, because that's the
only vendor whose real grammar we've modeled against ground truth. For Cisco,
Ribbon, Oracle, and Metaswitch they stay deliberately **silent** (no false
positives) until we see a real export. One real config per vendor turns those
domains on for that vendor and hardens the parser against production grammar.
**Even one config (any vendor) is high value.**

## Exactly what to export

| Vendor | How to export | What it unlocks |
|---|---|---|
| **AudioCodes Mediant** | Web GUI: *Setup → Administration → Maintenance → Configuration File → Save INI File* (the full `.ini`, with tables). Or the SBC Config Wizard output. | Hardens the real table parser; richer routing + firewall (AccessList) coverage |
| **Cisco CUBE** | `show running-config` (full), or at least `show running-config | section voice` plus `dial-peer` and `voice class tenant` blocks | Routing (dial-peer/tenant) + trusted-list ACL extraction |
| **Ribbon SBC Core** | `show configuration` (the `set ...` flat config) | Routing labels + ipAccessControlList extraction |
| **Oracle Acme Packet** | `show running-config` / `display-current-cfg` (ACLI) | `local-policy` routing + `access-control` extraction |
| **Metaswitch Perimeta** | The CLI config export (`adjacency sip` blocks plus the system/profile level) | TLS profiles, codec policy + media config (today only the adjacency layer is modeled) |
| **TE-Systems anynode** | The configuration export/backup from the web UI | Would unlock vendor #6: anynode is GUI-driven, so we cannot model its export format without a real one |
| **Avaya ASBCE** | The EMS configuration backup/export | Would unlock vendor #7: same, the export format is not publicly documented |

## How to sanitize it (so it's safe to hand us)

The tool never needs secrets, and the engine runs air-gapped when *you* run it.
For us to harden the parser, we only need the **structure**, so:

- **Remove** any passwords, shared secrets, SNMP/community strings, and private
  keys. We never parse these.
- **Keep** the structural grammar: table/section names, parameter names,
  transport/port settings, codec lists, routing rules, ACL/firewall rules.
- **Optional**: replace public IPs and real FQDNs with consistent placeholders
  (e.g. `sbc1.example.com`, `203.0.113.10`) as long as you keep the *shape* (a
  /28 stays a /28, an FQDN stays an FQDN, a wildcard stays a wildcard). Routing
  and ACL checks care about structure, not the literal values.

A single sanitized config per vendor, pasted into a text file, is all we need.

## What you'll get back per config

For each real config we'll: (1) confirm the parser reads it cleanly (or fix it
against the real grammar), (2) light up routing + access-control for that vendor,
and (3) add it as a regression fixture so it never breaks again. That's the same
path that made AudioCodes real (we modeled it against the Mediant manual).
