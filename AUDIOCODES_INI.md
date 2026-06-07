# AudioCodes .ini: Real Config Grammar and Mapping

Reference for how a real AudioCodes Mediant SBC config is structured and how this
validator maps it to the vendor-neutral model. Source: *Mediant Software SBC
User's Manual, ver 7.6*. Implemented in `sbc_validator/parsers/audiocodes_ini.py`.

The simplified `[sip:Name]` / `[tls:Name]` form used by the older smoke-test
samples is NOT what a Mediant exports. Real config is scalar parameters plus
indexed parameter **tables**.

## The table format

```
EnableMediaSecurity = 1            ; scalar parameter

[ SIPInterface ]                   ; table title
FORMAT Index = InterfaceName, ApplicationType, TLSContext, TCPPort, TLSPort;
SIPInterface 0 = "Teams", 2, "Teams-TLS", 0, 5061;   ; data line(s)
[ \SIPInterface ]                  ; end-of-table mark
```

- The FORMAT line names the columns; data lines are read in that order.
- A data line starts with the table name + index, values comma-separated, ends `;`.
- Tables that reference other tables must appear after their dependency.

## How Direct Routing is expressed (cross-table references)

There is no single "Teams interface" object. The Teams leg is assembled from
several tables that point at each other:

| Table | Role | Key columns we read |
|---|---|---|
| `ProxyIP` | the Teams proxy FQDNs + transport | ProxySetId, IPAddress, TransportType (2=TLS) |
| `ProxySet` | groups ProxyIPs; keep-alive; TLS context | ProxyName, TLSContext, ProxyKeepAliveType |
| `SIPInterface` | transport/ports + TLS context | InterfaceName, TLSContext, TCPPort, TLSPort |
| `IPProfile` | SRTP behaviour + allowed coders | ProfileName, SBCMediaSecurityBehaviour, SBCAllowedAudioCodersGroupName |
| `CodersGroup0` | the audio coder list | CodersGroupName, Coder |
| `IPGroup` | ties ProxySet + IPProfile + SIPInterface | Name, ProxySetName, IPProfileName, SIPInterfaceName |
| `MediaRealm` | media addressing | MediaRealmName, IPAddress |

**Leg identification:** the mapper finds the `ProxySet` whose `ProxyIP` rows
contain `sip.pstnhub.microsoft.com`, then the `IPGroup` that references that
ProxySet is the Teams leg. Transport, SRTP, codecs, and keep-alive are resolved
by following that IPGroup's references.

## Media security (SRTP)

- `EnableMediaSecurity = 1` (global) turns on SRTP capability.
- `SBCMediaSecurityBehaviour` (per IP Profile): 0=as-is, 1=SRTP/secured, 2=RTP,
  3=both. SRTP is negotiated for 1 or 3. The mapper sets `srtp_enabled = (global
  EnableMediaSecurity) and behaviour in {1,3,...}`.
- **Verified against the AudioCodes Teams DR config note** (Enterprise model): the
  GUI labels this "SBC Media Security Mode" with values **Secured** (Teams leg)
  and **Not Secured** (SIP-trunk leg), so the mapper accepts the named values too.
  The Teams coder group is `AudioCodersGroups_Teams` (AMR-WB, SILK-NB/WB, G.711
  A/U-law, G.729), bound to the IP Profile via the **Extension Coders Group**
  (`SBCExtensionCodersGroupName`). Note: published config notes are GUI walkthroughs
  with screenshots, not raw `.ini` dumps; a verbatim raw `.ini` comes from the SBC
  Configuration Wizard export or a customer config. `samples/audiocodes_teams_real.ini`
  mirrors the config note's parameter names and values.

## The correctness insight: certs and roots are NOT in the .ini

A Mediant `.ini` references a TLS context by name, but the **leaf certificate and
the trust-store root CAs are imported certificate files, not config text.** So
from a real `.ini` alone we cannot enumerate the 7 required roots or inspect the
leaf. The validator handles this honestly:

- The mapped Teams TLS context is `introspectable=False`.
- Domain C emits **`C.CA.TRUST_STORE_UNAVAILABLE` (LOW)** and **`C.CERT.UNAVAILABLE`
  (LOW)** with "verify out-of-band" guidance, instead of false-claiming
  `C.CA.ROOT_MISSING` / `C.CERT.MISSING` (CRITICAL). This was the key fix: without
  it the tool would scream CRITICAL on every real config.
- To get the full cert checks (EKU/SAN/expiry/chain), supply the leaf PEM via an
  annotated comment line: `; sbc-validator: leaf-cert path/to/leaf.pem`.

## Coverage and roadmap

Implemented: the table reader (FORMAT/data/end-mark, quoted values, scalar
params), and the DR mapper (Teams-leg resolution, transport, SRTP, codecs,
keep-alive, TLS context, FQDN from `SIPGatewayName`). Best-effort, alias-tolerant
column lookups so version-to-version column differences degrade gracefully.

Not yet mapped (roadmap, needs a real exported config to build against):
NATTranslation / interface NAT for the true public media address, Message
Manipulations (normalization detection), Classification / IP2IPRouting, and the
richer IPProfile coder-negotiation fields. `samples/audiocodes_teams_real.ini` is
a realistic abridged example; a full vendor config-note appendix `.ini` is the
next fidelity test (see the sourcing notes in chat / project memory).
