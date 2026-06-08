# SBC Validator: Canonical Failure-Mode Catalog

The authoritative taxonomy of SBC misconfiguration failure modes (sourced from
vendor hardening guides and the whitespace research corpus), each mapped to the
exact triggering condition, the user-visible symptom, and the validator domain
that owns it. This is the master checklist the product is measured against.

## 1. TLS / Certificate / CA

- **Trust-chain disconnection (CA migration).** Condition: mismatched/missing root
  or intermediate certs during a CA migration. Symptom: the SBC silently drops all
  encrypted signaling. Domain C (trust-anchor chain).
- **FQDN vs CN/SAN mismatch.** Condition: the cert CN/SAN does not cover the SBC
  FQDN (wildcards allowed). Symptom: TLS/HTTPS provisioning fails; trunk won't
  connect; Teams rejects. Domain C (wildcard-aware).
- **Cipher suite / mTLS failure.** Condition: mTLS disabled or no approved cipher
  suite. Symptom: trunk rejects the connection (SIP 400 / TLS handshake failure).
  Domain C (mTLS done; per-config cipher matching is backlog).

## 2. SIP header / normalization

- **Regex rewrite typo.** Condition: one wrong character in a header-rewrite regex
  (e.g., the Teams Contact header). Symptom: INVITEs fail instantly, trunk appears
  dead, multi-day MTTR. Partial: domain B checks normalization presence (static
  validation cannot verify arbitrary regex correctness).
- **Config-wizard overwrite.** Condition: a vendor wizard (AudioCodes) applied to a
  live device resets unmanaged params to factory defaults. Symptom: custom security
  silently broken. Process issue, not a config-state check.

## 3. NAT / media / SDP

- **Private IP advertised in SDP.** Symptom: remote media sent to an unreachable
  private address, one-way audio. Domain D.
- **Missing symmetric RTP.** Symptom: media from NATed peers dropped. Domain D.
- **Media-plane ACL omission.** Condition: signaling IPs permitted but the carrier's
  RTP media subnet is not. Symptom: INVITE accepted, inbound RTP dropped, one-way
  audio misdiagnosed as codec/NAT. Domain S (media-plane ACL).
- **Payload profile mismatch (symmetric/asymmetric SDP).** Symptom: call connects
  but audio is destroyed once media starts. Partial: domain D symmetric RTP.

## 4. Codec / transcoding

- **Transcoding / DSP exhaustion.** Condition: incompatible codecs force the SBC to
  transcode without adequate DSP allocation (e.g., internal G.711 vs external
  G.729). Symptom: dropped calls / degraded media under load. Domain E (flags
  transcode-required + DSP caveat + wideband downgrade; does not size DSP capacity).

## 5. Routing / dial-plan / classification

- **Missing route direction / unclassified Teams.** Symptom: SIP 404; inbound or
  outbound calls get no route. Domain G (AudioCodes today).
- **Overly broad CIDR permit.** Condition: a /16 where the carrier publishes a /28.
  Symptom: the SIP parser is exposed to unauthorized hosts. Domain S (broad CIDR).
- **Top-down rule shadowing.** Condition: a broad permit above a specific deny on a
  top-down ACL engine. Symptom: specific rules register zero hits, malicious
  traffic slips through. Backlog (needs ordered-ACL model).

## 6. HA / failover

- **OPTIONS keep-alive timeout / busyout.** Condition: out-of-dialog OPTIONS ping
  fails to get a 200 OK. Symptom: dial-peer goes busyout, trunk down, calls
  rejected. Domain B (both legs).
- **HA trust-store / keepalive drift.** Condition: standby node config drifts from
  active. Symptom: a failover during the 2026 CA rotation lands on a node with the
  wrong trust set, calls hard-stop. The `diff` (HA) check (CRITICAL).
- **HA wizard conflict.** Condition: vendor wizard run in HA mode (unsupported).
  Symptom: provisioning halts. Process issue.

## 7. Security / DoS

- **Missing default-deny / SIP unknown-peer IPACL exposure.** Condition: relying on
  the system-default "admit any peer." Symptom: open to SIP scanning, REGISTER
  brute force, DDoS reflection. Domain S (no default-deny).
- **IPv6 plane neglect.** Condition: strict IPv4 default-deny but empty IPv6 ACL.
  Symptom: effectively default-allow over IPv6, perimeter bypass. Domain S (IPv6
  neglect).
- **Disabled RTP source-address validation.** Condition: SBC does not check inbound
  media against the SDP-negotiated peer. Symptom: rogue media accepted, reflection
  DoS / media injection. Domain S (RTP source validation).

## The B2BUA two-leg validation map

| Concern | Teams (external) leg | Carrier (internal) leg |
|---|---|---|
| Transport | must be TLS (domain B) | often UDP/TCP by design |
| OPTIONS keep-alive | checked (B) | checked, advisory (B) |
| Cert / EKU / chain / roots | domain C | TLS posture not yet inspected |
| SRTP / media security | domain C | SRTP-RTP interworking not yet modeled |
| Codec / transcode | domain E (overlap + transcode) | domain E |
| Access-control posture | n/a | domain S (AudioCodes firing; others gated) |
| Identity (Contact host) | must be FQDN, not IP (403) | domain B |

## Microsoft Direct Routing requirements (from Microsoft Learn)

- OPTIONS exchanged with sip.pstnhub.microsoft.com on port 5061 over TLS; a 200 OK
  is required before calls flow.
- The Contact header hostname must be the SBC FQDN (an IP yields 403 Forbidden) and
  must match the cert CN/SAN; wildcards supported per RFC 2818 (one label).
- Certified SBC devices and firmware versions are required by Microsoft.
- The current Microsoft root CA set must be in the trust store (the 2026 migration).
- Exact cipher list / ports / OPTIONS interval: encoded in the signed ruleset;
  the trust roots are sourced from Microsoft Learn with SHA-1 thumbprints.
