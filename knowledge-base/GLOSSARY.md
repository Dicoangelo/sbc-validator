# SBC Validator: Domain Glossary

Grounding the telecom and product vocabulary used throughout the project.

## Core telecom / SIP

- **SBC (Session Border Controller):** the security and interworking gateway at
  the edge of a real-time voice network. Sits between the enterprise and the
  carrier / cloud (e.g., Microsoft Teams). Vendors: AudioCodes (Mediant), Cisco
  (CUBE), Ribbon (SBC Core / CNe), Oracle (Acme Packet), Metaswitch, Ericsson, Nokia.
- **B2BUA (Back-to-Back User Agent):** the SBC's core architecture. It fully
  terminates the incoming session on one leg and originates a brand-new
  corresponding session on the other leg, rather than forwarding packets. Two
  separate calls bridged together; an "air gap." Enables security and translation
  but defies simple automation.
- **Leg:** one side of the B2BUA. The Teams/external leg vs the carrier/internal
  (PBX/PSTN) leg. They often differ in transport, codecs, and security, so the SBC
  translates between them.
- **SIP (Session Initiation Protocol):** the signaling protocol that sets up,
  modifies, and tears down calls. Layer 5. Messages: INVITE, OPTIONS, ACK, BYE,
  CANCEL, etc.
- **SDP (Session Description Protocol):** the media negotiation carried inside SIP
  (codecs, IP/port, encryption). A mismatched SDP payload profile can let a call
  connect but destroy the audio.
- **OPTIONS keep-alive:** out-of-dialog SIP pings that track whether a peer (SBC or
  Teams) is healthy. If they fail, a trunk is marked down/busyout, rejecting calls.
- **Direct Routing:** Microsoft's method to connect an on-prem/SBC phone system to
  Microsoft Teams Phone System. Requires strict TLS, specific SIP header formats,
  certified SBCs, and the current Microsoft root CAs.
- **Dial-peer (Cisco) / sipTrunkGroup (Ribbon) / session-agent + realm (Oracle) /
  IPGroup + ProxySet (AudioCodes):** vendor-specific constructs that define the
  legs and routing.

## Security / certificates

- **TLS:** encrypts the SIP signaling. Direct Routing mandates it on the Teams leg.
- **mTLS (mutual TLS):** both sides present certificates. Required by Direct Routing.
- **EKU (Extended Key Usage):** certificate attribute. serverAuth is required for
  the SBC leaf by Direct Routing (clientAuth-only/dual-use is being deprecated).
- **CN / SAN (Common Name / Subject Alternative Name):** the names a certificate
  is valid for. The SBC FQDN in the SIP Contact header must match one of them.
  Wildcards (\*.domain) are supported (one label).
- **Trust anchor / root CA / chain:** the certificate chain must terminate at a
  Microsoft-trusted root. The 2026 migration moves the required root set (DigiCert
  G5 in, retired Baltimore out).
- **SRTP (Secure RTP):** encrypts the media. The external leg typically requires
  SRTP; the carrier leg may be plain RTP, so the SBC interworks between them.
- **ACL (Access Control List):** the firewall rules governing which IPs reach the
  SBC's signaling and media planes. Default-deny + a tight carrier allow-list is
  the secure posture.

## Media

- **Codec:** audio encoding (G.711 PCMU/PCMA narrowband; G.722, SILK, OPUS
  wideband; G.729 compressed). Legs must share a codec or the SBC must transcode.
- **Transcoding / DSP:** converting between codecs in real time, consuming Digital
  Signal Processor resources. Insufficient DSP capacity under load = dropped/
  degraded calls (DSP exhaustion).
- **NAT traversal / symmetric RTP / one-way audio:** if the SBC advertises a
  private IP in SDP or lacks symmetric-RTP latching, media from NATed peers is
  dropped, producing one-way or no audio (the top customer complaint).
- **DTMF (RFC 2833 / telephone-event):** keypad tones. Method mismatches across
  legs break IVR/voicemail navigation.

## Operations

- **MTTR (Mean Time To Repair/Resolution):** for SBC misconfigs, commonly 1 to 4+
  days. The pain the product attacks.
- **HA (High Availability) / failover / drift:** active and standby SBC nodes. If
  their trust stores drift, a failover during the 2026 CA rotation hard-stops calls.
- **BYOC (Bring Your Own Carrier):** small orgs running their own SBC into Teams/
  Zoom without a NOC or proactive monitoring.
- **Shift-left:** moving validation from reactive break-fix to proactive
  pre-deployment (a CI/CD gate).

## Product terms

- **NormalizedConfig:** the vendor-neutral model every parser emits and every
  validator consumes. The vendor-agnostic contract.
- **Domains A-G + S:** the eight validation domains (see the master synthesis).
- **Verdict:** PASS / REVIEW / BLOCK. Any CRITICAL forces BLOCK.
- **Gated validator:** one that stays silent unless the source carries the relevant
  info (routing, ACL, trust store), to avoid false positives.
- **validate / simulate / explain / diff / fleet / serve / demo / report:** the
  eight CLI commands.
