# Evaluating SBC-AutoOps? Start here.

This is the five-minute path for a security or platform reviewer. You will verify
what you received, run the tool, prove it has no network, and point it at one of
your own configs. **You never send us a config.** Raw SBC configs stay on your box;
that is the entire design, and you can prove it below.

If you only have sixty seconds, run the two lines under step 2 and read step 4.

---

## 1. Get it, and verify it (don't trust it)

Two ways in, depending on what you were sent. Both end at the same manifest check.

**If you were sent the repository link** (clone it):

```bash
git clone https://github.com/Dicoangelo/sbc-validator.git
cd sbc-validator
git log --oneline -1               # the tagged release commit you were pointed at
shasum -a 256 -c SHA256SUMS         # every tracked file against the in-tree manifest
```

**If you were sent the source tarball** (with a SHA-256 in the email body):

```bash
shasum -a 256 sbc-validator-*-src.tar.gz    # must match the hash in the email
tar -xzf sbc-validator-*-src.tar.gz && cd sbc-validator-*/
shasum -a 256 -c SHA256SUMS                 # the same manifest check
```

Either path ends with the manifest verifying clean (every tracked file `OK`; the
only file it cannot self-cover is `SHA256SUMS` itself). There is no pre-built
binary to trust: you build from source. A runtime CycloneDX SBOM ships at
`docs/sbom-cyclonedx.json`. The engine has exactly one *direct* runtime dependency,
`cryptography`; a `pip list` shows it plus its own transitive deps (`cffi`,
`pycparser`) and nothing else.

## 2. Run it (no container required)

```bash
python3 -m venv .venv && .venv/bin/pip install .     # Python 3.10+
.venv/bin/sbc-validator demo
```

`demo` validates a mixed five-vendor fleet, predicts a call that dies at the TLS
handshake, explains a rejected call from a packet capture, and rolls up 2026
Microsoft Direct Routing CA-migration readiness. That is the whole product in one
command, against bundled sample configs.

Every command below uses files that exist in this tarball, so they all run as-is:

```bash
.venv/bin/sbc-validator validate samples/audiocodes_teams_real.ini   # PASS, risk 4
.venv/bin/sbc-validator validate samples/broken_a.ini                # BLOCK, exit 1
.venv/bin/sbc-validator simulate samples/audiocodes_min.ini          # NO_CONNECT at TLS
.venv/bin/sbc-validator explain  samples/one_way_audio.pcap          # ONE_WAY_AUDIO + fix
.venv/bin/sbc-validator diff     samples/audiocodes_min.ini samples/audiocodes_standby.ini
.venv/bin/sbc-validator fleet    samples                             # "X of N ready"
.venv/bin/sbc-validator serve                                        # local console, reads results/ only
```

`validate` returns a non-zero exit code on BLOCK, so it gates a CI pipeline. The
signed ruleset ships in-tree, so `--ruleset` is optional.

## 3. Prove it has no network (the air gap)

Configs cannot leave a host that has no route off it. Prove that yourself rather
than taking our word for it:

```bash
docker build -t sbc-validator .

# A. run the whole product with the network physically removed
docker run --rm --network none sbc-validator demo            # exit 0, full showcase

# B. control: the SAME image WITH a network can reach the internet,
#    which proves the silence in A is the --network none flag, not a dead image
docker run --rm --entrypoint python3 sbc-validator -c \
  "import socket; s=socket.socket(); s.settimeout(3); \
   print('reachable WITH network' if s.connect_ex(('8.8.8.8',53))==0 else 'no egress')"

# C. and with --network none, there is no route at all
docker run --rm --network none --entrypoint python3 sbc-validator -c \
  "import socket; s=socket.socket(); s.settimeout(3); \
   print('UNEXPECTED: reachable' if s.connect_ex(('8.8.8.8',53))==0 else 'CONFIRMED: no route, air gap holds')"
```

B is the one worth running: it shows the container *can* talk when allowed, so the
silence under `--network none` is the OS network namespace, not a broken build.

The data-flow contract, written to be lifted directly into a security review with a
file reference behind every claim, is in **[docs/SECURITY.md](docs/SECURITY.md)**.

## 4. Run it on your own config

This is the point. Export one SBC config from your estate and validate it locally,
air-gapped. Nothing leaves the box.

```bash
docker run --rm --network none -v "$PWD:/work" sbc-validator \
  validate /work/your-sbc-export.ini --html /work/report.html
```

Supported inputs today: AudioCodes `.ini`, Cisco CUBE IOS-XE running-config, Ribbon
set-config, Oracle Acme ACLI, Metaswitch Perimeta adjacency export. The exact export
commands per vendor are in **[docs/CONFIG-REQUEST.md](docs/CONFIG-REQUEST.md)** (it is
written as an intake spec, but it doubles as the "how do I export mine" guide).

For full certificate-chain depth (EKU, self-signed, root-anchor checks), also hand it
the leaf PEM next to the config; without it the certificate checks stay silent and say
so (`verify out-of-band`) rather than guess. Everything else runs from the config alone.

## 5. What it will and will not tell you

The tool refuses to guess. A wrong verdict is the one thing a pre-deployment control
cannot afford, so any check it cannot ground in your actual config stays **silent**
rather than asserting a PASS or a BLOCK it did not observe. If a domain is quiet for
your vendor, that is the design, not a gap, and `docs/VALIDATOR-COVERAGE.md` says
exactly which checks are active per vendor and why.

---

**Questions, or want a working session on one of your configs?**
Dico Angelo, Metaventions AI. Telecom architecture by Philip Drammeh.
