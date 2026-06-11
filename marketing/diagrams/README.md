# SBC-AutoOps Diagrams — generation method (custom paperbanana + nanobanana)

Canonical artifacts, and exactly how to reproduce them, so no session re-derives this.

## Files
| File | What it is | Engine |
|---|---|---|
| `sbc-autoops-architecture-refined.webp` | **Canonical architecture** (4K master). Six-zone air-gapped pipeline: INPUT (AudioCodes/Cisco CUBE/Ribbon/Oracle Acme/Metaswitch Perimeta) → PARSERS → NORMALIZED MODEL → VALIDATORS (8 domains) → MODES (validate/simulate/explain) → OUTPUT (PASS/REVIEW/BLOCK). Signed rule bundle "only inbound", anonymized findings out. | researchgravity refined pipeline |
| `sbc-autoops-architecture-web.png` | 1800px web copy of the above (embedded in `business-case.html` #how). | `sips -Z 1800` |
| `sbc-autoops-architecture.webp` | First-pass architecture (raw nano-banana, no critic). Superseded; kept as alt. | nano-banana-pro raw |
| `sbc-autoops-positioning.webp` | Positioning chart: call-life timeline (red X at TLS handshake) + three coverage bars (AIOps blind / single-vendor siloed / SBC-AutoOps pre-deploy). | nano-banana raw |
| `sbc-autoops-forcing-calendar-refined.webp` | **Forcing-event calendar 2026-2029** (4K master). Timeline: Wave 1 Microsoft CA/EKU (Mar 7-roots / Apr edge rotation / Jun serverAuth-only), Wave 2 cert-lifetime step chart 398→200→100→47 days, Wave 3 Chrome root policy, Wave 4 PQC. Footer: "each wave = a new signed rule bundle, same engine." Source: `insights/09-cadence-forcing-events.md`. The "cadence, not climax" evidence image. | researchgravity refined pipeline |
| `sbc-autoops-forcing-calendar-web.png` | 1800px web copy of the above. | `sips -Z 1800` |
| `sbc-autoops-call-death-chain-refined.webp` | **Where Calls Die** (4K master). Four-link chain TLS→SIP→SDP→media→STABLE, each with failure card: verdict (NO_CONNECT/REJECTED/NO_MEDIA/ONE_WAY_AUDIO), user symptom, two real check IDs. Source: `sbc_validator/call_sim.py` hardstop maps. | researchgravity refined pipeline |
| `sbc-autoops-call-death-chain-web.png` | 1800px web copy of the above. | `sips -Z 1800` |
| `sbc-autoops-silent-failure.webp` | Editorial narrative image: NOC with all-green dashboards while voice is silently dead ("you hear about it from users, not a dashboard"). Hero / LinkedIn / outreach asset. Web copy is `-web.jpg` (photo → jpeg). | nano-banana-pro raw (2K) |
| `sbc-autoops-hero-truth-layer.webp` | **Front-end hero visual** (4K + `-web.png`). Abstract "truth layer": five chaotic vendor streams pass through a translucent garnet plane and emerge as ordered parallel lines. NO text; right side intentionally quiet (terminal widget sits there). For the light hero on business-case.html. | refined pipeline (SUPERMAX council spec) |
| `sbc-autoops-architecture-dark.webp` | **Dark-theme architecture** (4K + `-web.png`) for the `#how` dark section. Six zones on rail blue-black `#161c25`, uniform faint-white panels, terminal-palette verdict pills, "Air-gapped in VPC" dashed boundary, "signed rules in"/"anon findings out" chips. | refined pipeline (SUPERMAX council spec) |

| `sbc-autoops-call-death-chain-dark.webp` | **Dark-theme call-death chain** (4K + `-web.png`) for the `#regulated` dark section. Four garnet-soft chain links → STABLE pill, four failure cards with VERDICT/SYMPTOMS/CHECK-ID eyebrows and real check IDs. | refined pipeline (SUPERMAX council spec) |
| `sbc-autoops-og-banner.webp` | **OG/social banner** (4K + `-web.png`; export 1200×630 for og:image). Brand mark + "The independent *truth* layer / for real-time voice" + mono trustline. Supersedes `og-card.png` candidate. | refined pipeline (SUPERMAX council spec) |

### SUPERMAX front-end set (2026-06-10)
All four specs live in `SPECS-frontend-set.md`, authored by the sbc-image-council
(brand-guardian constraint sheet → design-engineer specs → team-lead renders →
visual-qa scoring). Six renders total for four keepers (~$1.85): architecture-dark
v1 leaked critic meta-text, call-death-chain v1 leaked "15%...90%" size-hierarchy
percentages. Both failure masters remain in `~/visual_assets/` for reference.

**New banked lessons (2026-06-10):**
- The critic can inject its OWN meta-text two ways: style words as labels
  ("Curved garnet arrow...") AND size-hierarchy percentages ("15%"). Specs must
  enumerate ALL allowed visible strings and explicitly ban the percent character.
- Dark sections use the rail palette `#161c25→#141a23` with garnet-soft `#c14d80`
  accents and terminal verdict colors (`#5fd39b`/`#ff6b5e`) — NOT ink `#15181e`
  or raw garnet. Source: brand-guardian constraint sheet.
- The model loves giving each diagram zone its own pastel fill. Pin: "ALL panels
  IDENTICAL faint translucent white; no teal/lavender/amber/gold panels."

## The custom config (paperbanana + nanobanana) — THE method to use
The high-quality path is the **researchgravity refined pipeline**, not raw nano-banana.
It is Planner → Stylist → [VLM TextCritic] × T → single render. The critic (Gemini 3.1 Pro
VLM) reasons in TEXT over the description and regenerates the prompt each round — catching
element-crowding (>15-18 boxes), label garbling (>22-25 chars), and constraint violations
(e.g. a hallucinated 3D funnel) BEFORE spending an image render.

MCP tool: `mcp__researchgravity__generate_refined`
Cost-optimal max-quality settings (verified 2026-06-09):
- `quality: "max"` (4K), `resolution: "4K"`, `aspect_ratio: "16:9"`
- `refine_mode: "text"` ← critical: runs the critic loop in text, renders the image **once**.
  `visual` mode re-renders every round (3-7x the Gemini image cost) for the same quality.
- Image renders per run = 1. Cost ≈ $0.32/run, ~150s. Two runs got the canonical (one to
  fix critic-introduced genericization of vendor names + leaked density-weight footers).

Reproduce:
```
mcp__researchgravity__generate_refined(
  quality="max", resolution="4K", aspect_ratio="16:9", refine_mode="text",
  caption="<one-sentence intent>",
  source_context="<flat-vector spec: zones, garnet #9d1b54, labels <22 chars,
                   named vendors, NO percentages/weights, no 3D, no funnels>")
```
Output lands in `~/visual_assets/refined-<id>_<ts>.png`; copy into this dir.

Raw nano-banana (no critic, for quick one-offs):
```
uv run ~/projects/agents/clawdbot/skills/nano-banana-pro/scripts/generate_image.py \
  --resolution 2K --filename "$PWD/name.png" --prompt "..."
```
GEMINI_API_KEY is set; uv at ~/.local/bin/uv.

## Lessons (banked)
- `refine_mode:"text"` is the whole cost story — same quality as visual, one render.
- The critic WILL shorten labels and may genericize proper nouns; pin them with explicit
  "use the real vendor names" + "keep labels under 22 chars" + "do NOT print any percentages".
- Brand garnet hex is `#9d1b54` (matches business-case.html), white background for embed.
- Fable 5 cannot generate images (text model); Gemini/Nano Banana Pro is the only image engine.

**2026-06-11:** all 4K masters converted to WebP q90 (105MB -> 4MB, ~0.4MB each at full 4K). True PNG originals remain in `~/visual_assets/`. Web copies (`-web.png`) and `og-banner-1200x630.png` unchanged.
