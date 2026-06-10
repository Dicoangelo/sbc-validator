# SBC-AutoOps Diagrams — generation method (custom paperbanana + nanobanana)

Canonical artifacts, and exactly how to reproduce them, so no session re-derives this.

## Files
| File | What it is | Engine |
|---|---|---|
| `sbc-autoops-architecture-refined.png` | **Canonical architecture** (4K master). Six-zone air-gapped pipeline: INPUT (AudioCodes/Cisco CUBE/Ribbon/Oracle Acme/Metaswitch Perimeta) → PARSERS → NORMALIZED MODEL → VALIDATORS (8 domains) → MODES (validate/simulate/explain) → OUTPUT (PASS/REVIEW/BLOCK). Signed rule bundle "only inbound", anonymized findings out. | researchgravity refined pipeline |
| `sbc-autoops-architecture-web.png` | 1800px web copy of the above (embedded in `business-case.html` #how). | `sips -Z 1800` |
| `sbc-autoops-architecture.png` | First-pass architecture (raw nano-banana, no critic). Superseded; kept as alt. | nano-banana-pro raw |
| `sbc-autoops-positioning.png` | Positioning chart: call-life timeline (red X at TLS handshake) + three coverage bars (AIOps blind / single-vendor siloed / SBC-AutoOps pre-deploy). | nano-banana raw |

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
