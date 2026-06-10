# Front-End Image Set — Render-Ready Specs

Four production specs for `mcp__researchgravity__generate_refined`
(`quality:"max"`, `resolution:"4K"`, `refine_mode:"text"`). Authored against the
canonical assets in this directory, the CSS tokens in `../business-case.html`, and
brand-guardian's constraint sheet (task #1). Follow `README.md` lessons exactly.

## Locked brand tokens (apply to every spec)

### Light contexts (hero)
- Canvas `#f7f8fa` (never pure white). White panels with `#e4e7ec` 1px hairlines.
- Text tiers: ink `#15181e`, soft `#525a66`, faint `#8b95a1`.
- Accent: garnet `#9d1b54`.

### Dark contexts (#how, #regulated)
- Canvas blue-black `#161c25` graduating to `#141a23`.
- Cards `rgba(255,255,255,0.035)` with `rgba(255,255,255,0.09)` hairline borders.
- Lines `#27313e`. Body text `#aeb8c4`. Muted `#6b7785`. White emphasis only on headlines.
- Accent on dark is garnet-SOFT `#c14d80` (NOT raw `#9d1b54`).
- Verdict tokens on dark use terminal palette: green `#5fd39b`, crit `#ff6b5e`.

### Semantic colors (severity / verdict ONLY, never decorative)
- CRITICAL / BLOCK `#c0392b`, HIGH / REVIEW `#e07a1f`, PASS `#1f8a6d`.

### Typography
- 800-900 weight, tight-tracked geometric grotesque sans headlines.
- At most ONE serif-italic garnet accent phrase per composition.
- Eyebrow labels: all-caps mono with a short garnet rule prefix.
- Mono for ALL check IDs and verdict tokens.

### Layout
- 1px hairlines only. 16px card radius. Max 15-18 labeled boxes.
- Soft barely-there shadows. Editorial consulting aesthetic
  (McKinsey-meets-modern-SaaS). No startup gradients, no neon, no glassmorphism,
  no 3D, no funnels, no isometric.
- Real vendor names always spelled out: AudioCodes, Cisco CUBE, Ribbon,
  Oracle Acme, Metaswitch Perimeta. Brand name is always "SBC-AutoOps".

## HARD RULES against the known critic-leak failure mode (every spec)
1. The ONLY visible text in each image is the exact quoted label strings listed
   in that spec. Nothing else may be rendered as text.
2. Never print style or meta words as visible text. Forbidden in pixels:
   `curved`, `dashed`, `dotted`, `bold`, `small`, `SMALL`, `garnet`, `arrow`,
   `signed`, `flat`, `vector`, `label`, `zone`, plus any sentence from this spec.
   (Exception: the literal arrow labels "signed rules in" / "anon findings out"
   in spec 2 are intentional content, not style words.)
3. Every visible label is under 22 characters.
4. Do not print any percentages, weights, or density figures.
5. No em dashes in rendered text. Use a middot "·" or a hyphen "-".

---

## 1 · hero-truth-layer
- **Placement:** light hero section (`.hero`), right/behind the floating terminal
  widget. Must not compete with it - calm, atmospheric, no text.
- **aspect_ratio:** `16:9`
- **caption:** Chaotic multi-vendor SBC configuration streams converging through a single translucent garnet plane and emerging as one clean ordered lane.

```
source_context:
A flat-vector editorial concept illustration on a near-white background (#f7f8fa,
never pure white), McKinsey-meets-modern-SaaS consulting polish, generous negative
space, calm and premium, barely-there soft shadows only. LEFT THIRD: five tangled,
chaotic streams of thin 1px lines and small fragmented rectangular config-card
glyphs in muted grey-blue (#525a66 and #8b95a1), crossing and overlapping in
disorder, each stream a slightly different texture to suggest five different vendor
formats. CENTER: a single tall translucent vertical plane in brand garnet (#9d1b54)
at about 28% opacity with a crisp 1px garnet edge, standing like a pane of glass
that all five streams pass THROUGH. RIGHT THIRD: the same five streams emerge from
the plane transformed into one set of clean, evenly spaced, perfectly parallel
horizontal garnet lines, order out of chaos. Subtle soft garnet radial glow behind
the plane only. Composition weighted to the left and center so the right two-fifths
stays open and quiet. NO text anywhere. No 3D, no perspective box, no funnel shape,
no literal pipes or plumbing, no human figures, no logos, no gradients on shapes,
no neon, no glassmorphism. Pure abstract 2D vector. Visible text in the image: NONE.
Do not render any words, letters, labels, percentages, or style descriptions as
visible text.
```

---

## 2 · architecture-dark
- **Placement:** `#how` dark section. A dark-theme re-render of the canonical
  six-zone pipeline (`sbc-autoops-architecture-web.png`), tuned for `.dark` bg.
- **aspect_ratio:** `16:9`
- **caption:** Six-zone air-gapped pipeline turning five vendor configs into one PASS / REVIEW / BLOCK verdict, signed rules in and anonymized findings out.

```
source_context:
A flat-vector technical architecture diagram on a dark blue-black background
(#161c25 graduating to #141a23), McKinsey-meets-modern-SaaS consulting production
polish, clean thin 1px hairlines in #27313e, body text #aeb8c4 with white emphasis
on headers. Card panels are faint translucent white (rgba 255 255 255 0.035) with a
1px rgba(255,255,255,0.09) border and 16px corner radius. The accent color is garnet
-soft #c14d80 (use this, not a deep raw garnet). A single horizontal pipeline of SIX
labeled zones, left to right, each zone a rounded-rect column panel with a garnet
-soft (#c14d80) header band and a short all-caps mono label:
Zone 1 label "INPUT" listing five small stacked vendor chips, each chip text one of:
"AudioCodes", "Cisco CUBE", "Ribbon", "Oracle Acme", "Metaswitch Perimeta".
Zone 2 label "PARSERS" with a small gear glyph.
Zone 3 label "NORMALIZED" with a small unified-schema node glyph.
Zone 4 label "VALIDATORS" with a 2x4 grid of eight tiny lettered tiles A B C D E F G S
and the sublabel "8 domains".
Zone 5 label "MODES" stacking three small chips: "Validate", "Simulate", "Explain".
Zone 6 label "VERDICT" stacking three pill badges: a green pill "PASS" (#5fd39b),
an amber pill "REVIEW" (#e07a1f), a red pill "BLOCK" (#ff6b5e).
Thin garnet-soft connector lines flow left-to-right between zones. A thin
rectangular boundary outlines all six zones to imply an air-gapped enclosure, with
one small top label "Air-gapped in VPC". Below the enclosure, two short horizontal
flows: a lower-left inbound line ending in a chip whose only text is "signed rules in",
and a lower-right outbound line starting from a chip whose only text is
"anon findings out".
The ONLY text that may appear anywhere in the image is exactly these strings:
"INPUT", "PARSERS", "NORMALIZED", "VALIDATORS", "8 domains", "MODES", "VERDICT",
"AudioCodes", "Cisco CUBE", "Ribbon", "Oracle Acme", "Metaswitch Perimeta",
"Validate", "Simulate", "Explain", "PASS", "REVIEW", "BLOCK",
"Air-gapped in VPC", "signed rules in", "anon findings out",
and the eight single letters A B C D E F G S.
Do NOT print any style or instruction words as visible text. The words curved,
dashed, dotted, bold, small, garnet, arrow, flat, vector, zone, label, weight must
NEVER appear as rendered text. No percentages, no numeric weights, no em dashes.
Keep every label under 22 characters. Flat 2D only, no 3D extrusion, no funnel, no
isometric, no neon, no glassmorphism.
```

---

## 3 · call-death-chain-dark
- **Placement:** `#regulated` dark section. Dark-theme variant of
  `sbc-autoops-call-death-chain-web.png`.
- **aspect_ratio:** `16:9`
- **caption:** A call is a four-link chain of TLS, SIP, SDP and media, and four failure cards name where it dies and the real check IDs behind each one.

```
source_context:
A flat-vector technical workflow diagram on a dark blue-black background (#161c25 to
#141a23), McKinsey-meets-modern-SaaS consulting polish, body text #aeb8c4 with white
emphasis, 1px hairlines #27313e, accent garnet-soft #c14d80. TOP ROW: a left-to-right
horizontal chain of four garnet-soft (#c14d80) rounded-rect link boxes connected by
thin garnet-soft connector lines, each box a short mono label in order:
"TLS handshake", "SIP signaling", "SDP offer/answer", "Media path". The chain
terminates at a green rounded pill (#5fd39b) labeled "STABLE". Small connector text
"next link" sits between boxes. BOTTOM ROW: four dark failure cards (faint
translucent white panel rgba 255 255 255 0.035, 16px radius, thin red top border
#ff6b5e), each aligned under its chain link, each containing a verdict word, a short
plain-English symptom line, and two mono check-id lines:
Card 1 verdict "NO_CONNECT", symptom "never registers", ids "C.CA.ROOT_MISSING"
and "C.TLS.MTLS_DISABLED".
Card 2 verdict "REJECTED", symptom "403 / 404 from Teams", ids "B.SIP.IDENTITY_IS_IP"
and "G.CLASS.UNCLASSIFIED".
Card 3 verdict "NO_MEDIA", symptom "sets up, no audio", ids "E.CODEC.NONE_OFFERED"
and "E.CODEC.NO_OVERLAP".
Card 4 verdict "ONE_WAY_AUDIO", symptom "callers can't hear", ids
"D.NAT.PRIVATE_IP" and "C.SRTP.DISABLED".
Top-right corner: a small chain-link glyph with the short label "first broken link".
The ONLY text allowed in the image is exactly those quoted strings above plus the
single connector word "next link". Do NOT render any style or instruction words as
text - curved, dashed, dotted, bold, small, garnet, arrow, flat, vector, label must
never appear. No percentages, no em dashes. Every label under 22 characters. Flat 2D
vector, no 3D, no funnel, no perspective, no neon, no glassmorphism.
```

---

## 4 · og-banner
- **Placement:** 16:9 social / Open Graph card (1200×630 export target). Replaces
  or complements `og-card.png`.
- **aspect_ratio:** `16:9`
- **caption:** A garnet-on-dark social card stating the product line, the independent truth layer for real-time voice, with a deterministic-verdict trustline.

```
source_context:
A minimal flat-vector social banner, full-bleed dark blue-black background (#161c25),
premium McKinsey-meets-modern-SaaS brand polish, deep negative space, a faint garnet
radial glow in the top-right corner only. TOP-LEFT: a brand mark, a rounded-square tile (32px, 16px radius) filled with a
subtle diagonal garnet gradient from #9d1b54 to #7a1340, with a single white letter
"S" centered, beside the white wordmark text "SBC-AutoOps". (The logo mark gradient
is the ONLY permitted gradient on a shape.) CENTER, large 800-900 weight tight-tracked
geometric grotesque headline in white across two lines, with exactly ONE word set in
serif-italic garnet-soft (#c14d80) as the accent: "The independent truth layer" /
"for real-time voice", where the serif-italic garnet word is "truth". BELOW the
headline, one all-caps mono trustline in muted light text (#aeb8c4) reading exactly:
"5 vendors · 8 domains · deterministic verdicts · air-gapped", using middot
separators. Lots of empty space, balanced and calm, no clutter, no charts, no
diagram, no human figures, no extra icons, no gradients on any shape EXCEPT the logo
mark and the corner background glow, no neon, no glassmorphism.
The ONLY text allowed in the image is exactly these strings: "S", "SBC-AutoOps",
"The independent truth layer", "for real-time voice",
"5 vendors · 8 domains · deterministic verdicts · air-gapped". Do NOT render any
style or instruction words (curved, dashed, small, bold, garnet, arrow, flat, vector,
serif, italic) as visible text. No percentages, no em dashes, no taglines beyond
those quoted. Flat 2D only.
```

---

## Render notes for team lead (task #3)
- Run each with `refine_mode:"text"` (one render per spec, ~$0.32 each).
- After render, eyeball for the leak failure: if any forbidden style word or a
  sentence fragment appears as text, re-run pinning the offending word in a
  "never print" clause. The architecture spec is the highest leak risk (it carries
  the "signed rules in" / "anon findings out" intentional labels).
- Web copies: `sips -Z 1800 <refined>.png <name>-web.png` per README convention.
