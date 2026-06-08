# NotebookLM Query Library

Reusable prompts for the **SBC Validator Project Knowledge Base** notebook:
https://notebooklm.google.com/notebook/b4d928f2-d15f-4468-a2fd-42ad0700caff

The notebook holds the full project end-to-end: vision/architecture synthesis,
all project docs, the complete source code, the build history, tests/samples/
ruleset, a domain glossary, the failure-mode catalog, and the decisions log.
These prompts are tuned to pull the best answers out of it.

## Onboarding / orientation

- "Explain the SBC Validator project to a new engineer joining the team: what it
  is, the problem it solves, how it works, and what they need to know first."
- "I am a 20-year telecom voice engineer. Convince me this tool is real and not
  marketing. Walk me through exactly what it validates and where it is honest
  about its limits."
- "Summarize the project in three levels: one sentence, one paragraph, one page."

## Product deep-dives

- "List the eight validation domains (A-G + S). For each, give the exact failure it
  catches, the triggering config condition, the user-visible symptom, and an
  example check_id."
- "Explain the three diagnostic modes (validate, simulate, explain). How are they
  different, when do you use each, and what does each output look like?"
- "Walk through what happens, step by step, when I run `validate` on a config:
  parse to normalized model, each validator, scoring, verdict, report."
- "Explain the B2BUA two-leg architecture and exactly what the validator checks on
  the Teams leg versus the carrier leg, including the honest gaps."

## Architecture / engineering

- "Describe the three planes (engine / rule service / telemetry) and what is built
  vs deferred in each."
- "Explain the signed rule channel end to end: signing, the pinned key, the
  rollback/freshness floor, and why a valid signature is not enough."
- "Why is the product deterministic instead of LLM-driven? Argue both sides, then
  give the project's actual position and reasoning."
- "Explain 'correctness by discipline.' Why do routing and security only fire for
  AudioCodes? Give the concrete false-positive examples that justify gating."

## Failure modes / domain mastery

- "Produce the canonical SBC failure-mode catalog as a table: category, condition,
  symptom, owning domain, and whether we cover it (yes/partial/gap)."
- "What are the exact Microsoft Teams Direct Routing requirements a config must
  satisfy, and which of our domains enforce each?"
- "Give me five realistic misconfigurations and predict, for each, the verdict and
  the call-flow outcome the simulator would produce."

## Strategy / business

- "Build the competitive battlecard: us vs Cisco DNA, AudioCodes OVOC, Ribbon LEAP,
  and AIOps. Where does each win and lose, and what is our one-line wedge?"
- "Make the investor case: market, the 2026 CA forcing event, product, moat, the
  data-moat thesis, business model, and the ask."
- "Argue the ICP decision: BYOC SMB beachhead vs multi-vendor enterprise. What does
  each change about the demo, pricing, and first ten conversations?"
- "What is the patent whitespace, and how is each item framed as an external tool
  acting on a third-party SBC?"

## Process / workflows

- "Document the vendor-onboarding workflow: how a real config turns gated domains
  into firing ones, using AudioCodes as the worked example."
- "Document the rule re-sign workflow for when Microsoft changes the CA list."
- "Map every CLI command (validate/simulate/explain/diff/fleet/serve/demo/report)
  to the workflow and persona that uses it."

## Generate-an-artifact prompts (for the Studio)

- Study guide focus: "Comprehensive study guide to master the project end-to-end."
- Briefing focus: "Executive + investor briefing, anti-hype, metric-backed."
- Slide focus: "Pitch deck: problem, wedge, solution, proof, moat, ask."
- Quiz focus: "Knowledge check on domains, failure modes, and architecture."
