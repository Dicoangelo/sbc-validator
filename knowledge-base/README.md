# Knowledge Base

End-to-end project knowledge for SBC Validator, plus the NotebookLM knowledge base
built from it.

## NotebookLM notebook

**SBC Validator — Project Knowledge Base (End-to-End)**
https://notebooklm.google.com/notebook/b4d928f2-d15f-4468-a2fd-42ad0700caff

Loaded with: this synthesis set, all project docs, the full source code, the
build history, tests/samples/ruleset, the glossary, the failure-mode catalog, and
the decisions log. Generated artifacts: Study Guide, Briefing Doc, deep-dive
audio, flashcards, quiz, infographic, pitch slide deck.

See **[NOTEBOOK-QUERIES.md](NOTEBOOK-QUERIES.md)** for the curated query library.

## Synthesis documents (the keystones)

| Doc | What it is |
|---|---|
| **[VISION_PRODUCT_ARCHITECTURE.md](VISION_PRODUCT_ARCHITECTURE.md)** | the master synthesis: vision, product, architecture, processes, philosophy, competition, strategy, roadmap |
| **[GLOSSARY.md](GLOSSARY.md)** | telecom + product vocabulary |
| **[FAILURE_MODE_CATALOG.md](FAILURE_MODE_CATALOG.md)** | the canonical SBC failure-mode taxonomy mapped to domains |
| **[DECISIONS_AND_RATIONALE.md](DECISIONS_AND_RATIONALE.md)** | the load-bearing architecture decisions and their reasoning |

## Rebuilding the NotebookLM sources

The synthesis docs above are committed. The concatenation bundles (all docs, all
code, build history, tests/samples) are regenerated from the repo:

```bash
# docs, code, history, tests/samples bundles -> /tmp/sbc_kb/
# (see the generation commands in the project history; they cat the repo into
#  01_PROJECT_DOCS.md, 02_SOURCE_CODE.md, 03_BUILD_HISTORY.md,
#  04_TESTS_SAMPLES_RULESET.md)
```

Then create a notebook and `source_add` each file, and generate artifacts via the
Studio. The query library drives the best output.
