"""
Baseline evaluation for the explainer corpus: multinomial naive Bayes over token
counts, pure stdlib. Purpose: prove (cheaply, pre-GPU) that the protocol-aware token
stream carries the failure-class signal end-to-end. A foundation-model fine-tune
(netFound, Path A) must beat this floor to justify itself.

  ../../../../.venv/bin/python eval_baseline.py corpus.jsonl
"""
from __future__ import annotations

import json
import math
import random
import sys
from collections import Counter, defaultdict


def load(path):
    rows = [json.loads(l) for l in open(path)]
    rng = random.Random(7)
    rng.shuffle(rows)
    cut = int(len(rows) * 0.8)
    return rows[:cut], rows[cut:]


def train(rows):
    class_tok = defaultdict(Counter)
    class_n = Counter()
    vocab = set()
    for r in rows:
        class_tok[r["label"]].update(r["tokens"])
        class_n[r["label"]] += 1
        vocab.update(r["tokens"])
    return class_tok, class_n, vocab


def predict(tokens, class_tok, class_n, vocab):
    total = sum(class_n.values())
    best, best_lp = None, -math.inf
    for c, n in class_n.items():
        lp = math.log(n / total)
        denom = sum(class_tok[c].values()) + len(vocab)
        for t in tokens:
            lp += math.log((class_tok[c][t] + 1) / denom)
        if lp > best_lp:
            best, best_lp = c, lp
    return best


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "corpus.jsonl"
    tr, te = load(path)
    class_tok, class_n, vocab = train(tr)
    print(f"train={len(tr)} test={len(te)} vocab={len(vocab)} classes={sorted(class_n)}")

    confusion = defaultdict(Counter)
    correct = 0
    for r in te:
        p = predict(r["tokens"], class_tok, class_n, vocab)
        confusion[r["label"]][p] += 1
        correct += (p == r["label"])
    acc = correct / len(te)
    print(f"\naccuracy: {acc:.3f}  ({correct}/{len(te)})\n")
    labels = sorted(confusion)
    print("confusion (rows=truth, cols=predicted):")
    print(" " * 19 + "  ".join(f"{l[:7]:>7}" for l in labels))
    for t in labels:
        row = "  ".join(f"{confusion[t][p]:>7}" for p in labels)
        n = sum(confusion[t].values())
        rec = confusion[t][t] / n if n else 0.0
        print(f"{t:>17}  {row}   recall={rec:.2f}")

    # the informative tokens per class (sanity: are these the RIGHT signals?)
    print("\ntop discriminative tokens per class:")
    total_tok = Counter()
    for c in class_tok:
        total_tok.update(class_tok[c])
    for c in labels:
        denom_c = sum(class_tok[c].values())
        scored = []
        for t, n in class_tok[c].items():
            p_c = n / denom_c
            p_all = total_tok[t] / sum(total_tok.values())
            scored.append((p_c * math.log(p_c / p_all + 1e-12), t))
        top = [t for _, t in sorted(scored, reverse=True)[:4]]
        print(f"  {c:>17}: {', '.join(top)}")


if __name__ == "__main__":
    main()
