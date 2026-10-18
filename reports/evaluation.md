# Evaluation against ground_truth.json

**Caveat:** the corpus and its labels were written by the same person who wrote the detector. This measures regressions and whether the heuristics do what they claim, not real-world accuracy.

| Set | Messages | Exact verdict | TP | FP | FN | TN | Precision | Recall | Expected indicators | Forbidden hits |
|---|---|---|---|---|---|---|---|---|---|---|
| holdout | 8 | 7/8 | 3 | 0 | 1 | 4 | 1.0 | 0.75 | 9/9 | 0 |
| tuning | 28 | 27/28 | 17 | 1 | 0 | 10 | 0.9444 | 1.0 | 55/55 | 0 |
| all | 36 | 34/36 | 20 | 1 | 1 | 14 | 0.9524 | 0.9524 | 64/64 | 0 |

## Misses and surprises

- `B12-secops-awareness-quoted-phish` (known hard negative): verdict suspicious (score 28), expected benign
- `H07-unauth-rar-password` (borderline): verdict benign (score 18), expected suspicious
