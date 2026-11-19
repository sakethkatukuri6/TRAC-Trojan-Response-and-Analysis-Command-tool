# TRAC local YARA ruleset

This directory is the **only** rules source `m2_static/yara_scan.py` will read when
`TRAC_YARA_RULES_DIR` is unset. Rules here are repository content: they are
reviewed in a pull request, versioned with the code, and identical on every
deployment. There is no feed, no download, and no operator-updatable cache.

## House rules

1. **A match is evidence, never a verdict.** `TRAC` treats a rule as asserting
   maliciousness only when it declares it — tag `malicious`, or
   `meta.verdict = "malicious"`, or `meta.malicious = true`. Anything else scores
   nothing and is reported as corroborating detail.
2. **A family name is a claim you own.** `meta.family` is the only place `TRAC`
   reads a family from. Do not set it from a string you found in a binary, a
   filename, or a rule *name*; only from identification you can defend. Rules here
   assert no families.
3. **Harmless fixtures only.** Patterns in this directory match test artefacts
   (the EICAR test file, linker-emitted section names, TRAC's own synthetic
   markers) or are generic behavioural signatures. No real malware content, no
   hashes of live samples.
4. **No `include`.** The engine compiles with `includes=False`, so a rule file
   cannot pull in a path outside this directory.
5. Every rule carries `meta.author` and `meta.description`, because a score
   contribution has to be attributable to a curatable statement.

## Enabling

```
$env:TRAC_YARA_ENABLED = "1"          # or point at another curated directory:
$env:TRAC_YARA_RULES_DIR = "D:\trac-rules"
```

Until then `static.yara_matches` is absent, which is TRAC saying "the engine did
not run" rather than "nothing matched".
