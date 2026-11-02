# Fuzzing

Coverage-guided fuzzing of presidio-evidence with [Atheris](https://github.com/google/atheris).
`fuzz_envelope.py` feeds arbitrary input through envelope parsing, `verify_envelope`
against a fixed trust store, canonical JSON and the decimal-string check, and
fails on any exception other than the declared `EvidenceError` / `ValueError`.

```bash
python -m pip install -e '.[fuzz]'
python fuzz/make_corpus.py fuzz/corpus   # seed from vectors/
python fuzz/fuzz_envelope.py fuzz/corpus -max_total_time=60
```

Linux only (Atheris has no macOS wheel). CI runs the harness on Python 3.12 on
pull requests that touch `src/` or `fuzz/` (60 s) and weekly (300 s);
see `.github/workflows/fuzz.yml`.
