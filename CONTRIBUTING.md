# Contributing

Thanks for helping make Aletheia better.

1. Fork the repository and create a branch.
2. Keep the core **standard-library only**. Optional integrations must degrade gracefully when a module or tool is missing.
3. Analysis code must never write outside the case folder. New system commands go through `SafeRunner` and must be added to the allow-list (with forbidden sub-commands, if any) in `aletheia/core/runner.py`.
4. Every new detection needs a MITRE ATT&CK mapping, a severity, a confidence, evidence references, and a test that uses **synthetic** artefacts (tests must never modify the host).
5. Every new remediation action must implement pre-check → backup → execute → verify → rollback, and must be added to `planner.py` (order, reversibility, risk text) and `frameworks.D3FEND`.
6. Run `ruff check aletheia tests --select E9,F` and `python -m unittest discover -s tests` before opening a PR.

By contributing you agree that your contributions are licensed under the MIT License.
