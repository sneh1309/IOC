# Aletheia - notes for Claude

* Package: `aletheia/`. CLI entry is `aletheia/cli.py`; the zero-install launcher is `run_aletheia.py`.
* Pipeline: `scan.py` → `collectors/*` (read-only) → `detection/{ioc,rules,yara_scan}.py` → `report/*` → seal (`core/evidence.py`).
* Remediation: `remediation/{planner,actions,engine}.py`. Never weaken the interactive-TTY gate or the approval phrases.
* Core must stay standard-library only, Python 3.9+.
* Tests: `python -m unittest discover -s tests` (synthetic data only; never modify the host).
* To *use* the tool (rather than develop it), follow `skills/aletheia-dfir/SKILL.md`.
