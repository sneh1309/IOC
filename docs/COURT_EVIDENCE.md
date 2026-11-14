# Court & Evidence Handling Guide

> Not legal advice. Admissibility is decided by the court. Consult counsel in your jurisdiction.

## Examiner checklist

**Before**
- [ ] Written authority: client consent, engagement letter, warrant or policy. Reference it in `--purpose` / `--notes`.
- [ ] Photograph the device, its screen and its connections. Note the date and time from a trusted clock and compare it with the device clock (Aletheia records both).
- [ ] Prepare clean external media for `--output`. Use a write-blocked/forensic USB or a freshly formatted drive.
- [ ] Run Aletheia from external media as well, if possible (`python run_aletheia.py`). Record the tool's **build SHA-256** (shown on the report cover).
- [ ] Decide whether to capture memory first (recommended for suspected fileless malware, rootkits or ransomware).

**During**
- [ ] Run elevated (root/Administrator) so coverage is complete.
- [ ] Keep contemporaneous notes: who, what, when, why.
- [ ] Do **not** take remediation actions until analysis is sealed and, where required, the evidence has been duplicated.

**After**
- [ ] Write the **manifest SHA-256** printed by the scan into your notes and the custody form.
- [ ] `aletheia verify <case>` → "INTEGRITY VERIFIED". Optionally use `--sign` with your GPG key.
- [ ] Make two copies of the case folder (working + archive). Verify each copy.
- [ ] Print `report.pdf`. Sign the Examiner Declaration (section 13) and have a reviewer counter-sign.
- [ ] Fill in the *Transfer of custody* table (section 9) every time the evidence changes hands.
- [ ] Before testimony, run `aletheia verify` again and record the result.

## What makes the output defensible

| Requirement | Evidence produced by Aletheia |
|---|---|
| **Authenticity**: the record is what it claims to be | SHA-256 of every artefact; `SHA256SUMS` seal; optional GPG signature; hostname, machine ID, IPs and OS identity in `system.json` |
| **Integrity**: unchanged since collection | Hash-chained audit log, read-only files, `aletheia verify` (detects altered, missing and added files) |
| **Reliability of the process** | Open-source code; tool build hash in the report; documented methodology; automated tests; recorded command lines and output hashes |
| **Continuity / chain of custody** | Audit log with actor (`user@host`) and UTC timestamps; transfer-of-custody table; remediation recorded separately with the approver's name |
| **Expert basis** | Each finding cites its rule, evidence, confidence and MITRE ATT&CK technique. Limitations are stated explicitly (section 2). |

## Jurisdiction notes

**Canada**: *Canada Evidence Act* ss. 31.1–31.8: the person tendering an electronic document must prove authenticity (s. 31.1). The best-evidence rule is satisfied by proving the integrity of the electronic documents system (s. 31.2–31.3). Standards may be considered (s. 31.5). Provincial equivalents include Ontario *Evidence Act* s. 34.1. Privacy: PIPEDA / provincial statutes; a breach of security safeguards may need to be reported to the OPC.

**United States**: FRE 901(b)(9) (evidence about a process or system that produces an accurate result); FRE 902(13)/(14) (self-authentication of electronic records and of data copied from a device, by hash value, with a certification); FRE 702 / *Daubert* (testability, peer review, error rate, standards, general acceptance).

**United Kingdom**: ACPO/NPCC Good Practice Guide for Digital Evidence; Forensic Science Regulator Code of Practice; PACE s.69 has been repealed, so the common-law presumption of reliability applies.

**EU**: GDPR Art. 33/34 breach notification timelines; e-Evidence Regulation for cross-border requests.

## Important caveats to disclose

* The examination was **live** (see the report's "Live-response limitations").
* Heuristic findings are investigative leads until validated by the examiner.
* If remediation was performed, disclose it and provide the separate remediation report. It is sealed independently, and the analysis evidence was not modified by it.
