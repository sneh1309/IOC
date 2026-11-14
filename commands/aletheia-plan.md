---
description: Explain the proposed remediation plan for an Aletheia case (changes nothing)
argument-hint: "<case-folder>"
---
Use the `aletheia-dfir` skill. Show the remediation plan for case folder: $ARGUMENTS
(if empty, use the most recent case folder from this conversation or ask).

Run the `plan` command (read-only), explain every action (what, why, reversible?, risk), add recovery advice,
and finish by telling the user that only they can execute it by typing:
`! aletheia remediate "<case-folder>"` (or the python launcher equivalent). Never run remediate yourself.
