---
description: Check hashes, IPs, domains or URLs against Aletheia's loaded threat-intel feeds
argument-hint: "<indicator> [indicator ...]"
---
Use the `aletheia-dfir` skill to run `ioc-check $ARGUMENTS` and explain any matches (source feed, threat name).
If no feeds have been downloaded yet, offer to run `feeds update` (it contacts abuse.ch - ask first).
