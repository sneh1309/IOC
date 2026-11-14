# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/sneh1309/IOC/security/advisories/new).
We aim to acknowledge reports within 72 hours.

Issues we especially want to hear about:

* any way the **analysis** stage can modify, delete or add data on the examined system
* any way to trigger **remediation** without interactive human approval
* any way to alter a sealed case folder without `aletheia verify` detecting it
* parsing bugs that a malicious artefact (crafted log, file name, registry value) could exploit

## Design commitments

* The core has zero third-party dependencies (Python standard library only), so supply-chain risk is minimal.
* No network access during scans. Feeds are fetched only by `aletheia feeds update`, over verified HTTPS.
* No shell invocation (`shell=False` everywhere). Analysis commands are allow-listed, and state-changing arguments are refused.
* Case output can contain sensitive personal data from the examined device. `.gitignore` excludes case folders, so **never commit or upload case folders** to public locations.

## Supported versions

Only the latest release receives security fixes.
