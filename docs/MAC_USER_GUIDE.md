# Aletheia for Mac: Step-by-Step User Guide

**Read-only investigation of a Mac for spyware, remote access, email forwarding and misuse, with a court-ready report.**

---

## What this tool does and does not do

| ✅ It DOES | ❌ It NEVER |
|---|---|
| Read logs, settings and app databases | Delete, edit, move or "clean" anything |
| Copy databases byte-for-byte to the USB stick, then analyse **the copy** | Open the Mac's own databases directly |
| Seal every result with SHA-256 hashes and a tamper-evident log | Reset, reboot, log out, or change settings |
| Produce an HTML/PDF report that answers your questions | Install software (it won't even trigger Apple's "install developer tools" prompt) |
| Save everything to **your USB stick** | Run any remediation/clean-up (it is disabled in Mac mode) |

### The questions it answers (report section **1A**)

| # | Question | Where the answer comes from |
|---|---|---|
| Q1 | Is email being forwarded to another address, and **when did it start**? | Apple Mail sent/forwarded messages to the watched address (with dates), Mail forwarding rules, browser visits to webmail forwarding/rules settings pages |
| Q2 | What apps were used (including Messages) and when? | Screen Time / app-usage database, Messages (contacts, counts, dates, attachments) |
| Q3 | What was opened, downloaded or transferred? | Downloads (with source website), Messages attachments, USB and AirDrop events, recently created/changed files |
| Q4 | On which **dates and times** was the computer used? | Wake/sleep history, screen unlocks and logins, app and browser activity → a daily first/last-activity table |
| Q5 | Which networks / IP addresses was it on? Was it **taken somewhere else**? | Remembered Wi-Fi networks with "added/joined" dates, IP address leases with router details |
| Q6 | Is there **hidden spyware**? | Remote-access/stalkerware app list, apps with keystroke / screen-recording / control permissions, login items, profiles/MDM, kernel extensions, persistence, YARA and IOC scan |
| Q7 | Is someone **accessing it remotely**? | Screen Sharing, Remote Login (SSH) and Remote Management status, remote-session log events, Apple IDs that sync data to other devices |
| Q8 | What emails were **forwarded or deleted**? | Apple Mail index: "Fwd:" messages, Trash/Deleted Items, deleted flags |
| Q9 | Were logs or settings **tampered with**? | Log-erase / clock-change / privacy-reset events, boot/shutdown history, cleared shell history |

---

## Step 0: Authorisation (before you touch the Mac)

1. Get **written permission from the Mac's owner** to examine the device: name, date, device description, and the scope. Keep it in the case file.
2. Treat the owner's password as confidential. Do not write it in the report or tickets.
3. Agree what you will search for. These are the **watch terms**: the suspect email address(es), name, phone number.

> Examine only devices you are authorised to examine. The report can contain other people's personal information. Store it securely and share it only with people entitled to see it.

---

## Step 1: Prepare the USB stick (on YOUR computer, not the client's Mac)

1. **USB stick**: 32 GB or more. Format it as **exFAT** so it works on Mac and Windows. Name it `EVIDENCE`.
   * Windows: File Explorer → right-click the stick → Format → File system **exFAT** → Volume label `EVIDENCE` → Start.
   * Mac: Disk Utility → select the stick → Erase → Format **ExFAT** → Name `EVIDENCE`.
2. **Unzip `Aletheia_USB.zip` onto the stick.** You should then have `EVIDENCE/aletheia/` containing `run_aletheia.py`, `mac/`, `setup/` and this guide.
3. **Add portable Python (once, needs internet).** This lets the tool run on any Mac without installing anything on it:
    * **Windows:** open `EVIDENCE\aletheia\setup` and double-click **`SETUP_USB_Windows.bat`**. If Windows SmartScreen asks, choose *More info → Run anyway*.
    * **Mac:** in Terminal run `bash /Volumes/EVIDENCE/aletheia/setup/setup_usb_mac.command`
    * It downloads the official portable Python 3.12 for **both** Apple Silicon and Intel Macs, checks the SHA-256, and prints **DONE**. The launcher automatically picks the right one on the client's Mac.
4. **Check**: `EVIDENCE/aletheia/` now has the folders `python-aarch64` and `python-x86_64`.
5. **Practice run** on a Mac you own (Steps 3–6) before going to the client.
6. Optional: copy extra IOC lists or YARA rules into `EVIDENCE/aletheia/` (see the main README).

> Without the portable Python, the tool uses the Mac's own Python **only if it is already installed**. If neither is available, it stops without changing anything.

---

## Step 2: At the client's Mac (before running anything)

1. **Photograph** the Mac, its screen and its serial number (Apple menu → About This Mac). Note the date/time from your phone and compare it with the Mac's clock.
2. Plug the Mac into **power**.
3. **Do not** open Mail, Messages, Safari or other apps. Opening them adds new data.
4. Log in with the owner's account and plug in the USB stick.
5. Write down the time of each action in your notes. That is your chain-of-custody record.

---

## Step 3: Allow Terminal to read protected data (Full Disk Access)

macOS hides Mail, Messages, Safari and privacy settings from all programs unless you allow it.

1. Open **System Settings → Privacy & Security → Full Disk Access**.
2. Turn **Terminal** on (click **+** and choose Applications → Utilities → Terminal if it isn't listed). Enter the password when asked.
3. If Terminal was already open, **quit it completely** (⌘Q).

> **Disclosure:** this is the only setting you change, and it changes nothing about the owner's data. Note the time in your notes. You can switch it off again at the end (Step 5).

---

## Step 4: Run the investigation

1. Open **Terminal**: press ⌘ + Space, type `Terminal`, press Return.
2. Type `bash ` (with a space after it), then **drag** the file `EVIDENCE/aletheia/mac/run_mac_investigation.command` from Finder into the Terminal window. Press **Return**.
   It looks like: `bash /Volumes/EVIDENCE/aletheia/mac/run_mac_investigation.command`
3. Answer the questions:

   | Prompt | Example |
   |---|---|
   | Examiner full name | `Jane Technician` |
   | Case / ticket number | `20261116.0042` |
   | Client / device owner name | `<owner's name>` |
   | Organization | `Bercell Integrated Technologies` |
   | Evidence item | `MacBook Air 13" M2, S/N C02XXXXXXX` |
   | **Watch for** | the suspect email address(es), names or phone numbers, comma-separated |
   | **From date** | The first day you care about, e.g. `2026-10-01`. **Recommended: a date range is much faster** (minutes instead of up to 40). Press Enter to skip and use "last N days". |
| **To date** | The last day, e.g. `2026-11-15` (Enter = today). Both dates are included. |
| Days back (only if no From date) | `90` (Enter). Use `365` if the problem is older; it takes longer. |
   | Collect message TEXT? | **N** (default: only dates/contacts). Choose Y only if the owner consented and the case requires it. |
   | Save results to | press Enter (saves to the USB stick) |

4. When asked for a **password**, type the Mac's administrator password. The characters are invisible; press Return. It's needed only to *read* protected system logs.
5. **Wait** (a few minutes with a short date range, up to 10–40 minutes for 90+ days) and don't use the Mac. Progress is shown on screen.
6. When finished, the screen shows the **result folder** and a **Manifest SHA-256**. **Write the SHA-256 in your notes.** It proves later that nothing in the results was changed.

> Don't open the report on the client's Mac. A browser would create new history entries on it.

---

## Step 5: Finish on the Mac

1. Optional (ask the owner): System Settings → Privacy & Security → Full Disk Access → turn **Terminal** off again.
2. Quit Terminal (⌘Q), **eject** the USB stick (drag to Trash / right-click → Eject), and unplug it.
3. Record the end time.

---

## Step 6: Read the report (on YOUR computer)

1. Open `EVIDENCE/aletheia/cases/<CASE>_<date>/report/report.html` in a browser.
2. **Verify integrity** first. In a terminal on your computer:
   ```
   cd /path/to/EVIDENCE/aletheia
   python3 run_aletheia.py verify "cases/<CASE>_<date>"
   ```
   It must say **INTEGRITY VERIFIED**.
3. Read:
   * **1. Executive Summary**: overall verdict and key findings.
   * **1A. Investigation Questions & Answers**: Q1–Q9 in plain language with tables. All times are the Mac's local time.
   * **4. Detailed Findings**: each suspicious item, its evidence, and its MITRE ATT&CK technique.
   * Full tables for spreadsheets are in `report/investigation/*.csv`. They open in Excel.
4. **PDF for the file/court**: browser → Print → *Save as PDF*. Sign section 13 (Examiner Declaration).
5. **Make two copies** of the whole case folder (working + archive) and run `verify` on each.

### Reading the key answers

* **When did forwarding start? (Q1)** Look at the *first* date in "Mail sent/forwarded to watched addresses", and at the date of any "Visits to webmail forwarding/rules pages". A visit to the forwarding settings page shortly before the first forwarded email is strong evidence of when it was set up.
* **Was the Mac taken elsewhere? (Q5)** Look for Wi-Fi networks the owner doesn't recognise. Their "added"/"joined" dates show when the Mac was there.
* **Spyware / remote access? (Q6, Q7)** Any remote-access app (TeamViewer, AnyDesk …), any non-Apple app with *Input Monitoring* or *Screen Recording*, any profile/MDM, or Screen Sharing/Remote Login set to **On**. Ask the owner whether they recognise each one.
* **Usage times (Q4)** Compare the daily first/last activity with times the owner says they were *not* using the Mac.

---

## Step 7: Checks that must be done online (not stored on the Mac)

Some evidence lives on the email/Apple servers, not on the Mac. Do these with the owner, take **screenshots with the date/time visible**, and add them to the case file.

| Check | Where |
|---|---|
| Server-side forwarding (Outlook/Hotmail) | outlook.live.com → ⚙ Settings → Mail → **Forwarding** |
| Inbox rules that forward/delete | outlook.live.com → ⚙ Settings → Mail → **Rules** |
| Sign-ins (IP addresses, locations, devices) | account.microsoft.com → Security → **Sign-in activity** |
| Deleted emails that can still be recovered | Outlook.com → Deleted Items → **Recover items deleted from this folder** |
| Devices on the same Apple ID (can read Messages/Photos) | Mac: System Settings → [name] → **Devices**, or appleid.apple.com |
| Messages forwarded to other devices | iPhone: Settings → Messages → **Text Message Forwarding** |

For Gmail: Settings → *Forwarding and POP/IMAP* and *Filters*; Google Account → Security → *Your devices*.

---

## Troubleshooting

| Message | Fix |
|---|---|
| `No Python 3 is available` | Run the USB setup script on your computer (Step 1.3). Nothing was changed on the Mac. |
| `"python3.12" cannot be opened because the developer cannot be verified` | On *your* computer re-run the USB setup script (it clears the download flag), or on your Mac run `xattr -dr com.apple.quarantine /Volumes/EVIDENCE/aletheia`. |
| `Terminal does NOT have Full Disk Access` | Step 3, then quit Terminal with ⌘Q and reopen it. |
| Report says *permission denied* in "Collection access problems" | Same as above: Full Disk Access was not active. Re-run. |
| Q2 app usage is empty | Normal on macOS 14+ (Apple moved app usage to a new format). Use Q4 activity, browser and Messages tables instead. |
| It seems stuck at "unified log" | Reading the system log can take several minutes per query. Wait, or re-run with a shorter From/To date range. |

---

## What changes on the Mac (full disclosure, for your notes)

Running anything on a live computer leaves unavoidable traces. Aletheia keeps them to the minimum and they don't affect the owner's data:

* macOS records that a USB stick was mounted, that Terminal ran, and the `sudo` password use (system log entries).
* Turning on Full Disk Access for Terminal adds one entry to the privacy settings (and removing it later is another).
* No files in the owner's account are created, changed or deleted. All output goes to the USB stick. Databases are **copied** (read-only) and only the copies are analysed, so the Mac's own databases are never opened by a database engine (which could otherwise write journal files). Our automated tests verify that analysed source files stay byte-for-byte identical, with unchanged modification times.
* One honest caveat: on a live Mac, reading a file can update its *last-accessed* time (macOS has no way to read without this). File contents and modified/created dates are not affected. If last-accessed times matter to your case, use offline analysis of a disk image instead (below).

For the highest standard (e.g. criminal matters), a full forensic image of the disk should be taken by a specialist. Aletheia can also analyse a **mounted Mac volume or image offline** without running anything on the Mac:
`python3 run_aletheia.py scan --mac-root "/Volumes/Macintosh HD" --watch <terms> --examiner "<name>" --output <folder>`

---

## About the date range

* **Filtered to the range:** everything that has a date. That covers emails sent/forwarded/deleted, Messages, attachments, web history, downloads, app usage, wake/sleep, unlocks, USB/AirDrop, remote-session and tamper log events, and files created or modified.
* **Always shown, whatever the range:** the Mac's *current* state. That covers installed apps and spyware, privacy permissions, Mail forwarding rules, sharing/remote settings, profiles, and remembered Wi-Fi networks (with their dates). Spyware installed before your range can still be spying during it.
* Command line equivalent: `--from 2026-10-01 --to 2026-11-15`.
