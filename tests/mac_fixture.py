"""Builds a synthetic macOS volume (real macOS schemas, fake data) for offline-mode tests.

All identities are fictitious and use reserved example domains.
"""

import datetime as dt
import os
import plistlib
import sqlite3

MAC_EPOCH = 978307200
NOW = dt.datetime(2026, 11, 10, 14, 30, tzinfo=dt.timezone.utc).timestamp()
WATCHED = "suspect.person@example.net"


def _db(path, script, rows=()):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(script)
    for sql, vals in rows:
        c.executemany(sql, vals)
    c.commit()
    c.close()


def _plist(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump(obj, fh)


def build(root: str) -> dict:
    home = os.path.join(root, "Users", "owner")
    day = 86400
    # ---------------- Apple Mail
    mail = os.path.join(home, "Library/Mail/V10/MailData")
    _db(os.path.join(mail, "Envelope Index"), """
        CREATE TABLE messages (ROWID INTEGER PRIMARY KEY, sender INTEGER, subject INTEGER, subject_prefix TEXT,
            date_sent INTEGER, date_received INTEGER, mailbox INTEGER, deleted INTEGER);
        CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT);
        CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT, comment TEXT);
        CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT);
        CREATE TABLE recipients (ROWID INTEGER PRIMARY KEY, message INTEGER, address INTEGER, type INTEGER);
    """, [
        ("INSERT INTO addresses VALUES (?,?,?)", [(1, "owner@example.com", ""), (2, WATCHED, ""), (3, "bank@example.org", "")]),
        ("INSERT INTO mailboxes VALUES (?,?)", [(1, "imap://owner@outlook/INBOX"), (2, "imap://owner@outlook/Sent"),
                                                (3, "imap://owner@outlook/Deleted Items")]),
        ("INSERT INTO subjects VALUES (?,?)", [(1, "Your bank statement"), (2, "Lunch?"), (3, "Password reset")]),
        ("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)", [
            (1, 3, 1, "", NOW - 40 * day, NOW - 40 * day, 1, 0),
            (2, 1, 1, "Fwd: ", NOW - 30 * day, NOW - 30 * day, 2, 0),     # forwarded to watched
            (3, 1, 3, "Fwd: ", NOW - 5 * day, NOW - 5 * day, 2, 0),       # forwarded to watched
            (4, 3, 3, "", NOW - 6 * day, NOW - 6 * day, 3, 1),            # deleted
            (5, 2, 2, "", NOW - 2 * day, NOW - 2 * day, 1, 0)]),
        ("INSERT INTO recipients VALUES (?,?,?,?)", [(1, 1, 1, 0), (2, 2, 2, 0), (3, 3, 2, 0), (4, 4, 1, 0), (5, 5, 1, 0)]),
    ])
    _plist(os.path.join(mail, "SyncedRules.plist"), [
        {"RuleName": "Auto copy", "Active": "1", "ShouldForward": "1", "ForwardRecipients": [WATCHED],
         "Criteria": [{"Header": "AnyRecipient", "Expression": "owner@example.com"}]},
        {"RuleName": "Newsletters", "Active": "1", "Mailbox": "News"}])
    # ---------------- Messages
    _db(os.path.join(home, "Library/Messages/chat.db"), """
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, service TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, handle_id INTEGER, service TEXT, date INTEGER,
            is_from_me INTEGER, cache_has_attachments INTEGER);
        CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, created_date INTEGER, filename TEXT, transfer_name TEXT,
            mime_type TEXT, total_bytes INTEGER, is_outgoing INTEGER);
        CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
    """, [
        ("INSERT INTO handle VALUES (?,?,?)", [(1, "+15555550100", "iMessage"), (2, WATCHED, "iMessage")]),
        ("INSERT INTO message VALUES (?,?,?,?,?,?,?)", [
            (1, "hi", 1, "iMessage", int((NOW - 3 * day - MAC_EPOCH) * 1e9), 0, 0),
            (2, "sent you the file", 2, "iMessage", int((NOW - 1 * day - MAC_EPOCH) * 1e9), 1, 1)]),
        ("INSERT INTO attachment VALUES (?,?,?,?,?,?,?)", [(1, int(NOW - day - MAC_EPOCH), "~/x/statement.pdf",
                                                           "statement.pdf", "application/pdf", 12345, 1)]),
        ("INSERT INTO message_attachment_join VALUES (?,?)", [(2, 1)]),
    ])
    # ---------------- Safari + Chrome
    _db(os.path.join(home, "Library/Safari/History.db"), """
        CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT);
        CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
    """, [("INSERT INTO history_items VALUES (?,?)", [(1, "https://outlook.live.com/mail/0/options/mail/forwarding"),
                                                     (2, "https://www.anydesk.com/en/downloads/mac-os")]),
          ("INSERT INTO history_visits VALUES (?,?,?,?)", [(1, 1, NOW - 31 * day - MAC_EPOCH, "Forwarding"),
                                                           (2, 2, NOW - 20 * day - MAC_EPOCH, "AnyDesk download")])])
    _db(os.path.join(home, "Library/Application Support/Google/Chrome/Default/History"), """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, start_time INTEGER, target_path TEXT, tab_url TEXT, total_bytes INTEGER);
    """, [("INSERT INTO urls VALUES (?,?,?)", [(1, "https://example.com/news", "News")]),
          ("INSERT INTO visits VALUES (?,?,?)", [(1, 1, int((NOW - 4 * day + 11644473600) * 1e6))]),
          ("INSERT INTO downloads VALUES (?,?,?,?,?)", [(1, int((NOW - 20 * day + 11644473600) * 1e6),
                                                         "/Users/owner/Downloads/AnyDesk.dmg",
                                                         "https://download.anydesk.com/AnyDesk.dmg", 30000000)])])
    _db(os.path.join(home, "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"), """
        CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, LSQuarantineTimeStamp REAL,
            LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT,
            LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT, LSQuarantineTypeNumber INTEGER,
            LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineOriginAlias BLOB);
    """, [("INSERT INTO LSQuarantineEvent (LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineDataURLString, "
           "LSQuarantineOriginURLString) VALUES (?,?,?,?)",
           [(NOW - 20 * day - MAC_EPOCH, "Google Chrome", "https://download.anydesk.com/AnyDesk.dmg",
             "https://www.anydesk.com")])])
    # ---------------- knowledgeC (Screen Time / app usage)
    _db(os.path.join(home, "Library/Application Support/Knowledge/knowledgeC.db"), """
        CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT, ZVALUEINTEGER INTEGER,
            ZSTARTDATE REAL, ZENDDATE REAL);
    """, [("INSERT INTO ZOBJECT (ZSTREAMNAME, ZVALUESTRING, ZVALUEINTEGER, ZSTARTDATE, ZENDDATE) VALUES (?,?,?,?,?)",
           [("/app/usage", "com.apple.MobileSMS", None, NOW - 1 * day - MAC_EPOCH, NOW - 1 * day - MAC_EPOCH + 900),
            ("/app/usage", "com.apple.mail", None, NOW - 5 * day - MAC_EPOCH, NOW - 5 * day - MAC_EPOCH + 600),
            ("/device/isLocked", None, 0, NOW - 1 * day - MAC_EPOCH - 60, None)])])
    # ---------------- privacy permissions (TCC)
    tcc = """CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER,
             auth_reason INTEGER, last_modified INTEGER);"""
    _db(os.path.join(root, "Library/Application Support/com.apple.TCC/TCC.db"), tcc,
        [("INSERT INTO access VALUES (?,?,?,?,?,?)", [
            ("kTCCServiceScreenCapture", "com.philandro.anydesk", 0, 2, 3, int(NOW - 20 * day)),
            ("kTCCServiceListenEvent", "com.example.keycatcher", 0, 2, 3, int(NOW - 19 * day)),
            ("kTCCServiceAccessibility", "com.apple.Terminal", 0, 2, 3, int(NOW - 100 * day))])])
    # ---------------- software
    _plist(os.path.join(root, "Library/Receipts/InstallHistory.plist"), [
        {"date": dt.datetime.fromtimestamp(NOW - 20 * day), "displayName": "AnyDesk", "displayVersion": "8.0",
         "processName": "Installer", "packageIdentifiers": ["com.philandro.anydesk"]}])
    _plist(os.path.join(root, "Applications/AnyDesk.app/Contents/Info.plist"),
           {"CFBundleIdentifier": "com.philandro.anydesk", "CFBundleShortVersionString": "8.0"})
    _plist(os.path.join(root, "Applications/Safari.app/Contents/Info.plist"),
           {"CFBundleIdentifier": "com.apple.Safari", "CFBundleShortVersionString": "19.0"})
    # ---------------- networks
    _plist(os.path.join(root, "Library/Preferences/com.apple.wifi.known-networks.plist"), {
        "wifi.network.ssid.OwnerHome": {"SSID": b"OwnerHome", "AddedAt": dt.datetime.fromtimestamp(NOW - 400 * day),
                                        "JoinedByUserAt": dt.datetime.fromtimestamp(NOW - 400 * day)},
        "wifi.network.ssid.OtherHouse": {"SSID": b"OtherHouse", "AddedAt": dt.datetime.fromtimestamp(NOW - 12 * day),
                                         "JoinedByUserAt": dt.datetime.fromtimestamp(NOW - 12 * day)}})
    _plist(os.path.join(root, "private/var/db/dhcpclient/leases/en0-1,aa:bb:cc:dd:ee:ff"), {
        "IPAddress": "192.168.50.23", "RouterIPAddress": "192.168.50.1", "SSID": "OtherHouse",
        "LeaseStartDate": dt.datetime.fromtimestamp(NOW - 12 * day), "RouterHardwareAddress": b"\x11\x22\x33\x44\x55\x66"})
    _plist(os.path.join(home, "Library/Preferences/MobileMeAccounts.plist"), {"Accounts": [
        {"AccountID": "owner@example.com", "DisplayName": "Owner", "Services": [{"Name": "MESSAGES", "Enabled": True}]}]})
    # ---------------- e-mail accounts: Internet Accounts (incl. a DELETED row), Chrome sign-in + saved login,
    #                  Thunderbird, a leftover Apple Mail folder of a removed account, webmail history
    acc_db = os.path.join(home, "Library/Accounts/Accounts4.sqlite")
    _db(acc_db, """
        CREATE TABLE ZACCOUNTTYPE (Z_PK INTEGER PRIMARY KEY, ZACCOUNTTYPEDESCRIPTION TEXT, ZIDENTIFIER TEXT);
        CREATE TABLE ZACCOUNT (Z_PK INTEGER PRIMARY KEY, ZACCOUNTTYPE INTEGER, ZUSERNAME TEXT, ZACCOUNTDESCRIPTION TEXT,
            ZDATE REAL, ZIDENTIFIER TEXT, ZACTIVE INTEGER, ZOWNINGBUNDLEID TEXT);
    """, [("INSERT INTO ZACCOUNTTYPE VALUES (?,?,?)", [(1, "iCloud", "com.apple.account.AppleAccount"),
                                                     (2, "Google", "com.apple.account.Google")]),
          ("INSERT INTO ZACCOUNT VALUES (?,?,?,?,?,?,?,?)", [
              (1, 1, "owner@example.com", "iCloud", NOW - 500 * day - MAC_EPOCH, "11111111-1111-1111-1111-111111111111", 1, ""),
              (2, 2, "other.person@example.org", "Gmail", NOW - 25 * day - MAC_EPOCH, "22222222-2222-2222-2222-222222222222", 1, ""),
              (3, 2, "removed.account@example.org", "Gmail", NOW - 60 * day - MAC_EPOCH, "33333333-3333-3333-3333-333333333333", 1, "")])])
    c = sqlite3.connect(acc_db)
    c.execute("PRAGMA secure_delete=OFF")
    c.execute("DELETE FROM ZACCOUNT WHERE Z_PK = 3")   # removed account - bytes survive in the free page
    c.commit()
    c.close()
    gone = os.path.join(home, "Library/Mail/V10/44444444-4444-4444-4444-444444444444/INBOX.mbox/Messages")
    os.makedirs(gone, exist_ok=True)
    with open(os.path.join(gone, "1.emlx"), "w") as fh:
        fh.write("512\nDelivered-To: gone.mailbox@example.org\nTo: gone.mailbox@example.org\nSubject: hi\n\nbody\n")
    chrome = os.path.join(home, "Library/Application Support/Google/Chrome/Default")
    with open(os.path.join(chrome, "Preferences"), "w") as fh:
        fh.write('{"account_info": [{"email": "other.person@example.org", "full_name": "Other Person"}]}')
    _db(os.path.join(chrome, "Login Data"), """
        CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER,
            date_last_used INTEGER, times_used INTEGER);
    """, [("INSERT INTO logins VALUES (?,?,?,?,?,?)", [
        ("https://login.live.com/", WATCHED, b"\x00ENCRYPTED", int((NOW - 31 * day + 11644473600) * 1e6),
         int((NOW - 2 * day + 11644473600) * 1e6), 7)])])
    tb = os.path.join(home, "Library/Thunderbird/Profiles/abcd.default")
    os.makedirs(tb, exist_ok=True)
    with open(os.path.join(tb, "prefs.js"), "w") as fh:
        fh.write('user_pref("mail.identity.id1.useremail", "tb.user@example.org");\n')
    c = sqlite3.connect(os.path.join(home, "Library/Safari/History.db"))
    c.executemany("INSERT INTO history_items VALUES (?,?)", [(3, "https://mail.google.com/mail/u/0/#inbox"),
                                                             (4, "https://accounts.google.com/v3/signin/identifier")])
    c.executemany("INSERT INTO history_visits VALUES (?,?,?,?)", [(3, 3, NOW - 24 * day - MAC_EPOCH, "Gmail"),
                                                                  (4, 4, NOW - 25 * day - MAC_EPOCH, "Sign in")])
    c.commit()
    c.close()
    # recent user file
    os.makedirs(os.path.join(home, "Documents"), exist_ok=True)
    with open(os.path.join(home, "Documents", "notes.txt"), "w") as fh:
        fh.write("x")
    return {"home": home, "watched": WATCHED}
