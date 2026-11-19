# Wazuh–Pantomath integration

This folder lets **Wazuh** check what it sees on your computers and network
against **Pantomath's IOC database**. Wazuh raises an alert of its own when a
file hash, IP address, domain, URL or email sender in one of its alerts is a
known indicator in Pantomath. That alert says what the indicator is, how
confident Pantomath is, which malware or campaign it belongs to, and where
the report came from.

Everything in this folder goes on the **Wazuh manager**. Nothing is
installed on Pantomath or on the computers Wazuh watches.

**Requires**

- Pantomath **1.3.2 or later**, which has the IOC database and the `/api/v1`
  lookup API.
- A Wazuh **4.x manager**. This was tested with 4.14.9.
- Nothing else. The scripts use only Python's standard library and run on
  the Python that ships with Wazuh. The optional CDB sync also uses `curl`.

---

## Contents

1. [The words used in this guide](#1-the-words-used-in-this-guide)
2. [What each file does](#2-what-each-file-does)
3. [The two ways to connect: which do I need?](#3-the-two-ways-to-connect-which-do-i-need)
4. [Before you start](#4-before-you-start)
5. [Method A: real-time lookups (recommended)](#5-method-a-real-time-lookups-recommended)
6. [Method B: CDB lists with `pantomath-cdb-sync` (optional)](#6-method-b-cdb-lists-with-pantomath-cdb-sync-optional)
7. [Using both methods together](#7-using-both-methods-together)
8. [Seeing the results](#8-seeing-the-results)
9. [Testing it](#9-testing-it)
10. [Drill on a real endpoint (19 October 2026)](#10-drill-on-a-real-endpoint-19-october-2026)
11. [Troubleshooting](#11-troubleshooting)
12. [Updating and uninstalling](#12-updating-and-uninstalling)
13. [Questions people ask](#13-questions-people-ask)

---

## 1. The words used in this guide

| Word | Meaning |
|---|---|
| **Wazuh manager** | The central Wazuh server. It receives events, applies rules and stores alerts. In this guide's examples it is 192.168.1.10. |
| **Wazuh agent** | The small program on each computer Wazuh watches (the "endpoint"), such as the test PC at 192.168.1.50. It sends events to the manager. Nothing in this folder goes on agents. |
| **Event** | One thing Wazuh received, such as a log line, a file change, or a network connection seen by Sysmon. |
| **Rule** | A pattern Wazuh matches against events. When a rule matches, the event becomes an **alert** with a **level** from 0 (ignore) to 15 (critical). Every rule has a numeric ID; ours are 100800–100811. |
| **Alert** | An event that matched a rule with a level above 0. Alerts are stored in `/var/ossec/logs/alerts/alerts.json` and shown in the Wazuh dashboard. |
| **Rule group** | A label on rules, such as `sysmon`, `web` or `syscheck`. The integration uses groups to decide which alerts to check. |
| **integratord** | The part of the Wazuh manager that runs **integrations**: small programs it calls for each alert that passes a filter. Wazuh's VirusTotal and Slack integrations work this way, and so does `custom-pantomath`. |
| **`ossec.conf`** | The manager's main configuration file, `/var/ossec/etc/ossec.conf`. Most changes need a manager restart: `systemctl restart wazuh-manager`. |
| **CDB list** | Wazuh's built-in lookup table: a file of `key:value` lines in `/var/ossec/etc/lists/`. A rule can check whether a field's value is a key in the list. Wazuh reads CDB lists **only when the manager starts**. |
| **Syscheck / FIM** | Wazuh's file integrity monitoring. It reports files added or changed in watched folders, with their MD5, SHA-1 and SHA-256 hashes. This is how a downloaded file's hash reaches Pantomath. |
| **Indicator (IOC)** | A value Pantomath knows to be malicious (an IP, domain, URL, hash or email sender), with a **confidence** from 0 to 100. |
| **SIEM key** | A Pantomath key that starts with `pms_`. It opens `/api/v1` (lookup, export, health) and nothing else in Pantomath. You create it under Settings, Security, **SIEM keys**. `/api/v1` **refuses** normal API keys (`pmk_…`). |

---

## 2. What each file does

| File | Installed to | Needed? | What it does |
|---|---|---|---|
| `custom-pantomath` | `/var/ossec/integrations/` | **Yes** (method A) | A short shell wrapper. Wazuh's integratord runs this file by name, and it starts `custom-pantomath.py` with Wazuh's own Python. Wazuh starts its built-in integrations the same way. |
| `custom-pantomath.py` | `/var/ossec/integrations/` | **Yes** (method A) | The integration itself. For each alert Wazuh hands it, it collects the IPs, domains, URLs, hashes and email senders. It asks Pantomath about all of them in **one** request, then sends a new event back into Wazuh for each match. |
| `pantomath_rules.xml` | `/var/ossec/etc/rules/` | **Yes** | The rules that turn the integration's events into alerts with levels (100800–100804). It also holds two **commented-out** rules (100810, 100811) for method B. |
| `pantomath-cdb-sync` | `/usr/local/bin/` | **Optional** (method B only) | A script you run from cron. It downloads Pantomath's indicators as four CDB lists and restarts the manager when they change. Nothing runs it until you schedule it, and nothing uses the lists until you declare them and enable rules for them. [Section 6](#6-method-b-cdb-lists-with-pantomath-cdb-sync-optional) explains it in full. |
| `install.sh` | (run once) | Convenient | Copies the four files above with the owners and permissions Wazuh expects, checks that the rules load, and prints the `ossec.conf` block to add. It **does not** edit `ossec.conf`, set up cron or restart Wazuh. |

If you copy the files by hand instead of running `install.sh`, set these
owners and permissions:

| File | Owner | Mode |
|---|---|---|
| `/var/ossec/integrations/custom-pantomath` | `root:wazuh` | `750` |
| `/var/ossec/integrations/custom-pantomath.py` | `root:wazuh` | `750` |
| `/var/ossec/etc/rules/pantomath_rules.xml` | `wazuh:wazuh` | `660` |
| `/usr/local/bin/pantomath-cdb-sync` | `root:root` | `750` |

---

## 3. The two ways to connect: which do I need?

Wazuh can use Pantomath's indicators in two separate ways. **You only need
one.** Most people need only method A, the one the drill tested.

### Method A: real-time lookups (`custom-pantomath`)

Wazuh **asks Pantomath** each time one of the alerts you chose happens.

```
 endpoint            Wazuh manager                                   Pantomath
 ────────            ─────────────                                   ─────────
 file lands  ──►  rule 554 "File added"  ──►  integratord runs
                                               custom-pantomath  ──►  POST /api/v1/lookup
                                                                      "is 275a021b… known?"
                                               ◄──────────────────── "yes, confidence 100,
                                                                       EICAR test file"
                  rule 100801, level 12  ◄──  event sent back
                  "known payload indicator"
```

### Method B: CDB lists (`pantomath-cdb-sync`)

Wazuh **keeps its own copy** of Pantomath's indicators and checks against it
locally, without asking Pantomath.

```
 on a schedule (cron)                                                Pantomath
 pantomath-cdb-sync  ─────────────────────────────────────────────►  GET /api/v1/export?format=cdb
                     ◄─────────────────────────────────────────────  one "value:confidence" line
                                                                     per indicator
 writes /var/ossec/etc/lists/pantomath-ip (and -domain, -url, -hash)
 restarts the Wazuh manager if a list changed

 later, any event                Wazuh manager
 ────────────────                ─────────────
 connection to 198.51.100.23 ──► rule 100811: "is dstip in pantomath-ip?"  yes ──► alert, level 12
                                 (no request to Pantomath)
```

### Side by side

| | **A: real-time lookups** | **B: CDB lists** |
|---|---|---|
| How fresh | Always current: every check asks Pantomath | Only as current as the last sync **and** manager restart |
| Requests to Pantomath | One per alert checked | One download per list per sync |
| If Pantomath is down | Checks fail, and each one raises a level 3 "integration error" alert (100804) | Matching continues with the last lists |
| Detail in the Wazuh alert | Confidence, threat type, malware, campaign, sources, reference link, first and last seen, expiry | Confidence only (the list value) |
| Counted in Pantomath | Yes: *SIEM lookups today* and the **N×** marks on the IOC database tab | No |
| Restarts the Wazuh manager | Never, after setup | Every time a list changes |
| Which fields are checked | Many field names at once, including Sysmon hash strings and FIM hashes | Only the fields you write rules for: one rule per field per list |
| Setup | Install, add one `ossec.conf` block, restart | Install, add a cron job, declare 4 lists, enable or write rules, restart |
| **Choose it when** | **Normally** | You have so many events that one request per alert is too much, or the manager can't reach Pantomath reliably |

**If you're unsure, use method A only and ignore `pantomath-cdb-sync`.**
`install.sh` copies it to `/usr/local/bin/` in case you need it later, but it
does nothing until you schedule it.

---

## 4. Before you start

Do these once, whichever method you use.

### 4.1 The manager must reach Pantomath

From the Wazuh manager:

```bash
curl -k https://PANTOMATH_ADDRESS/api/v1/health
```

If Pantomath answers at all, even with *401 Unauthorized*, the network path
works. *Connection refused* or a timeout points to a firewall or a wrong
address.

### 4.2 Create a SIEM key in Pantomath

1. In Pantomath, open **Settings, Security, SIEM keys**.
2. Create a key named after the manager, for example *Wazuh manager (192.168.1.10)*.
3. Copy the key, which starts with `pms_`. Pantomath shows it only **once**.

With one key per Wazuh manager, you can revoke one without breaking the
others. Methods A and B can share a key.

### 4.3 Decide how the manager trusts Pantomath's HTTPS

Pantomath's `setup-https` makes a **self-signed** certificate, which nothing
trusts until you say so. You have three choices:

| Choice | Setting (method A / method B) | When to use it |
|---|---|---|
| **1. Don't verify** | `"verify_tls": false` / `PANTOMATH_INSECURE=1` | A network you trust, especially if Pantomath's IP address may change. There is never anything to renew. Traffic is still encrypted; you only lose proof that the server really is Pantomath. |
| **2. Verify Pantomath's own certificate** | `"ca_file": "/var/ossec/etc/pantomath.crt"` / `PANTOMATH_CA_FILE=/var/ossec/etc/pantomath.crt` | You want verification and don't mind copying one file. See the steps below. |
| **3. Use a certificate from your internal CA** | `ca_file` pointing at your CA bundle | Your organisation already runs a CA. This is the best option. |

**Steps for choice 2:**

1. Copy `/etc/nginx/ssl/pantomath.crt` from the Pantomath server to the
   manager as `/var/ossec/etc/pantomath.crt`, then run:
   ```bash
   chown root:wazuh /var/ossec/etc/pantomath.crt && chmod 640 /var/ossec/etc/pantomath.crt
   ```
2. The address in `hook_url` (or `PANTOMATH_URL`) must be **one of the names
   or IPs listed in the certificate**. To see what it lists:
   ```bash
   openssl x509 -in /var/ossec/etc/pantomath.crt -noout -ext subjectAltName
   ```
3. **Connect by name, not by IP**, if Pantomath's IP may ever change. The
   certificate lists the Pantomath server's host name. Have the manager
   connect to `https://pantomath-host/`, resolved by DNS or by a line in the
   manager's `/etc/hosts`. When the IP changes, you only update DNS or
   `/etc/hosts`; the certificate stays valid and **doesn't need renewing**.
   If you connect by IP, verification only works while the IP stays the same.
4. A certificate made **before Pantomath 1.3.0** lists only `pantomath.local`
   and can't be verified by IP at all. Pantomath never replaces an existing
   certificate by itself. To verify, run this once on the Pantomath server,
   then repeat step 1:
   ```bash
   sudo pantomath-admin setup-https --renew-certificate
   ```
   Browsers will ask you once to accept the new certificate.

### 4.4 Check the key works

From the manager (use `-k` instead of `--cacert …` for choice 1):

```bash
curl --cacert /var/ossec/etc/pantomath.crt \
     -H "Authorization: Bearer pms_YOUR_KEY" \
     https://PANTOMATH_ADDRESS/api/v1/health
```

If it works, you get JSON with `status` (`ok`, or `degraded` when a feed is
failing), Pantomath's `version`, active indicator counts by type, and feed
health. *401* means the key is wrong or revoked, or is a normal `pmk_` API
key rather than a SIEM key.

---

## 5. Method A: real-time lookups (recommended)

### 5.1 Install

Copy this folder to the Wazuh manager. Then, from inside it, run:

```bash
sudo sh install.sh
```

It checks that it's running on a manager, not an agent, and copies the
files (section 2). It then runs `wazuh-analysisd -t` to make sure the rules
load, and prints the `ossec.conf` block to add. Nothing is active yet.

### 5.2 Configure

Back up `ossec.conf` first:

```bash
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.before-pantomath
```

Then add this inside `<ossec_config>`, or as its own `<ossec_config>` block
at the end of the file:

```xml
<integration>
  <name>custom-pantomath</name>
  <hook_url>https://PANTOMATH_ADDRESS</hook_url>
  <api_key>pms_YOUR_KEY</api_key>
  <group>sysmon,web,ids,firewall,syscheck,sshd</group>
  <alert_format>json</alert_format>
  <options>{"min_confidence": 50, "verify_tls": false}</options>
</integration>
```

What each element means:

| Element | Meaning |
|---|---|
| `<name>` | Must be exactly `custom-pantomath`. Wazuh runs `/var/ossec/integrations/custom-pantomath`, and the `custom-` prefix tells Wazuh it isn't a built-in integration. |
| `<hook_url>` | Pantomath's address, **without** `/api/v1` (the script adds that). If you verify TLS, use a name the certificate lists (section 4.3). |
| `<api_key>` | The SIEM key from section 4.2. |
| `<group>` | **Which alerts are checked.** Only alerts with at least one of these rule groups go to the integration. Separate groups with commas and no spaces. |
| `<alert_format>` | Must be `json`. |
| `<options>` | Optional settings, as a JSON object (see below). |

Wazuh also accepts `<rule_id>` (a comma-separated list of rule IDs) and
`<level>` (alerts at this level or higher), instead of or as well as
`<group>`. **With no filter at all, every alert goes to the integration**,
which means one request to Pantomath per alert. Start narrow and widen
later.

Groups worth checking:

| Group | What it carries |
|---|---|
| `syscheck` | Files added or changed (FIM), with their **file hashes**. Needed to catch malware landing on a PC. |
| `sysmon` | Windows Sysmon: process hashes, network connections (`destinationIp`), DNS queries (`queryName`). |
| `web` | Web server logs: client IPs and URLs. |
| `ids` | Suricata and similar: source and destination IPs, URLs, host names. |
| `firewall` | Firewall logs: source and destination IPs. |
| `sshd` | SSH logins: the IP that tried to log in. |

The `<options>` settings:

| Option | Default | Meaning |
|---|---|---|
| `min_confidence` | `0` | Only report matches at least this confident. `50` is a sensible start. Weaker matches are dropped without a message. |
| `verify_tls` | `true` | `false` accepts Pantomath's certificate without checking it (choice 1 in section 4.3). |
| `ca_file` | (none) | The certificate or CA bundle that verifies Pantomath (choices 2 and 3). |
| `include_expired` | `false` | Also report indicators that have expired in Pantomath. |

### 5.3 Check and restart

```bash
/var/ossec/bin/wazuh-analysisd -t        # prints nothing when the rules and config load
systemctl restart wazuh-manager
grep custom-pantomath /var/ossec/logs/ossec.log
```

The last command should show
`wazuh-integratord: INFO: Enabling integration for: 'custom-pantomath'`.

### 5.4 What the integration does for each alert

1. Wazuh writes the alert to a temporary file, then runs `custom-pantomath`
   with the file, the key, the address and the options.
2. The script **skips the alert** if it is one of its own events, so it
   never loops.
3. It collects values from the alert's fields with these names, at any
   depth and from any decoder:

   | Kind | Field names |
   |---|---|
   | IP | `srcip`, `dstip`, `src_ip`, `dst_ip`, `dest_ip`, `destip`, `sourceip`, `destinationip`, `remote_ip`, `remoteip`, `client_ip`, `clientip`, `ipaddress` |
   | URL | `url`, `request_url`, `http_url`, `full_url` |
   | Domain | `queryname`, `query`, `dns_query`, `destinationhostname`, `http_host`, `hostname_dst` |
   | Hash | `md5`, `sha1`, `sha256`, `md5_after`, `sha1_after`, `sha256_after` (from FIM), `hash`, `file_hash`, and Sysmon's `hashes` string (`SHA256=…,MD5=…`; its IMPHASH is ignored) |
   | Email sender | `sender`, `from_address`, `mail_from`, `smtp_from` |

   Names are compared in lowercase. **Private and other non-public IP
   addresses** (10.x, 192.168.x, 172.16–31.x, loopback, documentation
   ranges) are skipped, so your own machines' addresses never leave the
   manager. The alert's `rule`, `agent`, `manager` and `decoder` sections
   and its `full_log` are **never** sent. It collects at most 100 values per
   alert.
4. If it collected nothing, it stops without making a request.
5. Otherwise it sends **one** request, `POST /api/v1/lookup`, with every
   value. Unless Wazuh passes other limits, it waits up to 10 seconds and
   tries up to 3 times. A refused key (401 or 403) or a bad request (400)
   isn't retried.
6. For each value Pantomath knows, at or above `min_confidence`, it sends
   one event back into Wazuh. The event is **attributed to the same agent**
   as the original alert, so the new alert shows on that computer in the
   dashboard.
7. Values Pantomath doesn't know produce nothing.
8. If it can't ask Pantomath (wrong key, server unreachable, certificate
   refused), it sends one error event instead and writes the reason to
   `/var/ossec/logs/integrations.log`.

### 5.5 What comes back, and the alerts it raises

Each match is a JSON event with `integration: pantomath` and a `pantomath`
object:

| Field | Example | Meaning |
|---|---|---|
| `found` | `1` | 1 for a match, 0 for an error event |
| `value` | `198.51.100.23` | The value as it appeared in the alert |
| `normalized` | `198.51.100.23` | The value as Pantomath stores it (lowercased, refanged, punycode) |
| `type` | `ipv4` | One of ipv4, ipv6, domain, url, md5, sha1, sha256, email |
| `confidence` | `100` | 0–100 |
| `status` | `active` | Or `expired`, when `include_expired` is on |
| `threat_type` | `botnet_cc` | What the indicator is, according to the feed |
| `malware` | `Remcos` | The malware family, if known |
| `campaign` | | The campaign, if known |
| `sources` | `ThreatFox, Feodo Tracker` | Every source that reports it |
| `reference` | `https://threatfox.abuse.ch/ioc/…` | A link to the first source's report |
| `first_seen`, `last_seen`, `expires_at` | | When it was first and last reported, and when it expires (`never` for hashes) |
| `field` | `data.srcip` | **Where in the original alert** the value was found |
| `source.alert_id`, `source.rule`, `source.description` | | The original alert that was checked |

`pantomath_rules.xml` turns these events into alerts:

| Rule | Level | When | Rule groups |
|---|---|---|---|
| 100800 | 0 | Any event from the integration. It's the parent rule and never shows by itself. | `pantomath`, `threat_intel` |
| **100801** | **12** | A match with confidence **80–100** | `pantomath_match`, `pantomath_high` |
| **100802** | **10** | A match with confidence **50–79** | `pantomath_match` |
| **100803** | **6** | Any other match (below 50) | `pantomath_match`, `pantomath_low` |
| **100804** | **3** | The integration couldn't ask Pantomath; the description says why | `pantomath_error` |

An alert reads, for example: *"Pantomath: 198.51.100.23 in data.srcip is a
known botnet_cc indicator (Remcos), confidence 100"*.

If IDs 100800–100811 clash with your own local rules, change them in
`pantomath_rules.xml`, and update every `if_sid` that points to them.

### 5.6 Try the rules without a real alert

`wazuh-logtest` shows how Wazuh treats an event like the ones the
integration sends:

```bash
echo '{"integration":"pantomath","pantomath":{"found":1,"value":"203.0.113.45","confidence":90,"threat_type":"c2","malware":"QakBot","field":"data.srcip"}}' | /var/ossec/bin/wazuh-logtest
```

It should report rule **100801, level 12**. Set `confidence` to 60 to get
100802, or to 20 to get 100803. This tests only the rules, not the
connection to Pantomath; [section 9](#9-testing-it) tests the whole chain.

---

## 6. Method B: CDB lists with `pantomath-cdb-sync` (optional)

**Skip this section if you use method A.** The real-time integration needs
nothing in it.

### 6.1 What `pantomath-cdb-sync` is for

Wazuh can match fields against **CDB lists**, which are local lookup tables
in `/var/ossec/etc/lists/`. Matching against a list costs nothing and needs
no network. But the list has to come from somewhere and be kept up to date.
`pantomath-cdb-sync` **fills and refreshes those lists from Pantomath**. It
is a plain shell script that you run on a schedule (cron). It isn't part of
Wazuh, and Wazuh never runs it.

### 6.2 What it does each time it runs

1. **Checks its settings.** It stops with an error if `PANTOMATH_URL` or
   `PANTOMATH_KEY` is missing.
2. **Downloads four lists** from Pantomath into a temporary folder, one
   request each:

   | List file | Request | Holds |
   |---|---|---|
   | `/var/ossec/etc/lists/pantomath-ip` | `/api/v1/export?format=cdb&type=ip` | IPv4 and IPv6 addresses |
   | `/var/ossec/etc/lists/pantomath-domain` | `…&type=domain` | Domains |
   | `/var/ossec/etc/lists/pantomath-url` | `…&type=url` | URLs |
   | `/var/ossec/etc/lists/pantomath-hash` | `…&type=hash` | MD5, SHA-1 and SHA-256 hashes |

   Each request includes `min_confidence` (default 50), so low-confidence
   indicators stay out. Only **active** indicators are exported, not
   expired, false-positive or allowlisted ones.
3. **Compares** each download with the list already on the manager.
4. **Replaces only the lists that changed** (owner `wazuh:wazuh`, mode 660),
   and prints how many entries each new list has.
5. **Restarts the Wazuh manager** if at least one list changed, because
   Wazuh only reads CDB lists at startup. If nothing changed, it stops
   there.
6. **Cleans up** the temporary folder, whatever happened.

If any download fails (wrong key, network, certificate), the script stops
with an error **before** replacing any list, so the lists in place keep
working.

### 6.3 What the lists look like

Each line holds one indicator as `value:confidence`:

```
198.51.100.23:100
evil-login.example:85
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:100
"2001:db8::bad":90
"http://evil.example/payload.exe":75
```

Values that contain a colon (IPv6 addresses, URLs) are wrapped in double
quotes, as Wazuh requires. The number after the last colon is the
confidence.

### 6.4 Its settings

All settings are environment variables. Set them on the cron line (6.5,
step 5) or in front of the command.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `PANTOMATH_URL` | **Yes** | | Pantomath's address, for example `https://pantomath-host` |
| `PANTOMATH_KEY` | **Yes** | | A SIEM key (`pms_…`) |
| `PANTOMATH_MIN_CONFIDENCE` | No | `50` | Leave out indicators below this confidence |
| `PANTOMATH_CA_FILE` | No | | The certificate that verifies Pantomath (section 4.3, choice 2) |
| `PANTOMATH_INSECURE` | No | `0` | `1` accepts a self-signed certificate without checking it (choice 1) |
| `WAZUH_PATH` | No | `/var/ossec` | Where Wazuh is installed |

### 6.5 Set it up

1. **Run it once by hand**, so the list files exist before you declare them
   to Wazuh. Wazuh reports an error for a declared list whose file is
   missing.

   ```bash
   sudo PANTOMATH_URL=https://PANTOMATH_ADDRESS PANTOMATH_KEY=pms_YOUR_KEY PANTOMATH_INSECURE=1 \
     /usr/local/bin/pantomath-cdb-sync
   ```

   It prints a line such as `pantomath-ip: 18234 entries` for each list,
   then restarts the manager.

2. **Declare the lists** in the `<ruleset>` block of `ossec.conf`, next to
   the lists already there:

   ```xml
   <list>etc/lists/pantomath-ip</list>
   <list>etc/lists/pantomath-domain</list>
   <list>etc/lists/pantomath-url</list>
   <list>etc/lists/pantomath-hash</list>
   ```

   You only need to declare the lists you'll write rules for.

3. **Enable rules that use them.** Declaring a list does nothing by itself:
   a rule has to look values up in it. Two ready-made rules sit, commented
   out, at the bottom of `pantomath_rules.xml`:

   | Rule | Level | Checks |
   |---|---|---|
   | 100810 | 12 | An alert's **source IP** (`srcip`) against `pantomath-ip` |
   | 100811 | 12 | An alert's **destination IP** (`dstip`) against `pantomath-ip` |

   Both build on alerts that already matched a rule at level 3. To enable
   them, remove the `<!--` and `-->` around them.

   For domains, URLs and hashes, write your own rules for the field names
   your decoders produce. For example, for file hashes from file integrity
   monitoring:

   ```xml
   <rule id="100812" level="12">
     <if_group>syscheck</if_group>
     <list field="syscheck.sha256_after" lookup="match_key">etc/lists/pantomath-hash</list>
     <description>Pantomath CDB: file $(syscheck.path) has a known malicious SHA-256</description>
     <group>pantomath_match,pantomath_cdb,</group>
   </rule>
   ```

   Use `lookup="address_match_key"` for IP fields, because it understands IP
   addresses, and `lookup="match_key"` for everything else. Give new rules
   IDs from 100812 to 100819.

4. **Check and restart:**

   ```bash
   /var/ossec/bin/wazuh-analysisd -t
   systemctl restart wazuh-manager
   ```

5. **Schedule it** with this one line in `/etc/cron.d/pantomath`:

   ```
   0 */4 * * * root PANTOMATH_URL=https://PANTOMATH_ADDRESS PANTOMATH_KEY=pms_YOUR_KEY PANTOMATH_INSECURE=1 /usr/local/bin/pantomath-cdb-sync >> /var/log/pantomath-cdb-sync.log 2>&1
   ```

   It runs every 4 hours and appends its output to a log. The file contains
   the key, so make it readable only by root: `chmod 600 /etc/cron.d/pantomath`.

### 6.6 How often to run it: the restart trade-off

**The Wazuh manager restarts every time a list changes.** A restart takes
from a few seconds to a minute, and the manager doesn't analyse events
meanwhile. Agents buffer events and resend them, so events arrive late but
aren't lost.

Pantomath's feeds update many times a day, so the lists will almost always
have changed since the last run. In practice, **the manager restarts every
time the sync runs**:

| Interval | Lists are at most | Restarts per day |
|---|---|---|
| Every 30 minutes | ~30 minutes old | ~48 |
| Every 4 hours | ~4 hours old | ~6 |
| Once a day, at night | a day old | 1 |

Pick the longest interval you can live with. If you need fresher data than
that, method A probably suits you better. A higher `PANTOMATH_MIN_CONFIDENCE`
makes the lists smaller, so they change less often, but they will still
change.

---

## 7. Using both methods together

You can run both, but then one event can raise **two** alerts for the same
indicator: 100801 from the integration, and 100810/100811 (or your own CDB
rule) from the lists. A common split:

- Method A for the alerts that matter most and aren't too frequent
  (`syscheck`, `sysmon`, `ids`).
- Method B, with your own rules, for very frequent events you don't want to
  send to Pantomath one by one, such as every firewall connection.

To avoid duplicates, don't check the same groups with both methods.

---

## 8. Seeing the results

**In the Wazuh dashboard**, go to Threat Hunting (or Discover) and filter on:

| Filter | Shows |
|---|---|
| `rule.groups:pantomath_match` | Every match, from either method |
| `rule.id:100801` | High-confidence matches from the integration |
| `rule.groups:pantomath_cdb` | Matches from the CDB lists |
| `rule.groups:pantomath_error` | Times the integration couldn't ask Pantomath |
| `data.pantomath.malware:Remcos` | Matches for one malware family |

Integration matches are attributed **to the agent** whose alert was
checked, so they also appear on that computer's page.

**On the manager:**

```bash
grep '"pantomath"' /var/ossec/logs/alerts/alerts.json | tail -5
```

**In Pantomath**, on the IOC database tab: *SIEM lookups today* counts the
integration's lookups. Indicators that Wazuh asked about and found get an
**N×** mark, updated within 30 seconds, and the **N×** filter shows only the
indicators your network actually touched. CDB matches don't count here,
because with method B Wazuh never asks Pantomath about individual values.

---

## 9. Testing it

These steps test the real-time integration on the manager alone, with no
endpoint involved.

1. In Pantomath, IOC database, **+ Add indicators**: add
   `pantomath-wazuh-test.example` with confidence 90 and threat type
   `phishing`.
2. On the Wazuh manager, have Wazuh read a test log and raise an alert for
   it. Add this to `ossec.conf`:

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/pantomath-test.json</location>
   </localfile>
   ```

   and this to `/var/ossec/etc/rules/local_rules.xml`:

   ```xml
   <group name="pantomath_test,">
     <rule id="100890" level="5">
       <decoded_as>json</decoded_as>
       <field name="test">^pantomath$</field>
       <description>Pantomath integration test event</description>
     </rule>
   </group>
   ```

   Add `pantomath_test` to the integration's `<group>`, then restart the
   manager.
3. Write a test event:

   ```bash
   echo '{"test":"pantomath","url":"http://pantomath-wazuh-test.example/login","queryName":"pantomath-wazuh-test.example"}' >> /var/log/pantomath-test.json
   ```

4. Within a few seconds, `/var/ossec/logs/alerts/alerts.json` and the Wazuh
   dashboard show rule 100890, then rule **100801**: *"Pantomath:
   pantomath-wazuh-test.example in data.queryName is a known phishing
   indicator…"*. In Pantomath, the summary counts the SIEM lookups, and
   within 30 seconds the indicator shows **1×**.
5. **File hashes**, using the harmless EICAR antivirus test file. In
   Pantomath, add EICAR's SHA-256,
   `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`. In
   `ossec.conf`, have Wazuh watch a test folder in real time:

   ```xml
   <syscheck>
     <directories realtime="yes" check_all="yes">/root/pantomath-fim-test</directories>
   </syscheck>
   ```

   Restart the manager and create the file:

   ```bash
   mkdir -p /root/pantomath-fim-test
   printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /root/pantomath-fim-test/eicar.com
   ```

   Rule 554 (*File added to the system*) is followed by **100801**: *"… in
   syscheck.sha256_after is a known payload indicator (EICAR test file)…"*.
6. When done, delete the test indicators in Pantomath, and remove the test
   `<localfile>`, the `<syscheck>` folder, the test rule and the
   `pantomath_test` group.

**Testing method B:** after step 1, run `pantomath-cdb-sync` by hand, then
check that the value is in the list:

```bash
grep pantomath-wazuh-test.example /var/ossec/etc/lists/pantomath-domain
```

---

## 10. Drill on a real endpoint (19 October 2026)

This is the real case: a file Pantomath knows lands on a computer that runs
a Wazuh agent. Agents only report file hashes for folders that their file
integrity monitoring watches. So first, have the agents watch the folder
where downloads land, in real time. You can do this from the manager,
without touching the endpoint. In `/var/ossec/etc/shared/default/agent.conf`
(the `default` agent group), add:

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" check_all="yes">/home/test/Downloads</directories>
  </syscheck>
</agent_config>
```

`/var/ossec/bin/verify-agent-conf` checks the file. Agents pick up the
change and restart on their own within a minute;
`/var/ossec/bin/agent_groups -S -i <id>` then says *synchronized*. On
Windows agents, use a path such as `C:\Users\*\Downloads`.

Next, on the endpoint, put the EICAR test file where a download would land.
EICAR is harmless; never use live malware for a drill.

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/invoice-october.pdf.exe
```

EICAR's SHA-256 must be in Pantomath (section 9, step 5). This is what
happened in the drill (Wazuh 4.14.9 manager, agent on Ubuntu 24.04,
Pantomath 1.2.0):

| Time (UTC) | |
|---|---|
| 19:50:55 | The file lands in `/home/test/Downloads` |
| 19:50:55 | Agent: rule 554, *File added to the system* |
| 19:50:57 | **Rule 100801, level 12, on the agent**: *"Pantomath: 275a021b… in syscheck.sha256_after is a known payload indicator"*, also shown in the Wazuh dashboard |

After Pantomath was upgraded to 1.3.x, a test event with the source IP
198.51.100.23 raised rule **100801, level 12**: *"Pantomath: 198.51.100.23
in data.srcip is a known botnet_cc indicator (Remcos), confidence 100"*.

---

## 11. Troubleshooting

Start with these files:

| File | What's in it |
|---|---|
| `/var/ossec/logs/integrations.log` | The integration's errors (always), and every call it makes when debug mode is on |
| `/var/ossec/logs/ossec.log` | Whether integratord loaded the integration, and configuration errors |
| `/var/ossec/logs/alerts/alerts.json` | Every alert, including the integration's |
| `/var/log/pantomath-cdb-sync.log` | The CDB sync's output, if you use the cron line from 6.5 |

**Debug mode** logs every alert the integration receives, the values it
sent, and what came back. To turn it on, add this line to
`/var/ossec/etc/local_internal_options.conf`:

```
integrator.debug=2
```

Then restart the manager and watch `integrations.log`. Remove the line when
you're done, because it logs a lot.

### Real-time integration (method A)

| Symptom | Likely cause | Fix |
|---|---|---|
| No `Enabling integration for: 'custom-pantomath'` in `ossec.log` | The `<integration>` block is missing, misspelled or outside `<ossec_config>`, or the manager wasn't restarted | Check the block, run `wazuh-analysisd -t`, then restart |
| `ossec.log` says *Unable to run integration* or *permission denied* | Wrong owner or mode on the scripts | Run `install.sh` again, or apply the table in section 2 |
| Nothing in `integrations.log`, even with debug on | The alerts you expect don't have any of the groups in `<group>` | Find the alert's `rule.groups` in `alerts.json` and add one of them |
| The debug log says *checking []* | The alert has no fields the integration recognises, or only private IPs | That's expected for private IPs. Otherwise, compare the field names with 5.4 |
| Rule 100804, *Pantomath refused the key* | A `pmk_` API key was used instead of a `pms_` SIEM key, or the key was revoked | Create a SIEM key (4.2) and put it in `<api_key>` |
| Rule 100804, *could not be reached* … *CERTIFICATE_VERIFY_FAILED* | The manager doesn't trust Pantomath's certificate | Set `"verify_tls": false`, or use `ca_file` (4.3) |
| … *hostname mismatch* or *doesn't match* | `hook_url` uses a name or IP that the certificate doesn't list | Connect by a name it lists (4.3, step 3), or set `"verify_tls": false` |
| … *Connection refused* or *timed out* | Network, firewall or a wrong address, or Pantomath is stopped | Test with `curl` from the manager (4.1); run `systemctl status pantomath` on Pantomath |
| Lookups work, but a known value raises no alert | Its confidence is below `min_confidence`, it has expired (and `include_expired` is false), or it's marked false positive or allowlisted | Look the value up on Pantomath's IOC database tab |
| `wazuh-analysisd -t` complains about rule IDs | 100800–100811 clash with your own rules | Renumber them in `pantomath_rules.xml` |
| **N×** marks don't appear in Pantomath | They're written every 30 seconds | Wait a little. CDB matches are never counted. |

### CDB sync (method B)

| Symptom | Likely cause | Fix |
|---|---|---|
| `set PANTOMATH_URL…` or `set PANTOMATH_KEY…` | The variable isn't set. Cron doesn't see your shell's variables. | Put them on the cron line, as in 6.5 |
| `curl: (22) … 401` | Not a SIEM key, or the key was revoked | See 4.2 |
| `curl: (60) SSL certificate problem` | The certificate isn't trusted | Set `PANTOMATH_INSECURE=1` or `PANTOMATH_CA_FILE` |
| `curl: (7)` or `curl: (28)` | Pantomath can't be reached, or is too slow to answer | See 4.1 |
| Wazuh reports a list error after you declare the lists | A declared list file doesn't exist yet | Run the sync once by hand (6.5, step 1) |
| The lists are filled but nothing matches | No enabled rule uses them, or the rule's field name doesn't match your decoder's | Uncomment 100810/100811, or write a rule for your field (6.5, step 3) |
| The manager restarts too often | The sync runs too often | Run it less often (6.6) |
| A value is in Pantomath but not in the list | It's below `PANTOMATH_MIN_CONFIDENCE`, isn't active, or was added after the last sync | Lower the minimum, or run the sync |

---

## 12. Updating and uninstalling

**Updating:** copy the new folder to the manager and run `sudo sh install.sh`
again. It overwrites the files and leaves `ossec.conf` alone. Then run
`systemctl restart wazuh-manager`. If you edited `pantomath_rules.xml` (to
enable 100810/100811, for example), keep a copy first and redo your changes
afterwards.

**Uninstalling:**

```bash
rm /var/ossec/integrations/custom-pantomath /var/ossec/integrations/custom-pantomath.py
rm /var/ossec/etc/rules/pantomath_rules.xml
rm -f /usr/local/bin/pantomath-cdb-sync /etc/cron.d/pantomath
rm -f /var/ossec/etc/lists/pantomath-*
```

Then remove the `<integration>` block and any `<list>etc/lists/pantomath-…</list>`
lines from `ossec.conf` (or restore your backup) and restart the manager.
Finally, revoke the SIEM key in Pantomath, under Settings, Security.

---

## 13. Questions people ask

**Do I need `pantomath-cdb-sync`?**
No, not if you use the real-time integration (method A). It's only for
method B. If it's installed but not scheduled, it does nothing.

**Is anything installed on the endpoints?**
No, only the Wazuh agent you already have. To catch file hashes, the
agents' file integrity monitoring must watch the folders you care about,
which you can set from the manager (section 10).

**What does Pantomath learn about my network?**
Only the public IPs, domains, URLs, hashes and email senders from the alerts
you choose to check. Private IPs, agent names, rule details and raw logs
are never sent.

**Will this slow Wazuh down?**
No. The integration runs alongside analysis, not in its way. The original
alert is stored no matter what, and the Pantomath alert follows a moment
later (2 seconds in the drill). Each checked alert costs one small HTTPS
request, which is why `<group>` should stay narrow.

**What happens if Pantomath is down?**
With method A, each checked alert raises a level 3 *integration error*
alert (100804), and nothing is matched until Pantomath is back. With
method B, the sync fails without touching the lists, so the last lists keep
working.

**Pantomath's IP address changed. What do I do?**
Update `hook_url` (and `PANTOMATH_URL`, if you use the sync), then restart
the manager. With `verify_tls: false`, that's all. If you verify TLS and
connect by name, you instead update DNS or `/etc/hosts`, and change nothing
in Wazuh. Either way, the certificate doesn't need renewing.

**Why did a known indicator raise only level 6 or 10?**
The level follows Pantomath's confidence: 80 and above is level 12, 50–79
is level 10, and anything lower is level 6. Each extra source that reports
an indicator adds 10 to its confidence, and an analyst can set the
confidence in Pantomath.

**Can I change the levels?**
Yes. Edit `level="…"` or the confidence patterns in `pantomath_rules.xml`,
check with `wazuh-analysisd -t`, then restart.
