# OmenWatch integration for Wazuh: checks the IP addresses, domains, URLs,
# hashes and email senders in Wazuh alerts against OmenWatch's IOC database,
# and sends every match back into Wazuh as its own event, which the
# rules in omenwatch_rules.xml turn into an alert.
#
# Install on the Wazuh manager (see README.md, section 5):
#   /var/ossec/integrations/custom-omenwatch       (the wrapper, root:wazuh 750)
#   /var/ossec/integrations/custom-omenwatch.py    (this file, root:wazuh 750)
#   /var/ossec/etc/rules/omenwatch_rules.xml
#
# ossec.conf:
#   <integration>
#     <name>custom-omenwatch</name>
#     <hook_url>https://omenwatch.example</hook_url>   <!-- OmenWatch's address -->
#     <api_key>pms_...</api_key>                        <!-- a SIEM key: OmenWatch, Settings, Security -->
#     <group>web,sysmon,ids,firewall,syscheck</group>   <!-- which alerts to check -->
#     <alert_format>json</alert_format>
#     <options>{"min_confidence": 50}</options>          <!-- optional, see OPTIONS below -->
#   </integration>
#
# Only Python's standard library is used, so it runs on the Python that
# ships with the Wazuh manager. Wazuh calls it as (integratord):
#   custom-omenwatch <alert file> <api_key> <hook_url> <"debug" or ""> <options file or ""> <timeout> <retries>

import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from socket import AF_UNIX, SOCK_DGRAM, socket

NAME = "omenwatch"
WAZUH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{WAZUH}/logs/integrations.log"
SOCKET_ADDR = f"{WAZUH}/queue/sockets/queue"
MAX_VALUES = 100                  # per alert; OmenWatch accepts up to 1,000 per request

# Options (the <options> JSON object):
#   min_confidence  only report matches at least this confident (default 0)
#   verify_tls      false to accept OmenWatch's self-signed certificate (default true)
#   ca_file         a CA bundle that signs OmenWatch's certificate, instead of turning verification off
#   include_expired also report expired indicators (default false)
DEFAULT_OPTIONS = {"min_confidence": 0, "verify_tls": True, "ca_file": "", "include_expired": False}

# Alert fields worth checking, by the last part of their name (lowercase).
# Field names differ between decoders (Sysmon, Suricata, firewalls, web
# logs...), so this is a list of the common ones rather than exact paths.
IP_FIELDS = {"srcip", "dstip", "src_ip", "dst_ip", "dest_ip", "destip", "sourceip", "destinationip",
             "remote_ip", "remoteip", "client_ip", "clientip", "ipaddress"}
URL_FIELDS = {"url", "request_url", "http_url", "full_url"}
DOMAIN_FIELDS = {"queryname", "query", "dns_query", "destinationhostname", "http_host", "hostname_dst"}
HASH_FIELDS = {"md5", "sha1", "sha256", "md5_after", "sha1_after", "sha256_after", "hash", "file_hash", "hashes"}
EMAIL_FIELDS = {"sender", "from_address", "mail_from", "smtp_from"}
SKIP_SECTIONS = {"rule", "agent", "manager", "decoder", "predecoder", "full_log", "integration", NAME}
_SYSMON_HASHES = re.compile(r"(?:MD5|SHA1|SHA256)=([0-9A-Fa-f]{32,64})")

debug_enabled = False


def log(message: str, always: bool = False) -> None:
    if debug_enabled or always:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} {NAME}: {message}\n")
        except OSError:
            pass


def read_options(path: str) -> dict:
    options = dict(DEFAULT_OPTIONS)
    if path and os.path.exists(path):
        try:
            with open(path) as f:
                options.update(json.load(f))
        except (OSError, ValueError) as e:
            log(f"options file {path} ignored: {e}", always=True)
    return options


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def extract_observables(alert: dict) -> list[tuple[str, str]]:
    """(field path, value) for every value in the alert worth looking up, without duplicates."""
    found: dict[str, str] = {}

    def add(path, value):
        value = str(value).strip()
        if value and value not in found and len(found) < MAX_VALUES:
            found[value] = path

    def walk(node, path):
        if isinstance(node, dict):
            for key, child in node.items():
                if not path and key in SKIP_SECTIONS:
                    continue
                walk(child, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for child in node:
                walk(child, path)
        elif isinstance(node, (str, int)) and path:
            field = path.rsplit(".", 1)[-1].lower()
            value = str(node)
            if field in IP_FIELDS:
                if _public_ip(value):
                    add(path, value)
            elif field == "hashes":                       # Sysmon: "SHA1=...,MD5=...,SHA256=...,IMPHASH=..."
                for h in _SYSMON_HASHES.findall(value):
                    add(path, h)
            elif field in HASH_FIELDS:
                if re.fullmatch(r"[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", value):
                    add(path, value)
            elif field in URL_FIELDS or field in DOMAIN_FIELDS or field in EMAIL_FIELDS:
                if "." in value and " " not in value:
                    add(path, value)
    walk(alert, "")
    return [(path, value) for value, path in found.items()]


def lookup(values: list[str], hook_url: str, api_key: str, options: dict, timeout: int, retries: int) -> dict:
    url = hook_url.rstrip("/") + "/api/v1/lookup"
    body = json.dumps({"values": values, "include_expired": bool(options.get("include_expired"))}).encode()
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "User-Agent": "OmenWatch-Wazuh-integration",
    })
    context = None
    if url.lower().startswith("https://"):
        context = ssl.create_default_context(cafile=options.get("ca_file") or None)
        if options.get("verify_tls") is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    last_error = None
    for attempt in range(max(1, retries)):
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403):     # retrying won't help
                raise
            last_error = e
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            last_error = e
        time.sleep(min(2 ** attempt, 5))
    raise last_error


def build_events(alert: dict, observables: list[tuple[str, str]], result: dict, min_confidence: int) -> list[dict]:
    """One event per match, carrying the indicator's context and the alert it came from."""
    paths = {value: path for path, value in observables}
    rule = alert.get("rule", {})
    events = []
    for r in result.get("results", []):
        if not r.get("match") or int(r.get("confidence") or 0) < min_confidence:
            continue
        sources = r.get("sources") or []
        events.append({
            "integration": NAME,
            NAME: {
                "found": 1,
                "value": r["value"],
                "normalized": r.get("normalized") or r["value"],
                "type": r.get("type") or "",
                "confidence": int(r.get("confidence") or 0),
                "status": r.get("status") or "",
                "threat_type": r.get("threat_type") or "",
                "malware": r.get("malware") or "",
                "campaign": r.get("campaign") or "",
                "first_seen": r.get("first_seen") or "",
                "last_seen": r.get("last_seen") or "",
                "expires_at": r.get("expires_at") or "never",
                "sources": ", ".join(s.get("name", "") for s in sources),
                "reference": next((s["reference"] for s in sources if s.get("reference")), ""),
                "field": paths.get(r["value"], ""),
                "source": {"alert_id": alert.get("id", ""), "rule": str(rule.get("id", "")),
                           "description": rule.get("description", "")},
            },
        })
    return events


def error_event(alert: dict, code, description: str) -> dict:
    return {"integration": NAME, NAME: {"found": 0, "error": str(code), "description": description,
                                        "source": {"alert_id": alert.get("id", ""), "rule": str(alert.get("rule", {}).get("id", ""))}}}


def send_msg(msg: dict, agent: dict | None = None) -> None:
    """Into Wazuh's analysis queue, attributed to the alert's agent, the way Wazuh's own integrations do it."""
    if not agent or agent.get("id") == "000":
        string = f"1:{NAME}:{json.dumps(msg)}"
    else:
        location = f"[{agent['id']}] ({agent.get('name', '')}) {agent.get('ip', 'any')}"
        location = location.replace("|", "||").replace(":", "|:")
        string = f"1:{location}->{NAME}:{json.dumps(msg)}"
    log(f"sending {string}")
    sock = socket(AF_UNIX, SOCK_DGRAM)
    try:
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
    finally:
        sock.close()


def main(args: list[str]) -> int:
    global debug_enabled
    if len(args) < 4:
        log(f"wrong arguments: {args[1:]}", always=True)
        return 2
    alert_file, api_key, hook_url = args[1], args[2], args[3]
    debug_enabled = len(args) > 4 and args[4] == "debug"
    options = read_options(args[5] if len(args) > 5 else "")
    timeout = int(args[6]) if len(args) > 6 and args[6].isdigit() else 10
    retries = int(args[7]) if len(args) > 7 and args[7].isdigit() else 3
    if not hook_url or not api_key:
        log("set <hook_url> to OmenWatch's address and <api_key> to a SIEM key", always=True)
        return 2

    with open(alert_file) as f:
        alert = json.load(f)
    if alert.get("data", {}).get("integration") == NAME or NAME in alert.get("rule", {}).get("groups", []):
        return 0                                    # never look up our own events
    observables = extract_observables(alert)
    log(f"alert {alert.get('id')}: checking {[v for _, v in observables]}")
    if not observables:
        return 0
    try:
        result = lookup([v for _, v in observables], hook_url, api_key, options, timeout, retries)
    except urllib.error.HTTPError as e:
        message = {401: "OmenWatch refused the key: use a SIEM key from Settings, Security"}.get(e.code, f"HTTP {e.code} {e.reason}")
        log(message, always=True)
        send_msg(error_event(alert, e.code, message), alert.get("agent"))
        return 4
    except Exception as e:
        log(f"OmenWatch could not be reached: {e}", always=True)
        send_msg(error_event(alert, "unreachable", f"OmenWatch could not be reached: {e}"), alert.get("agent"))
        return 4
    for event in build_events(alert, observables, result, int(options.get("min_confidence") or 0)):
        send_msg(event, alert.get("agent"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
