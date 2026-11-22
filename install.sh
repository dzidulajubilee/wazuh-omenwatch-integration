#!/bin/sh
# Installs the OmenWatch integration on a Wazuh manager. Run as root from
# this folder:  sudo sh install.sh
# It copies the files with the owners and modes Wazuh expects and checks the
# rules load. It does not edit ossec.conf: it prints the block to add.
set -eu

WAZUH="${WAZUH_PATH:-/var/ossec}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "Run as root: sudo sh install.sh"; exit 1; }
[ -x "$WAZUH/bin/wazuh-control" ] || { echo "No Wazuh manager in $WAZUH (set WAZUH_PATH)"; exit 1; }
[ -x "$WAZUH/framework/python/bin/python3" ] || { echo "Wazuh's Python is missing: is this a manager, not an agent?"; exit 1; }

install -o root -g wazuh -m 750 "$HERE/custom-omenwatch" "$HERE/custom-omenwatch.py" "$WAZUH/integrations/"
install -o wazuh -g wazuh -m 660 "$HERE/omenwatch_rules.xml" "$WAZUH/etc/rules/"
install -o root -g root -m 750 "$HERE/omenwatch-cdb-sync" /usr/local/bin/
echo "Installed:"
echo "  $WAZUH/integrations/custom-omenwatch(.py)"
echo "  $WAZUH/etc/rules/omenwatch_rules.xml"
echo "  /usr/local/bin/omenwatch-cdb-sync (optional, for CDB lists)"

if "$WAZUH/bin/wazuh-analysisd" -t >/dev/null 2>&1; then
    echo "Rules check: OK"
else
    echo "Rules check FAILED:"; "$WAZUH/bin/wazuh-analysisd" -t || true; exit 1
fi

if grep -q "<name>custom-omenwatch</name>" "$WAZUH/etc/ossec.conf"; then
    echo
    echo "ossec.conf already has a custom-omenwatch integration. Restart to load the new files:"
    echo "  systemctl restart wazuh-manager"
else
    cat <<EOF

Now add this to $WAZUH/etc/ossec.conf (back it up first), with OmenWatch's
address and a SIEM key from OmenWatch, Settings, Security:

<ossec_config>
  <integration>
    <name>custom-omenwatch</name>
    <hook_url>https://omenwatch.example</hook_url>
    <api_key>pms_...</api_key>
    <group>sysmon,web,ids,firewall,syscheck,sshd</group>
    <alert_format>json</alert_format>
    <options>{"min_confidence": 50, "ca_file": "$WAZUH/etc/omenwatch.crt"}</options>
  </integration>
</ossec_config>

then:  systemctl restart wazuh-manager
EOF
fi
