# ownline-core

## Needed firewall rule

If using SPA server without sniffing, this rule is needed: `iptables -I INPUT 8 -p udp -m udp --dport <spa_UDP_port> -m limit --limit 10/minute --limit-burst 1 -j ACCEPT`

## System requirements

``
opkg install gcc curl
opkg install python3 python3 python3-dev python3-pip
pip3 install wheels
``


