#!/bin/sh
# Minimal dhclient hook for the lab: configure the address only; never touch /etc/resolv.conf.
case "$reason" in
  BOUND|RENEW|REBIND|REBOOT) ip addr replace "$new_ip_address/27" dev "$interface" ;;
esac
exit 0
