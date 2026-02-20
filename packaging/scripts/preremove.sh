#!/bin/sh
set -e

# Stop and disable the service before removal
if [ -d /run/systemd/system ]; then
    systemctl stop vulners-proxy.service 2>/dev/null || true
    systemctl disable vulners-proxy.service 2>/dev/null || true
fi
