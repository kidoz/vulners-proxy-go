#!/bin/sh
set -e

# Reload systemd after removal
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi

# Remove system user on purge (deb) or full remove (rpm)
case "$1" in
    purge|0)
        if getent passwd vulners-proxy >/dev/null 2>&1; then
            userdel vulners-proxy 2>/dev/null || true
        fi
        if getent group vulners-proxy >/dev/null 2>&1; then
            groupdel vulners-proxy 2>/dev/null || true
        fi
        ;;
esac
