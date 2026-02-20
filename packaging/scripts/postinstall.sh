#!/bin/sh
set -e

# Create system user if it doesn't exist
if ! getent group vulners-proxy >/dev/null 2>&1; then
    groupadd --system vulners-proxy
fi
if ! getent passwd vulners-proxy >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid vulners-proxy vulners-proxy
fi

# Reload systemd and enable service
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable vulners-proxy.service
    echo "vulners-proxy installed. Edit /etc/vulners-proxy/config.toml and run:"
    echo "  systemctl start vulners-proxy"
fi
