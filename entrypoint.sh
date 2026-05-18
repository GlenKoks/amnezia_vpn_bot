#!/bin/sh
set -e

if [ -n "$SSH_KEY_B64" ]; then
    mkdir -p /app/.ssh
    printf '%s' "$SSH_KEY_B64" | base64 -d > /app/.ssh/id_ed25519
    chmod 600 /app/.ssh/id_ed25519
fi

exec python bot.py
