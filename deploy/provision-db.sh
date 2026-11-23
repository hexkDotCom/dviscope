#!/usr/bin/env bash
# Creates the compose recipe's database secrets in deploy/secrets, once: a random password
# (readable only by the postgres image's user, UID 999) and the server's database URL
# (readable only by the server's service account, UID 10001). Existing secrets are kept:
# the database volume was initialized with that password. Also creates deploy/backups,
# where the `ops` service writes backups (owned by UID 10001, owner-only).
#
#   deploy/provision-db.sh        (needs sudo for chown)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd -P)
dest="$here/secrets"
if [ -L "$dest" ]; then echo "refusing: $dest is a symlink" >&2; exit 1; fi
real_dest=$(realpath -m "$dest")
case "$real_dest" in /mnt/*) echo "refusing: $real_dest is on a Windows drive; keep the compose directory on the Linux file system" >&2; exit 1;; esac
backups="$here/backups"
if [ -L "$backups" ]; then echo "refusing: $backups is a symlink" >&2; exit 1; fi
sudo install -d -m 0700 "$backups"
sudo chown 10001:10001 "$backups"
if sudo test -e "$dest/db_password" || sudo test -e "$dest/db_url"; then
  echo "kept: $dest already holds the database secrets"
  exit 0
fi
umask 077
snap=$(mktemp -d)
trap 'rm -rf "$snap"' EXIT
# 32 random bytes, URL-safe (no percent-encoding needed in the URL).
pw=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
printf '%s\n' "$pw" > "$snap/db_password"
printf 'postgres://dviscope:%s@db:5432/dviscope\n' "$pw" > "$snap/db_url"
sudo install -d -m 0755 "$dest"
sudo install -m 0400 "$snap/db_password" "$dest/db_password"
sudo install -m 0400 "$snap/db_url" "$dest/db_url"
sudo chown 999:999 "$dest/db_password"
sudo chown 10001:10001 "$dest/db_url"
echo "created $dest/db_password and $dest/db_url (never printed)"
