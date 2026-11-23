#!/usr/bin/env bash
# Installs a server certificate and key into deploy/tls for the compose recipe, owned by the
# container's service account (UID 10001) and readable only by it. Run after
# `dviscope tls init|renew --server-dir <staging>`; the staging copy stays with the
# maintainer. The switch is undone if any step fails, so the active pair always stays
# usable; the previous pair is kept as *.old after success.
#
#   deploy/provision-tls.sh <staging-dir>     (needs sudo for chown)
set -euo pipefail
staging=${1:?usage: provision-tls.sh <staging-dir>}
here=$(cd "$(dirname "$0")" && pwd -P)
dest="$here/tls"
# The destination and anything inside it must be real directories/files on the Linux file
# system: no symlinks (they could point at /mnt or elsewhere).
if [ -L "$dest" ]; then echo "refusing: $dest is a symlink" >&2; exit 1; fi
real_dest=$(realpath -m "$dest")
case "$real_dest" in /mnt/*) echo "refusing: $real_dest is on a Windows drive; keep the compose directory on the Linux file system" >&2; exit 1;; esac
for f in server.pem server.key server.pem.new server.key.new server.pem.old server.key.old; do
  if sudo test -L "$dest/$f"; then echo "refusing: $dest/$f is a symlink" >&2; exit 1; fi
done

exec 9>"$here/.provision-tls.lock"
flock -n 9 || { echo "another provisioning is running" >&2; exit 1; }

# Snapshot the staged pair (so a concurrent renewal cannot mix generations), then verify
# that the certificate and key belong together.
snap=$(mktemp -d)
trap 'rm -rf "$snap"' EXIT
chmod 700 "$snap"
for f in server.pem server.key; do
  [ -f "$staging/$f" ] || { echo "missing $staging/$f" >&2; exit 1; }
  cp "$staging/$f" "$snap/$f"
done
cert_pub=$(openssl x509 -in "$snap/server.pem" -noout -pubkey 2>/dev/null) || { echo "staged certificate is not valid PEM" >&2; exit 1; }
key_pub=$(openssl pkey -in "$snap/server.key" -pubout 2>/dev/null) || { echo "staged key is not a valid private key" >&2; exit 1; }
[ "$cert_pub" = "$key_pub" ] || { echo "staged certificate and key do not match" >&2; exit 1; }

# Numeric owners via chown: some install(1) implementations only accept names for -o/-g.
sudo install -d -m 0500 "$dest"
sudo chown 10001:10001 "$dest"
sudo install -m 0444 "$snap/server.pem" "$dest/server.pem.new"
sudo install -m 0400 "$snap/server.key" "$dest/server.key.new"
sudo chown 10001:10001 "$dest/server.pem.new" "$dest/server.key.new"

done_steps=()
rollback() {
  for ((i=${#done_steps[@]}-1; i>=0; i--)); do
    IFS='>' read -r from to <<<"${done_steps[$i]}"
    sudo mv -f "$to" "$from" || true
  done
  echo "provisioning failed; the previous certificate and key are still active" >&2
}
step() { # step FROM TO
  if sudo mv -f "$1" "$2"; then done_steps+=("$1>$2"); else rollback; exit 1; fi
}
stamp=$$
for f in server.pem server.key; do
  if sudo test -f "$dest/$f"; then step "$dest/$f" "$dest/$f.old-$stamp"; fi
done
step "$dest/server.key.new" "$dest/server.key"
step "$dest/server.pem.new" "$dest/server.pem"
for f in server.pem server.key; do
  if sudo test -f "$dest/$f.old-$stamp"; then sudo mv -f "$dest/$f.old-$stamp" "$dest/$f.old"; fi
done
echo "installed; restart the server: docker compose restart server"
