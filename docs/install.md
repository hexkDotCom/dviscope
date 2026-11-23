# Installing DVIScope

DVIScope has two parts: the **server** (`dviscope-server`, with PostgreSQL and the web UI)
and the **collector** (`dviscope`, on each machine that runs simulations and in CI). One
release archive per platform holds both binaries, the web UI, the deployment files, these
docs and a `SHA256SUMS` of every file:

| Archive | Platforms |
|---|---|
| `dviscope-<version>-x86_64-unknown-linux-musl.tar.gz` | Linux x86-64 (static binaries, any distribution) |
| `dviscope-<version>-x86_64-pc-windows-msvc.tar.gz` | Windows 10/11 x86-64 (static C runtime) |

The binaries, web UI and docs in the archive work offline: nothing is downloaded at run time.
The compose recipe also needs the PostgreSQL image; on a machine without internet access,
load it first (below).

## Verify the download

```sh
sha256sum -c dviscope-<version>-x86_64-unknown-linux-musl.tar.gz.sha256
gh attestation verify dviscope-<version>-x86_64-unknown-linux-musl.tar.gz \
  --repo hexkDotCom/dviscope \
  --signer-workflow hexkDotCom/dviscope/.github/workflows/release.yml
tar -xzf dviscope-<version>-x86_64-unknown-linux-musl.tar.gz
cd dviscope-<version>-x86_64-unknown-linux-musl && sha256sum -c SHA256SUMS
```

On Windows, `Get-FileHash -Algorithm SHA256` gives the same digests, and `tar -xzf` is
built in. The attestation proves the archive was built by the release workflow from a
tagged commit on `main`.

## Server: the compose recipe (recommended)

Needs Docker with Compose on Linux (or WSL 2), on the Linux file system (not `/mnt/c`).
In the release archive, `deploy/Dockerfile` builds the images from the archive's own
binaries and UI (no compiler, no Node, no download). Its one external prerequisite is the
PostgreSQL image `postgres:17-bookworm` (the database, and the base of the `ops` image that runs
backups): on a machine without internet access, `docker save postgres:17-bookworm` on a connected
one and `docker load` it here. (In the source tree, `deploy/Dockerfile` builds from
source instead.)

```sh
cd deploy
./provision-db.sh                                   # database password and URL, once
dviscope tls init --server-dir ~/.local/state/dviscope/server-staging
./provision-tls.sh ~/.local/state/dviscope/server-staging
docker compose up -d                                # migrate, then server and retention
curl --cacert ~/.local/state/dviscope/ca/dviscope-ca.pem https://127.0.0.1:8443/readyz
```

`dviscope tls init` runs on the Linux host (on Windows it refuses: owner-only ACLs for key
files are not implemented there); copy only the public CA certificate
(`ca/dviscope-ca.pem`) to the collectors. `migrate` applies the schema and exits; `server` serves HTTPS on `127.0.0.1:8443` (with the
web UI); `retention` applies the retention policy daily; `ops` (profile `ops`, run on
demand) does backups and restores ([operate.md](operate.md#backup-and-restore)) and runs the
administration commands. Then create the first users, project, producer and token, and load
the demo, with the compose commands in [first-afternoon.md](first-afternoon.md).

Edit `deploy/server.toml` for the public origin (`public_origin`, the URL users type) and
publish the port on another interface only behind your own firewall rules.

## Server: binaries without containers

```sh
sudo install -m 0755 bin/dviscope-server /usr/local/bin/
sudo install -d -m 0755 /opt/dviscope && sudo cp -r ui /opt/dviscope/ui
```

Write `dviscope-server.toml` as in [operate.md](operate.md#configuration) (`ui_dir =
"/opt/dviscope/ui"`), give the database URL in a private file (`url_file`), run
`dviscope-server migrate` once and then `dviscope-server` (for example as a systemd service
with a dedicated user). Schedule `dviscope-server retention` daily, or run
`dviscope-server retention --every 24` as a second service. PostgreSQL 16 or 17.

## Collector

Linux: copy `bin/dviscope` to a directory on `PATH`. Windows: copy `bin\dviscope.exe` to a
directory on `PATH` (no installer, no runtime needed). Its private state lives in
`~/.local/state/dviscope` (Linux; `$XDG_STATE_HOME` when set) or
`%LOCALAPPDATA%\dviscope` (Windows), on a local disk. Configure it once:

```toml
# <state>/dviscope.toml
server_url = "https://dviscope.example.internal:8443"
ca_file = "/path/to/dviscope-ca.pem"   # the server's CA (from `dviscope tls init`)
token_file = "/path/to/collector.token"
```

The token file is written owner-only and never printed. `DVISCOPE_SERVER_URL`,
`DVISCOPE_CA_FILE`, `DVISCOPE_TOKEN_FILE` and `DVISCOPE_STATE_DIR` override the file, and
flags override both. Check the setup with:

```sh
dviscope doctor --server --pilot
```

## Upgrading

Back up first (`dviscope-server backup`), then replace the binaries (or rebuild the image)
and run `dviscope-server migrate`; see [operate.md](operate.md#migrations). Upgrade the
collectors with the server; `dviscope doctor --server` shows the server's version and
capabilities.
