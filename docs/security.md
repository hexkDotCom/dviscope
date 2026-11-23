# Security operations

What the server and collectors defend against, and what an operator does when a credential
leaks. Reporting vulnerabilities: [SECURITY.md](../SECURITY.md).

## Baseline

- **Transport**: HTTPS only (a local CA from `dviscope tls init`); the server publishes its
  port on `127.0.0.1` in the compose recipe; PostgreSQL is never published.
- **Credentials**: tokens are stored hashed (SHA-256 of a random secret, printed once);
  collector tokens belong to one project and one producer and carry scopes; personal tokens
  and browser sessions carry the user's current role. Passwords are Argon2id. Token files,
  backups and journals are private files (owner-only).
- **Producer namespaces**: a record names its producer, and it must be the token's: one
  producer's token can neither create nor correct another producer's records, and its
  reconciliation sees only its own receipts.
- **Request bounds**: a declared `Content-Length` is required and reserved against the
  in-flight budget before a byte is read; at most 8 MiB encoded, 32 MiB decoded, a gzip
  ratio of 20, 1,000 records per batch, a bounded JSON depth. Only `gzip` (or no encoding)
  is accepted: any other or stacked `Content-Encoding` is refused.
- **Rendering**: nothing a producer or a user writes is interpreted. The web UI renders text
  as text (no HTML, no Markdown), with a strict Content Security Policy; the verdict's
  Markdown summary escapes every value; text meant to be copied (the collection repair
  list, the signature summary) has its values made plain: control characters (line
  breaks, terminal escape sequences) and Unicode direction controls become U+FFFD, so a
  hostile test name cannot add a line to a pasted list or recolor a terminal. CLI output is
  JSON (control characters escaped) and its error messages drop control characters.
- **No log text leaves the collector unasked**: summaries, receipts and commit statuses
  carry IDs and counts only.
- **Restore is safe**: the restored data and its safe state commit in one transaction:
  maintenance on, every session deleted, every token disabled until re-enabled (see
  [operate.md](operate.md)). Maintenance is a fence for every write, including retention
  and the admin commands other than credential recovery.
- **Backups are owner-only** files, refused where file modes do not protect them (Windows,
  and Windows drives seen from WSL), never part of an image build context, like every
  provisioned secret. Every credential change (issue, revoke, quarantine, release,
  re-enable) commits with its audit record.

## Rehearsal: a leaked collector token

Run this once on a test project before you need it; the acceptance test
`token_leak_rehearsal` performs exactly these steps.

1. **Identify the token**: the admin page lists collector tokens by ID, producer and label
   (never secrets); the audit log records who issued it.
2. **Quarantine it**, from the earliest time the leak could have started:

   ```sh
   dviscope-server admin quarantine-token --id 7 --since 2026-11-01T00:00:00Z
   ```

   The token is revoked at once, and every report revision it delivered since then becomes
   a settlement barrier: the slot is never a pass on that evidence (it settles
   `failed/insufficient` until a valid result arrives), whatever the revision claimed.
3. **Replace it**: issue a new token for the same producer, write it to the collector's
   `token_file` (owner-only), and restart the collector.

   ```sh
   dviscope-server admin issue-token --project rtl --producer nightly-runner --label replacement \
  --out ./collector.token
   ```

4. **Recover the results**: re-run the quarantined slots (`dviscope verdict` and the
   regression's repair list name them); their new attempts settle normally. Only after a
   review shows the quarantined revisions were genuine, `admin release-token --id 7` makes
   them count again (the token stays revoked).
5. **Check delivery**: `dviscope journal reconcile --dir <journal>` on each collector host
   confirms that the server holds what the collectors sent.
6. **Record it**: quarantine and release are in the audit log with their times.
