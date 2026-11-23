# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability
reporting: *Security* tab → *Report a vulnerability*. Do not open a public issue.

Include the version, what an attacker can do, and the steps to reproduce. Do not include
simulator logs, design data or other confidential material; describe the format instead.

We aim to acknowledge reports within 7 days and to publish a fix or mitigation as soon as
practical, crediting the reporter unless they prefer otherwise.

## Supported versions

Until 0.1.0 is released, only the latest pre-release receives fixes.

## Scope and threat model

DVIScope is a self-hosted engineering tool for a company network. It aims at sensible
protection against accidents, malicious changes to results and code, and common web and API
attacks; it is not designed to protect against a malicious host or database administrator.
The baseline (HTTPS only, hashed tokens, input limits, CSRF and security headers, scoped
collector tokens, quarantine of leaked credentials, safe restore) is described in the
project documentation.

## Verifying releases

Releases carry SHA-256 checksums, an SBOM and a build-provenance attestation. Verify a
download before installing it:

```bash
gh attestation verify <file> --repo hexkDotCom/dviscope \
  --signer-workflow hexkDotCom/dviscope/.github/workflows/release.yml
```
