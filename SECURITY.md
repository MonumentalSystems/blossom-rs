# Security Policy

## Supported versions

The latest released version and the default branch are eligible for security
fixes. Older releases are not supported.

Fixes land on the default branch and are included in the next release. The
default branch can therefore contain security fixes that have not yet reached
crates.io. If you are unsure whether a release contains a particular fix,
contact the maintainers before relying on it in a security-sensitive deployment.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use one of these private channels:

1. Submit a private report through
   [GitHub Security Advisories](https://github.com/MonumentalSystems/blossom-rs/security/advisories/new).
2. Email [richardj@safier.com](mailto:richardj@safier.com) with the subject
   `[blossom-rs security]`. Encrypt sensitive reports with the public key below.

Please include, when possible:

- the affected crate, version, commit, and configuration;
- a description of the issue and its likely impact;
- minimal reproduction steps or a proof of concept;
- any known mitigations; and
- your preferred name and disclosure credit, or whether you prefer anonymity.

We aim to acknowledge reports within seven days. We will investigate, provide
status updates at least every 30 days while the report remains open, and
coordinate disclosure with you. Please allow time for a fix and release before
publishing details that could put users at risk.

## OpenPGP public key

The reporting key belongs to `Richard Safier (General 2026 Key)
<richardj@safier.com>`.

Fingerprint: `6D3D 7CF2 31CA E25B 4543 1FA6 EB6B 2A1C AA58 30D9`

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=8JKV
-----END PGP PUBLIC KEY BLOCK-----
```
