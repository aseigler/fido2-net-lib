# Support and maintenance policy

fido2-net-lib is community-maintained, free, open source software. There is no paid support tier and no
contractual SLA — this document exists so that's an informed choice rather than an unknown. It describes
what maintenance actually looks like here, so you can decide whether that fits your project's needs.

For security vulnerabilities specifically, see [SECURITY.md](SECURITY.md) instead of this document — it has
its own disclosure process and response-time commitments.

## Supported .NET versions

The library currently targets **.NET 8.0** and **.NET 10.0** (see `SupportedTargetFrameworks` in
[`Directory.Build.props`](Directory.Build.props)), tracking .NET's own [.NET support
policy](https://dotnet.microsoft.com/platform/support/policy/dotnet-core): .NET 8 is a Long Term Support
(LTS) release, .NET 10 is the current release. When a target framework reaches its own end of support from
Microsoft, expect it to be dropped from a subsequent major version of this library rather than carried
indefinitely — this has been the pattern historically (each major version bump has taken the opportunity to
adjust the supported framework set).

## Release cadence

Releases are tagged on GitHub and published to NuGet automatically by CI (`.github/workflows/main.yml`'s
`release` trigger and `deploy-nuget` job) once a GitHub Release is published — there's no separate manual
publish step to fall behind on.

Looking at the actual tag history rather than promising a specific cadence: stable releases have landed
roughly every few months (for example, `4.0.0` in August 2025, `4.0.1` in April 2026, `4.1.0` in September
2026), with `preview`/`beta` tags shipped more frequently in between for people who want early access to
in-progress work. Versioning follows [semver](https://semver.org/)-style numbering (`MAJOR.MINOR.PATCH`,
with `-preview.N`/`-beta.N` suffixes for pre-releases), so a patch/minor bump should not carry breaking
changes.

This is a description of the observed pattern, not a guaranteed schedule — there's no commitment to release
on any fixed timeline.

## Getting help

- **Questions and usage help**: open a [GitHub issue](https://github.com/passwordless-lib/fido2-net-lib/issues)
  on the repository. There is no separate Discord/Slack/Discussions channel currently in active use for this
  project.
- **Security vulnerabilities**: do not open a public issue — follow the process in
  [SECURITY.md](SECURITY.md) instead.
- **Commercial/hosted alternative**: if you want a managed service with its own support relationship rather
  than self-hosting this library, [Bitwarden Passwordless.dev](https://passwordless.dev) (referenced in the
  main [README](README.md)) is built by contributors to this project and offers that as a separate product.

## What "community-supported" means in practice

There's no paid SLA, but that doesn't mean no signal about how the project is maintained:

- Issues and pull requests are triaged by maintainers as volunteer time allows, not on a contracted schedule.
- The project has kept up with new .NET releases (.NET 10 support, post-quantum ML-DSA support) and with
  changes to the WebAuthn/FIDO2 specifications themselves, which is the maintenance signal that actually
  matters for a security-relevant library like this one — an unmaintained fork would fall behind the spec.
- Version numbers follow semver, so you can tell from the version alone whether an upgrade is expected to be
  safe (patch/minor) or requires reading release notes for breaking changes (major).
- This document itself, and [SECURITY.md](SECURITY.md), are meant to make that maintenance posture explicit
  rather than something you have to infer from commit history.
