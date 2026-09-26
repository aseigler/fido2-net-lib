# What happened to devicePublicKey

Passkeys solved a real problem — password reuse, phishing, the whole mess — by making credentials
syncable across a user's devices. They also quietly gave something up to get there: the ability for a
Relying Party to know it's talking to *this specific device*, rather than *some device holding a copy of
this key*. WebAuthn had an answer to that lined up. It didn't ship. This is the story of implementing it,
watching it die, and pulling it back out of this library.

## What device binding used to mean

Before passkeys were commonly backup-eligible, a FIDO2 credential was, in practice, bound to one
authenticator. If you registered a security key or a platform authenticator, the private key never left
that device. An assertion from that credential was a reasonably strong signal that the physical device was
present.

Backup-eligible credentials break that assumption on purpose. The whole point of a synced passkey is that
the private key material is available from any of the user's devices via their platform's passkey provider
(iCloud Keychain, Google Password Manager, etc.). That's the right tradeoff for most consumer sign-in flows.
It's a real regression for anyone who actually needed device-level assurance — a corporate device management
policy, a regulated workflow that wants to know a specific issued laptop was used, fraud detection that
treats "new device" as a signal worth acting on.

WebAuthn's `BE`/`BS` flags (backup eligibility and backup state) tell a Relying Party *whether* a credential
could be synced and whether it currently is. They don't tell you *which* device presented it. That gap had a
name, an implementation, and a proposed fix — `devicePublicKey`.

## The original design, and its gap

[`devicePubKey`](https://github.com/w3c/webauthn/pull/1663) let an authenticator return a second, device-bound
public key alongside the primary (possibly synced) one, on both registration and assertion. A Relying Party
could then track that device-bound key separately from the primary credential — "this login used the same
physical device as last time" became verifiable again, even for a synced passkey.

It had a real gap, though: it only modeled the single-device case. It had no good answer for what happens
when a user shows up on a *new* device via passkey-provider sync — a device that's never presented a
device-bound key before. The extension's own editor, Adam Langley, put the problem plainly during the
redesign that followed:

> A passkey provider likely has useful information about how the user authenticated themselves on that new
> device but we don't want to tie that to the primary key.

There was no way for the passkey provider itself to vouch for a new device's authentication assurance
without collapsing that signal into the primary key and breaking interoperability between providers.

## The redesign built for exactly this use case

[PR #1957](https://github.com/w3c/webauthn/pull/1957) replaced `devicePubKey` with `supplementalPubKeys`, and
it was a genuinely better design, not just a rename. Instead of one device-bound key, an authenticator could
return one or two supplemental keys, each independently scoped as either **device-bound** or
**provider-scoped** — the latter letting a passkey provider attest to its own authentication-assurance level
for that sync event, distinct from the primary key's own guarantees.

This wasn't a vague nod toward enterprise needs. The design was explicit about who it was for:

> This architecture maintains primary key interoperability while allowing providers to communicate
> security-relevant attestations through supplemental signals, addressing compliance and fraud-prevention use
> cases without forcing unnecessary re-authentication of users.

`supplementalPubKeys` was, on paper, the answer to the exact problem this document opened with: regulated and
enterprise use cases that need more than "this credential could theoretically be synced."

I implemented it, in this library, as `devicePubKey`/`supplementalPubKeys` support landed in the draft spec.

## Why it actually died

Here's the part worth getting precisely right, because it's not the story you'd guess: `supplementalPubKeys`
was not rejected on technical or design grounds. [PR #2109](https://github.com/w3c/webauthn/pull/2109),
merged August 7, 2024, dropped it from the spec entirely, and the stated reason was pure process:

> This extension will not have two interoperable implementations within the Level 3 timeframe.

W3C Recommendation status requires demonstrating two independent, interoperable implementations within a
spec level's timeframe. Nobody built competing ones in time. Not "the industry decided enterprises didn't
need this" — nobody shipped it, on either side, before the deadline.

The same day, [PR #2116](https://github.com/w3c/webauthn/pull/2116) tried to revert the removal, anticipating
the feature would land in some form regardless. It was closed, unmerged, with a reviewer noting the eventual
replacement would "probably have a meaningfully different form" — an explicit punt to a future redesign, not
a restoration of what existed. [fido2-net-lib's own issue tracking this](https://github.com/passwordless-lib/fido2-net-lib/issues/566)
followed the spec: once `supplementalPubKeys` was gone from WebAuthn Level 3, the implementation came back
out of this library too.

I checked directly against the finalized WebAuthn Level 3 Recommendation (published as a full W3C
Recommendation on August 25, 2026): neither `devicePubKey` nor `supplementalPubKeys` appears anywhere in it.
This isn't a case of "renamed again and I missed it" — it is genuinely, currently absent from the standard.
Deferred, not delivered. Possibly revisited in a future Level 4; nothing scheduled.

## What this leaves open

If you're deploying passkeys in a context that actually cares about device assurance — regulated industries,
enterprise fleets, anywhere "which device did this" matters — there is currently no standardized WebAuthn
mechanism to get that signal for a backup-eligible credential. That's not a library limitation. It's a gap in
the spec itself, and it isn't closing soon.

That doesn't mean the underlying need goes away. It means the answer has to come from outside the extension
that was supposed to provide it:

- **Attestation at registration time.** Backup-eligible or not, attestation still tells you what kind of
  authenticator created a credential and, depending on the format, ties it to a specific model or even
  instance. This is exactly the piece a lot of consumer-focused WebAuthn tooling skips, because most consumer
  sign-in flows have no use for it. An enterprise deployment that cares about device assurance can't skip it.
- **Non-discoverable, single-device credentials as a deliberate policy**, where the threat model actually
  calls for it — a blunter tool than `supplementalPubKeys` would have been, but a real one: don't offer a
  syncable credential type at all for the tier of access that needs device-level assurance.
- **Device identity from outside WebAuthn entirely.** A domain-joined machine authenticating a service
  account via Kerberos already carries a device-binding guarantee that has nothing to do with what the
  browser or platform chooses to tell a Relying Party — it comes from the directory infrastructure, not the
  ceremony. An on-prem Active Directory-backed credential store is a fundamentally different device-binding
  story than a bare web-based synced-passkey flow, for exactly this reason.

None of these is the extension that was supposed to exist. All three are usable today, and none of them
requires a spec change nobody has scheduled.
