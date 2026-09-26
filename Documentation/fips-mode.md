# FIPS mode

This page describes what it takes to run this library in a configuration where every cryptographic
operation is backed by a FIPS 140-validated module, and where it falls short of that today.

## The short version

1. Build the library from source with `-p:DisableNSec=true`. See
   [building-without-nsec.md](building-without-nsec.md) for exactly what that switch does; the summary
   relevant here is that it removes the one crypto path in this library that never touches the host
   operating system's validated module.
2. Run on a host operating system that is itself in FIPS mode (Windows: FIPS mode enabled in local/group
   policy; Linux: a distribution and OpenSSL build with a FIPS provider enabled).
3. Offer only `PubKeyCredParam.FipsApproved` in `pubKeyCredParams` when creating a credential, instead of
   `PubKeyCredParam.Defaults`.
4. Be aware of the two caveats below (legacy attestation/CRL interop, and post-quantum algorithms) before
   claiming full compliance.

None of this requires code changes if you consume the library as a source dependency; (1) is the only step
that is not available to a consumer of the published NuGet package -- see "Current limitation" below.

## Why this is necessary: what does and does not delegate to the OS

Most of this library's signature verification goes through `System.Security.Cryptography.ECDsa` and
`System.Security.Cryptography.RSA`. On Windows these delegate to CNG; on Linux, to OpenSSL. Both become
FIPS-validated the moment the host OS itself is running in FIPS mode -- no code in this library needs to
change for that to happen, because the library never implements the cryptography itself, it just calls
into the platform.

EdDSA (Ed25519) is the one exception. It is verified through `NSec.Cryptography`, which wraps `libsodium` --
a bundled, self-contained implementation that never calls into CNG or OpenSSL at all. Turning on FIPS mode
at the OS level has no effect on it whatsoever: a relying party could be fully convinced it is running in a
FIPS-compliant configuration while this one algorithm silently runs outside it. `DisableNSec=true` removes
this path entirely (an EdDSA credential is refused with `Fido2VerificationException`/`UnimplementedAlgorithm`
at parse time, the same way an unsupported algorithm like Ed448 already is), so it is the only way to
actually close this gap, not just reduce its likelihood.

`PubKeyCredParam.FipsApproved` (excludes EdDSA, RS1, and ES256K -- see its own XML doc comment for exactly
why each is excluded) is worth setting regardless of whether you can build with `DisableNSec=true`, but by
itself it is not a complete guarantee: it only controls which algorithm a *well-behaved* authenticator is
offered. A non-conformant authenticator could still return an EdDSA credential you never asked for, and
constructing that credential's public key runs through NSec while the response is being parsed, before this
library's own algorithm-match check (`pubKeyCredParams`) has a chance to reject it. Only `DisableNSec=true`
closes that path unconditionally, by removing the NSec code entirely rather than trying to out-run it with a
policy check.

RS1 (SHA-1) and ES256K (secp256k1) are also not FIPS-approved -- SHA-1 is deprecated for signatures, and
secp256k1 is not a NIST curve -- but both are verified through the OS-delegated `RSA`/`ECDsa` APIs, so a
host operating system genuinely enforcing FIPS mode should refuse them on its own. `FipsApproved` excludes
both anyway, as defense in depth: it costs nothing and removes any dependence on that OS-level enforcement
actually being correct.

## Current limitation: this is a source-build switch

`DisableNSec=true` only works if you build the library yourself. The published NuGet package is built
normally and references NSec like any other build; there is no runtime flag or configuration setting that
removes it from an assembly that has already been compiled with it in. If your FIPS-mode deployment cannot
build from source, you cannot fully close the EdDSA gap today -- `FipsApproved` still helps for
well-behaved authenticators, but the parse-time exposure described above remains. This is a known,
deliberate limitation, not an oversight: closing it without a source build would mean moving Ed25519 behind
a provider interface and shipping it as a separate optional package, which is a public API change that has
not been made. If this matters to you, say so -- it is the kind of thing that would justify making that
change.

## Caveat: legacy attestation and CRL verification can still involve SHA-1

None of the above touches two places where this library *verifies* a signature that was produced with
SHA-1, rather than choosing SHA-1 itself:

- **TPM attestation** (`Src/Fido2/AttestationFormat/Tpm.cs`) recognizes `TPM_ALG_SHA1`, because some real
  TPM 1.2/early TPM 2.0 hardware only supports a SHA-1 PCR bank.
- **Certificate revocation list verification** (`Src/Fido2/Extensions/CertificateRevocationList.cs`)
  recognizes CRLs signed with `EcdsaWithSha1`/`Sha1WithRsaEncryption`, because some real CAs in attestation
  trust chains have issued (and still issue) CRLs signed that way.

This is unavoidable interop with what real-world hardware and certificate authorities actually produced --
not a primitive this library chose for its own purposes -- but under a strict reading of FIPS-mode policy,
verifying a SHA-1 signature is itself a use of a non-approved algorithm, regardless of who produced it. A
deployment that needs a hard guarantee here should reject attestation statements and CRLs that require
SHA-1 rather than merely accepting them; that is a relying-party policy decision this library does not make
for you, since rejecting them means refusing genuinely legitimate legacy authenticators and CA chains.

(Separately, `Src/Fido2.Models/Metadata/MetadataBLOBPayloadEntry.cs` uses SHA-1 to compute a certificate
thumbprint used purely as a lookup key for matching FIDO Metadata Service entries. This is not a security
control -- it is not verifying anything or protecting against forgery -- so it does not carry the same
concern as the two cases above, but it is still SHA-1 in the codebase and worth knowing about if an auditor
greps for it without that context.)

## Forward-looking: post-quantum algorithms

.NET 10 adds `System.Security.Cryptography.MLDsa` (ML-DSA, FIPS 204), used by the Demo project. Its concrete
implementations -- `MLDsaCng` on Windows, `MLDsaOpenSsl` on Linux -- delegate to the OS the same way
`ECDsa`/`RSA` do, unlike NSec/EdDSA, so architecturally it will inherit FIPS validation automatically once
the underlying OS module is certified for it. As of this writing, though, `MLDsa` is marked `[Experimental]`
(`SYSLIB5006`) in .NET 10, and OS-level support is narrow (Windows 11 Insider builds; OpenSSL 3.5+ on
Linux) -- module certification lags feature releases, and there is no indication yet of a NIST CMVP
certificate covering this specific algorithm on either platform. Treat ML-DSA as forward-looking. Do not
include it in `pubKeyCredParams` for a deployment that needs to make a current FIPS-compliance claim.
