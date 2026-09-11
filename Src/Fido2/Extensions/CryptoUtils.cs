using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal static class CryptoUtils
{
    public static byte[] HashData(HashAlgorithmName hashName, ReadOnlySpan<byte> data)
    {
        #pragma warning disable format
        return hashName.Name switch
        {
            "SHA1"   => SHA1.HashData(data),
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new ArgumentOutOfRangeException(nameof(hashName)),
        };
        #pragma warning restore format
    }

    /// <summary>
    /// The digest a COSE signature algorithm applies to the data it signs.
    /// </summary>
    /// <exception cref="Fido2VerificationException">The algorithm is unknown, or is one that signs the message
    /// directly and so has no digest to name (EdDSA, ML-DSA).</exception>
    public static HashAlgorithmName HashAlgFromCOSEAlg(COSE.Algorithm alg)
    {
        return alg switch
        {
            COSE.Algorithm.RS1 => HashAlgorithmName.SHA1,
            COSE.Algorithm.ES256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.ES384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.ES512 => HashAlgorithmName.SHA512,
            COSE.Algorithm.PS256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.PS384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.PS512 => HashAlgorithmName.SHA512,
            COSE.Algorithm.RS256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.RS384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.RS512 => HashAlgorithmName.SHA512,
            COSE.Algorithm.ES256K => HashAlgorithmName.SHA256,
            COSE.Algorithm.ESP256 => HashAlgorithmName.SHA256,
            COSE.Algorithm.ESP384 => HashAlgorithmName.SHA384,
            COSE.Algorithm.ESP512 => HashAlgorithmName.SHA512,
            _ => throw new Fido2VerificationException(Fido2ErrorMessages.InvalidCoseAlgorithmValue),
        };
    }

    /// <summary>
    /// Determines whether an attestation certificate chains to one of the trust anchors an authenticator's metadata
    /// statement declares.
    /// </summary>
    /// <param name="trustPath">The attestation certificate followed by whatever issuing certificates the authenticator
    /// supplied (the x5c array), in order.</param>
    /// <param name="attestationRootCertificates">The metadata statement's attestationRootCertificates.</param>
    /// <param name="validationMode">Conformance mode skips revocation checking, as the conformance tool's certificates
    /// name CRL distribution points that do not exist.</param>
    /// <remarks>
    /// <para>
    /// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationrootcertificates
    /// </para>
    /// <para>
    /// "Each element of this array represents a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this
    /// authenticator model. Multiple certificates might be used for different batches of the same model. The array does
    /// not represent a certificate chain, but only the trust anchor of that chain. A trust anchor can be a root
    /// certificate, an intermediate CA certificate or even the attestation certificate itself."
    /// </para>
    /// <para>
    /// <see cref="X509Chain"/> has no notion of an intermediate CA as a trust anchor: on Linux and macOS a certificate in
    /// <see cref="X509ChainPolicy.CustomTrustStore"/> that is not self-signed is used only as an issuer, and the chain it
    /// heads is reported as partial. So the chain is built with partial chains permitted, letting the engine verify every
    /// link, and the trust decision is made here: the attestation certificate is trusted when a declared anchor appears
    /// anywhere above it in the chain the engine verified.
    /// </para>
    /// <para>
    /// Online revocation checking of the attestation certificate itself (see <paramref name="validationMode"/>) only
    /// runs on Windows and Linux. On macOS, <see cref="X509Chain"/> never attempts a CRL fetch for a certificate under
    /// a <see cref="X509ChainTrustMode.CustomRootTrust"/> anchor, so there is nothing there for
    /// <see cref="X509RevocationMode.Online"/> to check.
    /// </para>
    /// </remarks>
    public static bool ValidateTrustChain(X509Certificate2[] trustPath, X509Certificate2[] attestationRootCertificates, FidoValidationMode validationMode = FidoValidationMode.Default)
    {
        if (trustPath.Length == 0)
        {
            throw new ArgumentException("The trust path must contain the attestation certificate", nameof(trustPath));
        }

        X509Certificate2 attestationCert = trustPath[0];

        // The anchor may be the attestation certificate itself, in which case nothing else in x5c matters.
        if (IsDeclaredTrustAnchor(attestationCert, attestationRootCertificates))
        {
            return true;
        }

        using var chain = new X509Chain();

        // Trust comes from the metadata statement alone; the platform's own root store has no say. A self-signed
        // anchor becomes a genuine root this way, and an intermediate anchor is still found as an issuer.
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(attestationRootCertificates);

        // A chain that ends at an intermediate anchor, or at a root the authenticator supplied, is not an error here:
        // whether it is trusted is decided below.
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        // Windows consults the exclusive root store for trust, not for issuer lookup, so the anchors go here too.
        chain.ChainPolicy.ExtraStore.AddRange(attestationRootCertificates);

        for (int i = 1; i < trustPath.Length; i++) // skip the attestation certificate
        {
            chain.ChainPolicy.ExtraStore.Add(trustPath[i]);
        }

        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        // If the attestation certificate names a CRL distribution point, its revocation status must be obtainable
        // and clear. An issuing CA that offers no way to check its own status does not fail the chain, but one that
        // has been revoked still does.
        //
        // macOS is excluded: instrumenting X509Chain directly showed SecTrust never attempts a CRL fetch at all for
        // a certificate under a CustomRootTrust anchor -- zero requests reached a local CRL server across every
        // combination of RevocationMode and X509VerificationFlags tried, including this one. Turning on Online
        // there would not check anything; it would only make an unreachable-but-otherwise-valid certificate fail.
        if (validationMode != FidoValidationMode.FidoConformance2024 && !OperatingSystem.IsMacOS() && TryGetCrlDistributionPointUrl(attestationCert, out _))
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
        }

        if (!chain.Build(attestationCert))
        {
            return false;
        }

        // Every link in the chain now verifies. The attestation certificate is trusted if a declared anchor sits
        // anywhere above it; anything above the anchor is immaterial.
        for (int i = 1; i < chain.ChainElements.Count; i++) // skip the attestation certificate
        {
            if (IsDeclaredTrustAnchor(chain.ChainElements[i].Certificate, attestationRootCertificates))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsDeclaredTrustAnchor(X509Certificate2 certificate, X509Certificate2[] attestationRootCertificates)
    {
        foreach (X509Certificate2 attestationRootCertificate in attestationRootCertificates)
        {
            // MDS3: "a binary comparison is sufficient to determine if the attestation trust anchor is the attestation
            // certificate itself".
            if (attestationRootCertificate.RawDataMemory.Span.SequenceEqual(certificate.RawDataMemory.Span))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Finds the first HTTP(S) URL among the certificate's CRL distribution points.
    /// </summary>
    /// <remarks>
    /// .NET has no typed view of the CRL Distribution Points extension (RFC 5280 §4.2.1.13), so it is decoded here.
    /// Distribution points that name the CRL relative to its issuer, or by a non-HTTP location such as LDAP, are
    /// passed over.
    /// </remarks>
    public static bool TryGetCrlDistributionPointUrl(X509Certificate2 certificate, [NotNullWhen(true)] out string? url)
    {
        url = null;

        if (certificate.Extensions["2.5.29.31"] is not { } extension) // id-ce-cRLDistributionPoints
        {
            return false;
        }

        var distributionPointTag = new Asn1Tag(TagClass.ContextSpecific, 0);  // DistributionPoint.distributionPoint
        var fullNameTag = new Asn1Tag(TagClass.ContextSpecific, 0);           // DistributionPointName.fullName
        var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);                // GeneralName.uniformResourceIdentifier

        try
        {
            // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
            var distributionPoints = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();

            while (distributionPoints.HasData)
            {
                // DistributionPoint ::= SEQUENCE {
                //     distributionPoint       [0]     DistributionPointName OPTIONAL,
                //     reasons                 [1]     ReasonFlags OPTIONAL,
                //     cRLIssuer               [2]     GeneralNames OPTIONAL }
                var distributionPoint = distributionPoints.ReadSequence();

                if (!distributionPoint.HasData || !distributionPoint.PeekTag().HasSameClassAndValue(distributionPointTag))
                {
                    continue;
                }

                // DistributionPointName ::= CHOICE {
                //     fullName                [0]     GeneralNames,
                //     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
                //
                // The [0] around the CHOICE is explicit, so the name is nested one level down.
                var distributionPointName = distributionPoint.ReadSequence(distributionPointTag);

                if (!distributionPointName.PeekTag().HasSameClassAndValue(fullNameTag))
                {
                    continue;
                }

                // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
                var generalNames = distributionPointName.ReadSequence(fullNameTag);

                while (generalNames.HasData)
                {
                    if (!generalNames.PeekTag().HasSameClassAndValue(uriTag))
                    {
                        generalNames.ReadEncodedValue();
                        continue;
                    }

                    string candidate = generalNames.ReadCharacterString(UniversalTagNumber.IA5String, uriTag);

                    if (Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) && uri.Scheme is "http" or "https")
                    {
                        url = candidate;
                        return true;
                    }
                }
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension names no usable distribution point.
        }

        return false;
    }

    /// <summary>
    /// Determines whether <paramref name="cert"/> is revoked according to <paramref name="crl"/>, a DER-encoded CRL
    /// obtained from the certificate's CRL distribution point.
    /// </summary>
    /// <param name="crl">The DER-encoded CertificateList.</param>
    /// <param name="cert">The certificate whose status is in question.</param>
    /// <param name="issuer">The certificate of the CA that issued <paramref name="cert"/>, which must also have
    /// issued and signed the CRL.</param>
    /// <param name="verificationTime">When given, the CRL must not have passed its nextUpdate time. A stale CRL is one
    /// an attacker on the path to the distribution point could replay to hide a later revocation.</param>
    /// <exception cref="CryptographicException">The CRL is malformed, was not issued by <paramref name="issuer"/>,
    /// or is stale.</exception>
    public static bool IsCertInCRL(ReadOnlyMemory<byte> crl, X509Certificate2 cert, X509Certificate2 issuer, DateTimeOffset? verificationTime = null)
    {
        var revocationList = CertificateRevocationList.Decode(crl);

        // RFC 5280 §6.3.3 (b): the CRL must have been issued by the certificate's issuer...
        if (!revocationList.Issuer.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData))
        {
            throw new CryptographicException($"The CRL was issued by '{revocationList.Issuer.Name}', not by the certificate's issuer '{cert.IssuerName.Name}'");
        }

        if (!issuer.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData))
        {
            throw new CryptographicException($"The certificate was issued by '{cert.IssuerName.Name}', not by '{issuer.SubjectName.Name}'");
        }

        // ...and (f) its signature must verify under that issuer's key.
        if (!revocationList.VerifySignature(issuer))
        {
            throw new CryptographicException($"The CRL signature does not verify with the public key of '{issuer.SubjectName.Name}'");
        }

        if (verificationTime is { } time && revocationList.NextUpdate is { } nextUpdate && nextUpdate < time)
        {
            throw new CryptographicException($"The CRL issued by '{revocationList.Issuer.Name}' is stale: its next update was due {nextUpdate:u}");
        }

        return revocationList.IsRevoked(cert);
    }
}
