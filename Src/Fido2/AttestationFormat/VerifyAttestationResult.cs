using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// What an attestation statement established: the kind of attestation and the certificates that back it.
/// </summary>
public sealed class VerifyAttestationResult
{
    /// <summary>
    /// Initializes the result.
    /// </summary>
    public VerifyAttestationResult(AttestationType type, X509Certificate2[] certificates)
    {
        Type = type;
        Certificates = certificates;
    }

    /// <summary>
    /// The attestation type the statement established.
    /// </summary>
    public AttestationType Type { get; }

    /// <summary>
    /// The attestation certificate followed by the rest of the chain the authenticator supplied, or an empty array when the statement carries none.
    /// </summary>
    public X509Certificate2[] Certificates { get; }

    /// <summary>
    /// Splits the result into its type and certificates.
    /// </summary>
    public void Deconstruct(out AttestationType type, out X509Certificate2[] certificates)
    {
        (type, certificates) = (Type, Certificates);
    }
}
