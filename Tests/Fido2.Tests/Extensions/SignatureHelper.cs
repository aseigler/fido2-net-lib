using System.Security.Cryptography;

namespace fido2_net_lib;

internal static class SignatureHelper
{
    /// <summary>
    /// Signs <paramref name="data"/> in the DER Ecdsa-Sig-Value form WebAuthn §6.5.6 requires of ECDSA signatures.
    /// </summary>
    public static byte[] SignEcDsa(ECDsa ecdsa, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        return ecdsa.SignData(data, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
    }
}
