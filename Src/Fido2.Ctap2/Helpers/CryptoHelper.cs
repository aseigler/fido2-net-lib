using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// The cryptography behind the PIN/UV auth protocols: ECDH key agreement and the padding they apply.
/// </summary>
public static class CryptoHelper
{
    internal static ReadOnlySpan<byte> DefaultIV => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    internal static byte[] AesCbcDefaultIvNoPadding(byte[] key, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();

        aes.Key = key;

        // AES256-CBC(sharedSecret, IV = 0, data).
        return aes.EncryptCbc(data, iv: DefaultIV, PaddingMode.None);
    }

    /// <summary>
    /// Performs ECDH on P-256 with the authenticator's key-agreement key and a fresh platform key, returning the shared point's x-coordinate and the platform's public key to send back.
    /// </summary>
    /// <param name="authenticatorKeyAgreementKey">The key from authenticatorClientPIN getKeyAgreement.</param>
    /// <param name="platformKeyAgreementKey">The platform's ephemeral public key, to send as the command's keyAgreement.</param>
    public static byte[] GenerateSharedSecret(CredentialPublicKey authenticatorKeyAgreementKey, out CredentialPublicKey platformKeyAgreementKey)
    {
        using var authenticatorKey = authenticatorKeyAgreementKey.CreateECDsa(); // public key
        using var platformKey = ECDsa.Create(); // private key

        platformKey.GenerateKey(ECCurve.NamedCurves.nistP256);

        platformKeyAgreementKey = new CredentialPublicKey(platformKey, COSE.Algorithm.ES256);

        using var pub = ECDiffieHellman.Create(authenticatorKey.ExportParameters(false));
        using var pri = ECDiffieHellman.Create(platformKey.ExportParameters(true));

        byte[] sharedSecret = pri.DeriveKeyFromHash(pub.PublicKey, HashAlgorithmName.SHA256); // Same as pri.DeriveKeyMaterial(pub.PublicKey)

        return sharedSecret;
    }

    /// <summary>
    /// Performs the ECDH key agreement shared by both PIN/UV auth protocols, generating a fresh
    /// platform key-agreement key and returning the raw shared point's x-coordinate, <c>Z</c>
    /// (§6.5.6's <c>ecdh</c> utility function, prior to either protocol's <c>kdf</c>).
    /// </summary>
    internal static byte[] DeriveRawSharedPointZ(CredentialPublicKey authenticatorKeyAgreementKey, out CredentialPublicKey platformKeyAgreementKey)
    {
        using var authenticatorKey = authenticatorKeyAgreementKey.CreateECDsa(); // public key
        using var platformKey = ECDsa.Create(); // private key

        platformKey.GenerateKey(ECCurve.NamedCurves.nistP256);

        platformKeyAgreementKey = new CredentialPublicKey(platformKey, COSE.Algorithm.ES256);

        using var pub = ECDiffieHellman.Create(authenticatorKey.ExportParameters(false));
        using var pri = ECDiffieHellman.Create(platformKey.ExportParameters(true));

        return pri.DeriveRawSecretAgreement(pub.PublicKey);
    }

    /// <summary>
    /// PIN/UV Auth Protocol One's <c>authenticate(key, message)</c> operation:
    /// <c>LEFT(HMAC-SHA-256(key, message), 16)</c>.
    /// </summary>
    public static byte[] AuthenticateProtocolOne(byte[] pinUvAuthToken, ReadOnlySpan<byte> message)
    {
        return HMACSHA256.HashData(pinUvAuthToken, message).AsSpan(0, 16).ToArray();
    }

    /// <summary>
    /// Pads <paramref name="value"/> with trailing zeros to <paramref name="length"/> bytes, as a PIN is before encryption; a value already at least that long is returned as is.
    /// </summary>
    public static byte[] ZeroPadRight(byte[] value, int length)
    {
        if (value.Length < length)
        {
            var padded = new byte[64];

            value.AsSpan().CopyTo(padded);

            return padded;
        }

        return value;
    }
}
