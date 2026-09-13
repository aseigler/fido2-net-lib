using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// The outcome of key agreement with the authenticator: both public keys and the shared secret they yield.
/// </summary>
public sealed class NegotiateSharedSecretResult
{
    /// <summary>
    /// Initializes the result.
    /// </summary>
    /// <param name="authenticatorKey">The authenticator's key-agreement public key.</param>
    /// <param name="platformKey">The platform's ephemeral public key.</param>
    /// <param name="sharedShared">The shared secret, as the PIN/UV auth protocol derives it.</param>
    public NegotiateSharedSecretResult(
        CredentialPublicKey authenticatorKey,
        CredentialPublicKey platformKey,
        byte[] sharedShared)
    {
        ArgumentNullException.ThrowIfNull(authenticatorKey);
        ArgumentNullException.ThrowIfNull(platformKey);
        ArgumentNullException.ThrowIfNull(sharedShared);

        AuthenticatorKey = authenticatorKey;
        PlatformKey = platformKey;
        SharedSecret = sharedShared;
    }

    // Fido2 Public Key
    /// <summary>
    /// The authenticator's key-agreement public key.
    /// </summary>
    public CredentialPublicKey AuthenticatorKey { get; }

    // Client Public Key
    /// <summary>
    /// The platform's ephemeral public key, sent to the authenticator as the command's keyAgreement.
    /// </summary>
    public CredentialPublicKey PlatformKey { get; }

    /// <summary>
    /// The shared secret the PIN/UV auth protocol's encryption and authentication keys derive from.
    /// </summary>
    public byte[] SharedSecret { get; }
}
