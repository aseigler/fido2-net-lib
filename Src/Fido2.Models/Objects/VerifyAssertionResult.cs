#nullable disable

namespace Fido2NetLib.Objects;

/// <summary>
/// Result of the MakeAssertion verification
/// </summary>
public class VerifyAssertionResult
{
    public byte[] CredentialId { get; init; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; init; }

    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool IsBackedUp { get; init; }

    /// <summary>
    /// For a Secure Payment Confirmation assertion, the browser-bound key's public key as a COSE_Key, when the browser
    /// supplied one and its signature over the client data verified; otherwise <see langword="null"/>. Compare it with
    /// the one seen at registration, or on earlier transactions, for evidence that the same browser installation is
    /// confirming.
    /// </summary>
#nullable enable
    public byte[]? BrowserBoundPublicKey { get; init; }
#nullable restore
}
