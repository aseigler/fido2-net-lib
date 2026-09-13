namespace Fido2NetLib.Objects;

/// <summary>
/// Parameters used for callback function
/// </summary>
public sealed class IsUserHandleOwnerOfCredentialIdParams(byte[] credentialId, byte[] userHandle)
{
    /// <summary>
    /// The user handle the authenticator returned with the assertion.
    /// </summary>
    public byte[] UserHandle { get; } = userHandle;

    /// <summary>
    /// The ID of the credential that produced the assertion.
    /// </summary>
    public byte[] CredentialId { get; } = credentialId;
}
