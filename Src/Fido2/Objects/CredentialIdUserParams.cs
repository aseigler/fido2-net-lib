namespace Fido2NetLib.Objects;

/// <summary>
/// Parameters used for callback function to check that the CredentialId is unique user
/// </summary>
public sealed class IsCredentialIdUniqueToUserParams(byte[] credentialId, Fido2User user)
{
    /// <summary>
    /// The ID of the credential being registered.
    /// </summary>
    public byte[] CredentialId { get; } = credentialId;

    /// <summary>
    /// The user the credential is being registered to.
    /// </summary>
    public Fido2User User { get; } = user;
}
