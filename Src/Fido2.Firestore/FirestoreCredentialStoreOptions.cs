namespace Fido2NetLib.Firestore;

/// <summary>
/// Collection names used by <see cref="FirestoreCredentialStore"/>.
/// </summary>
public class FirestoreCredentialStoreOptions
{
    /// <summary>
    /// The collection a username is claimed in, one document per username, keyed by the username itself.
    /// Defaults to <c>fido2Usernames</c>.
    /// </summary>
    public string UsernamesCollectionName { get; set; } = "fido2Usernames";

    /// <summary>
    /// The collection <see cref="Fido2User"/> accounts are stored in, keyed by the base64url-encoded user ID.
    /// Defaults to <c>fido2Users</c>.
    /// </summary>
    public string UsersCollectionName { get; set; } = "fido2Users";

    /// <summary>
    /// The collection <see cref="StoredCredential"/>s are stored in, keyed by the base64url-encoded credential
    /// ID. Defaults to <c>fido2Credentials</c>.
    /// </summary>
    public string CredentialsCollectionName { get; set; } = "fido2Credentials";
}
