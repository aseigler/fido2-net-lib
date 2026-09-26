namespace Fido2NetLib.MongoDb;

/// <summary>
/// Collection names used by <see cref="MongoDbCredentialStore"/>.
/// </summary>
public class MongoDbCredentialStoreOptions
{
    /// <summary>
    /// The name of the collection <see cref="Fido2User"/> accounts are stored in. Defaults to <c>fido2.users</c>.
    /// </summary>
    public string UsersCollectionName { get; set; } = "fido2.users";

    /// <summary>
    /// The name of the collection <see cref="StoredCredential"/>s are stored in. Defaults to <c>fido2.credentials</c>.
    /// </summary>
    public string CredentialsCollectionName { get; set; } = "fido2.credentials";
}
