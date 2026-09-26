namespace Fido2NetLib.DynamoDb;

/// <summary>
/// Table and index names used by <see cref="DynamoDbCredentialStore"/>.
/// </summary>
public class DynamoDbCredentialStoreOptions
{
    /// <summary>
    /// The single table holding user, credential, and credential-ID-reservation items. Defaults to
    /// <c>"Fido2Credentials"</c>.
    /// </summary>
    public string TableName { get; set; } = "Fido2Credentials";

    /// <summary>
    /// The name of the Global Secondary Index keyed on <c>UserHandle</c>, used to look up a discoverable
    /// credential's owner without already knowing the username. Defaults to <c>"UserHandleIndex"</c>.
    /// </summary>
    public string UserHandleIndexName { get; set; } = "UserHandleIndex";

    /// <summary>
    /// The name of the Global Secondary Index keyed on <c>CredentialId</c>, used to look up a credential, or the
    /// user it belongs to, by ID alone. Defaults to <c>"CredentialIdIndex"</c>.
    /// </summary>
    public string CredentialIdIndexName { get; set; } = "CredentialIdIndex";
}
