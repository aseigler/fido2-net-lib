using Fido2NetLib.Objects;

using Newtonsoft.Json;

namespace Fido2NetLib.Cosmos;

/// <summary>
/// The single item shape stored in the container, shared by all three <see cref="Type"/> discriminator values:
/// a username lookup, a user, and a credential. A real Cosmos schema would normally use distinct types with a
/// polymorphic converter; one flat, mostly-nullable shape keeps this reference store's mapping code short.
/// </summary>
internal sealed class CosmosItem
{
    /// <summary>
    /// The Cosmos item id. For a username lookup and a user item this is a fixed constant ("lookup" or "user");
    /// for a credential item it is the credential ID, base64url-encoded (Cosmos item ids may not contain '/').
    /// </summary>
    [JsonProperty("id")]
    public string Id { get; set; } = default!;

    /// <summary>
    /// The container's partition key value. A username lookup is partitioned by the username itself; a user and
    /// its credentials are all partitioned by the user's ID, base64url-encoded.
    /// </summary>
    [JsonProperty("partitionKey")]
    public string PartitionKey { get; set; } = default!;

    /// <summary>
    /// One of "usernameLookup", "user", or "credential".
    /// </summary>
    [JsonProperty("type")]
    public string Type { get; set; } = default!;

    /// <summary>
    /// The Cosmos system-generated ETag, used as an optimistic-concurrency precondition on writes. Populated by
    /// Cosmos on read; ignored on write.
    /// </summary>
    [JsonProperty("_etag")]
    public string? ETag { get; set; }

    /// <summary>The user's ID: on a lookup item, who the username currently resolves to.</summary>
    [JsonProperty("userId")]
    public byte[]? UserId { get; set; }

    /// <summary>The user's name (a user item only).</summary>
    [JsonProperty("name")]
    public string? Name { get; set; }

    /// <summary>The user's display name (a user item only).</summary>
    [JsonProperty("displayName")]
    public string? DisplayName { get; set; }

    /// <summary>The credential ID (a credential item only).</summary>
    [JsonProperty("credentialId")]
    public byte[]? CredentialId { get; set; }

    /// <summary>See <see cref="StoredCredential.RpId"/> (a credential item only).</summary>
    [JsonProperty("rpId")]
    public string? RpId { get; set; }

    /// <summary>See <see cref="StoredCredential.PublicKey"/> (a credential item only).</summary>
    [JsonProperty("publicKey")]
    public byte[]? PublicKey { get; set; }

    /// <summary>See <see cref="StoredCredential.SignCount"/> (a credential item only).</summary>
    [JsonProperty("signCount")]
    public uint? SignCount { get; set; }

    /// <summary>See <see cref="StoredCredential.Transports"/> (a credential item only).</summary>
    [JsonProperty("transports")]
    public AuthenticatorTransport[]? Transports { get; set; }

    /// <summary>See <see cref="StoredCredential.AuthenticatorAttachment"/> (a credential item only).</summary>
    [JsonProperty("authenticatorAttachment")]
    public AuthenticatorAttachment? AuthenticatorAttachment { get; set; }

    /// <summary>See <see cref="StoredCredential.UvInitialized"/> (a credential item only).</summary>
    [JsonProperty("uvInitialized")]
    public bool? UvInitialized { get; set; }

    /// <summary>See <see cref="StoredCredential.IsBackupEligible"/> (a credential item only).</summary>
    [JsonProperty("isBackupEligible")]
    public bool? IsBackupEligible { get; set; }

    /// <summary>See <see cref="StoredCredential.IsBackedUp"/> (a credential item only).</summary>
    [JsonProperty("isBackedUp")]
    public bool? IsBackedUp { get; set; }

    /// <summary>See <see cref="StoredCredential.AttestationObject"/> (a credential item only).</summary>
    [JsonProperty("attestationObject")]
    public byte[]? AttestationObject { get; set; }

    /// <summary>See <see cref="StoredCredential.AttestationClientDataJson"/> (a credential item only).</summary>
    [JsonProperty("attestationClientDataJson")]
    public byte[]? AttestationClientDataJson { get; set; }

    /// <summary>See <see cref="StoredCredential.IsDiscoverable"/> (a credential item only).</summary>
    [JsonProperty("isDiscoverable")]
    public bool? IsDiscoverable { get; set; }

    /// <summary>See <see cref="StoredCredential.UserHandle"/> (a credential item only).</summary>
    [JsonProperty("userHandle")]
    public byte[]? UserHandle { get; set; }

    /// <summary>See <see cref="StoredCredential.AttestationFormat"/> (a credential item only).</summary>
    [JsonProperty("attestationFormat")]
    public string? AttestationFormat { get; set; }

    /// <summary>See <see cref="StoredCredential.RegDate"/> (a credential item only).</summary>
    [JsonProperty("regDate")]
    public DateTimeOffset? RegDate { get; set; }

    /// <summary>See <see cref="StoredCredential.AaGuid"/> (a credential item only).</summary>
    [JsonProperty("aaGuid")]
    public Guid? AaGuid { get; set; }
}
