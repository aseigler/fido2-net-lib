using Fido2NetLib.Objects;

using Google.Cloud.Firestore;

namespace Fido2NetLib.Firestore;

/// <summary>
/// The document in the usernames collection: one per claimed username, document ID equal to the username
/// itself, so Firestore's own document-ID uniqueness is what makes a username claimable exactly once --
/// no secondary index needed.
/// </summary>
[FirestoreData]
internal sealed class UsernameItem
{
    [FirestoreProperty]
    public Blob UserId { get; set; } = default!;
}

/// <summary>
/// The document in the users collection, document ID equal to the base64url-encoded <see cref="Fido2User.Id"/>.
/// </summary>
[FirestoreData]
internal sealed class UserItem
{
    [FirestoreProperty]
    public Blob UserId { get; set; } = default!;

    [FirestoreProperty]
    public string Name { get; set; } = default!;

    [FirestoreProperty]
    public string? DisplayName { get; set; }
}

/// <summary>
/// The document in the credentials collection, document ID equal to the base64url-encoded
/// <see cref="StoredCredential.Id"/>. Firestore enforces document-ID uniqueness per collection, so a
/// credential ID is globally unique the moment it's created -- not merely unique within some partition or
/// shard, unlike the equivalent item in <c>Fido2.Cosmos</c>.
/// </summary>
[FirestoreData]
internal sealed class CredentialItem
{
    [FirestoreProperty]
    public Blob CredentialId { get; set; } = default!;

    [FirestoreProperty]
    public Blob UserId { get; set; } = default!;

    [FirestoreProperty]
    public Blob UserHandle { get; set; } = default!;

    [FirestoreProperty]
    public string? RpId { get; set; }

    [FirestoreProperty]
    public Blob? PublicKey { get; set; }

    [FirestoreProperty]
    public long SignCount { get; set; }

    /// <summary>
    /// Stored as Firestore's default integer representation of the enum, the same choice
    /// <c>Fido2.Cosmos</c>'s equivalent field makes (Firestore's POCO mapping, like Cosmos's Newtonsoft
    /// serialization there, does not consult this type's own <c>System.Text.Json</c>
    /// <c>JsonConverter</c> attribute -- that only applies to the wire-format JSON this library's callers see).
    /// </summary>
    [FirestoreProperty]
    public AuthenticatorTransport[]? Transports { get; set; }

    [FirestoreProperty]
    public AuthenticatorAttachment? AuthenticatorAttachment { get; set; }

    [FirestoreProperty]
    public bool UvInitialized { get; set; }

    [FirestoreProperty]
    public bool IsBackupEligible { get; set; }

    [FirestoreProperty]
    public bool IsBackedUp { get; set; }

    [FirestoreProperty]
    public Blob? AttestationObject { get; set; }

    [FirestoreProperty]
    public Blob? AttestationClientDataJson { get; set; }

    [FirestoreProperty]
    public bool? IsDiscoverable { get; set; }

    [FirestoreProperty]
    public string? AttestationFormat { get; set; }

    [FirestoreProperty]
    public Timestamp RegDate { get; set; }

    /// <summary>
    /// Stored as a string: Firestore's POCO mapping has no built-in <see cref="Guid"/> support, and a string
    /// is simpler than wrapping it as a <see cref="Blob"/> for a value nothing here ever queries by.
    /// </summary>
    [FirestoreProperty]
    public string AaGuid { get; set; } = default!;
}
