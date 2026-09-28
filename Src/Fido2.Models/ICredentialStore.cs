using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Persists <see cref="Fido2User"/> accounts and their <see cref="StoredCredential"/>s. This is the contract a
/// storage backend (e.g. an EF Core provider) implements; <c>Fido2NetLib.Development.DevelopmentInMemoryStore</c>
/// is a reference implementation used by the demos, not a production store.
/// </summary>
public interface ICredentialStore
{
    /// <summary>
    /// The user with the given name, or <see langword="null"/> if there is none.
    /// </summary>
    Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// The user with the given name, creating one with <paramref name="addCallback"/> if there is none.
    /// </summary>
    Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default);

    /// <summary>
    /// The credentials registered to the user.
    /// </summary>
    Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default);

    /// <summary>
    /// The credential with the given ID, or <see langword="null"/>.
    /// </summary>
    Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default);

    /// <summary>
    /// The credentials whose user handle is <paramref name="userHandle"/>, for a discoverable-credential ceremony.
    /// </summary>
    Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default);

    /// <summary>
    /// The users a credential ID is registered to; more than one would mean the ID is not unique, which a
    /// conformant store must never allow to happen.
    /// </summary>
    Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers a credential to a user.
    /// </summary>
    Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Applies the credential record state updates a Relying Party performs after a successful authentication
    /// ceremony: the signature counter, the backup state, and <c>uvInitialized</c>.
    /// See step 24 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion"/>.
    /// </summary>
    /// <param name="assertionResult">The verified assertion.</param>
    /// <param name="uvInitializationAuthorized">
    /// Whether promoting <c>uvInitialized</c> from <see langword="false"/> to <see langword="true"/> (when this
    /// assertion had UV) has been authorized. The spec says that promotion "SHOULD require authorization by an
    /// additional authentication factor equivalent to WebAuthn user verification", so it only happens when the
    /// caller says so; it is never demoted.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <remarks>
    /// The stored signature counter must never move backwards. The assertion was verified against the counter the
    /// caller read beforehand; if another sign-in has stored a counter at or above this one's since then (both
    /// concurrent, or one a replay), an implementation leaves the record unchanged and throws a
    /// <see cref="Fido2VerificationException"/> with <see cref="Exceptions.Fido2ErrorCode.InvalidSignCount"/> -- the
    /// outcome verification would have had with the up-to-date counter -- and the sign-in should be refused.
    /// </remarks>
    /// <exception cref="Fido2VerificationException">The stored counter has already reached this assertion's.</exception>
    Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a credential. Returns <see langword="true"/> if one was found and removed.
    /// </summary>
    /// <remarks>
    /// A Relying Party that deletes a credential should also tell the authenticator, so a passkey provider
    /// stops offering an entry that will no longer be accepted: see
    /// <see cref="AllAcceptedCredentialsOptions"/> and <see cref="UnknownCredentialOptions"/>.
    /// </remarks>
    Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default);
}
