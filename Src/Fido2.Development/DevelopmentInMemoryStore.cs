using System.Collections.Concurrent;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Development;

/// <summary>
/// An in-memory store of users and their credentials for the demos. Nothing survives a restart; a real application keeps this in its own database.
/// </summary>
public class DevelopmentInMemoryStore : ICredentialStore
{
    private readonly ConcurrentDictionary<string, Fido2User> _storedUsers = new();

    // A plain List<T> is not thread-safe, and this store is a singleton shared across every request. Guarded by
    // _storedCredentialsLock rather than swapped for a concurrent collection, since removal and the
    // predicate-based lookups below need an atomic read-modify-write that ConcurrentBag/ConcurrentDictionary
    // don't offer any more simply than a lock does.
    private readonly List<StoredCredential> _storedCredentials = new();

    // A plain object, not System.Threading.Lock, since this project targets net8.0 as well as net10.0.
    private readonly object _storedCredentialsLock = new();

    public Fido2User GetOrAddUser(string username, Func<Fido2User> addCallback)
    {
        return _storedUsers.GetOrAdd(username, addCallback());
    }

    public Fido2User? GetUser(string username)
    {
        _storedUsers.TryGetValue(username, out var user);
        return user;
    }

    public List<StoredCredential> GetCredentialsByUser(Fido2User user)
    {
        lock (_storedCredentialsLock)
        {
            return _storedCredentials.Where(c => c.UserId.AsSpan().SequenceEqual(user.Id)).ToList();
        }
    }

    public StoredCredential? GetCredentialById(byte[] id)
    {
        lock (_storedCredentialsLock)
        {
            return _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(id));
        }
    }

    public Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        lock (_storedCredentialsLock)
        {
            return Task.FromResult(_storedCredentials.Where(c => c.UserHandle.AsSpan().SequenceEqual(userHandle)).ToList());
        }
    }

    public void UpdateCounter(byte[] credentialId, uint counter)
    {
        lock (_storedCredentialsLock)
        {
            var cred = _storedCredentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
            cred.SignCount = counter;
        }
    }

    /// <summary>
    /// Applies the credential record state updates a Relying Party performs after a successful authentication
    /// ceremony: the signature counter, the backup state, and <c>uvInitialized</c>.
    /// See step 24 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion"/>.
    /// </summary>
    /// <remarks>
    /// Promoting <c>uvInitialized</c> from <see langword="false"/> to <see langword="true"/> SHOULD require
    /// authorization by an additional authentication factor equivalent to WebAuthn user verification. This
    /// in-memory development store performs the update unconditionally; a real Relying Party should not.
    /// </remarks>
    public void UpdateCredentialRecord(VerifyAssertionResult assertionResult)
    {
        lock (_storedCredentialsLock)
        {
            var cred = _storedCredentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(assertionResult.CredentialId));

            cred.SignCount = assertionResult.SignCount;
            cred.IsBackedUp = assertionResult.IsBackedUp;

            if (!cred.UvInitialized)
                cred.UvInitialized = assertionResult.IsUserVerified;
        }
    }

    public void AddCredentialToUser(Fido2User user, StoredCredential credential)
    {
        credential.UserId = user.Id;

        lock (_storedCredentialsLock)
        {
            _storedCredentials.Add(credential);
        }
    }

    /// <summary>
    /// Removes a credential. Returns <see langword="true"/> if one was found and removed.
    /// </summary>
    /// <remarks>
    /// A Relying Party that deletes a credential should also tell the authenticator, so a passkey provider
    /// stops offering an entry that will no longer be accepted: see
    /// <see cref="Objects.AllAcceptedCredentialsOptions"/> and <see cref="Objects.UnknownCredentialOptions"/>.
    /// </remarks>
    public bool RemoveCredential(byte[] credentialId)
    {
        lock (_storedCredentialsLock)
        {
            var cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

            if (cred is null)
                return false;

            return _storedCredentials.Remove(cred);
        }
    }

    public Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
        StoredCredential? cred;
        lock (_storedCredentialsLock)
        {
            cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
        }

        if (cred is null)
            return Task.FromResult<List<Fido2User>>([]);

        return Task.FromResult(_storedUsers.Where(u => u.Value.Id.SequenceEqual(cred.UserId)).Select(u => u.Value).ToList());
    }

    // ICredentialStore: async wrappers over the synchronous API above, so this store can also serve as the
    // reference ICredentialStore implementation the demos are built against.

    Task<Fido2User?> ICredentialStore.GetUserAsync(string username, CancellationToken cancellationToken)
        => Task.FromResult(GetUser(username));

    Task<Fido2User> ICredentialStore.GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken)
        => Task.FromResult(GetOrAddUser(username, addCallback));

    Task<List<StoredCredential>> ICredentialStore.GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken)
        => Task.FromResult(GetCredentialsByUser(user));

    Task<StoredCredential?> ICredentialStore.GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken)
        => Task.FromResult(GetCredentialById(id));

    Task ICredentialStore.AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken)
    {
        AddCredentialToUser(user, credential);
        return Task.CompletedTask;
    }

    // Unlike UpdateCredentialRecord above (the demos' simplified form), this follows the ICredentialStore contract:
    // uvInitialized is only promoted when authorized, and a counter that another sign-in has already passed is
    // refused rather than written backwards.
    Task ICredentialStore.UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized, CancellationToken cancellationToken)
    {
        lock (_storedCredentialsLock)
        {
            var cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(assertionResult.CredentialId))
                ?? throw new InvalidOperationException("No stored credential matches the asserted credential ID.");

            if (!((assertionResult.SignCount == 0 && cred.SignCount == 0) || cred.SignCount < assertionResult.SignCount))
            {
                throw new Fido2VerificationException(
                    Exceptions.Fido2ErrorCode.InvalidSignCount,
                    "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator");
            }

            cred.SignCount = assertionResult.SignCount;
            cred.IsBackedUp = assertionResult.IsBackedUp;

            if (uvInitializationAuthorized && assertionResult.IsUserVerified)
                cred.UvInitialized = true;
        }

        return Task.CompletedTask;
    }

    Task<bool> ICredentialStore.RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken)
        => Task.FromResult(RemoveCredential(credentialId));
}
