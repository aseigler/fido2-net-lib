using System.Collections.Concurrent;

namespace Fido2NetLib.Development;

/// <summary>
/// An in-memory store of users and their credentials for the demos. Nothing survives a restart; a real application keeps this in its own database.
/// </summary>
public class DevelopmentInMemoryStore
{
    private readonly ConcurrentDictionary<string, Fido2User> _storedUsers = new();
    private readonly List<StoredCredential> _storedCredentials = new();

    /// <summary>
    /// The user with the given name, creating one with <paramref name="addCallback"/> if there is none.
    /// </summary>
    public Fido2User GetOrAddUser(string username, Func<Fido2User> addCallback)
    {
        return _storedUsers.GetOrAdd(username, addCallback());
    }

    /// <summary>
    /// The user with the given name, or <see langword="null"/>.
    /// </summary>
    public Fido2User? GetUser(string username)
    {
        _storedUsers.TryGetValue(username, out var user);
        return user;
    }

    /// <summary>
    /// The credentials registered to the user, by user ID.
    /// </summary>
    public List<StoredCredential> GetCredentialsByUser(Fido2User user)
    {
        return _storedCredentials.Where(c => c.UserId.AsSpan().SequenceEqual(user.Id)).ToList();
    }

    /// <summary>
    /// The credential with the given ID, or <see langword="null"/>.
    /// </summary>
    public StoredCredential? GetCredentialById(byte[] id)
    {
        return _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(id));
    }

    /// <summary>
    /// The credentials whose user handle is <paramref name="userHandle"/>, for a discoverable-credential ceremony.
    /// </summary>
    public Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_storedCredentials.Where(c => c.UserHandle.AsSpan().SequenceEqual(userHandle)).ToList());
    }

    /// <summary>
    /// Stores the signature counter an assertion reported.
    /// </summary>
    public void UpdateCounter(byte[] credentialId, uint counter)
    {
        var cred = _storedCredentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
        cred.SignCount = counter;
    }

    /// <summary>
    /// Registers a credential to a user.
    /// </summary>
    public void AddCredentialToUser(Fido2User user, StoredCredential credential)
    {
        credential.UserId = user.Id;
        _storedCredentials.Add(credential);
    }

    /// <summary>
    /// The users a credential ID is registered to; more than one would mean the ID is not unique.
    /// </summary>
    public Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
        var cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

        if (cred is null)
            return Task.FromResult<List<Fido2User>>([]);

        return Task.FromResult(_storedUsers.Where(u => u.Value.Id.SequenceEqual(cred.UserId)).Select(u => u.Value).ToList());
    }
}
