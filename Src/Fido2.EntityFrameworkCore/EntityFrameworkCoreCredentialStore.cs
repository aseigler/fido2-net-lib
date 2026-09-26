using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.EntityFrameworkCore;

namespace Fido2NetLib.EntityFrameworkCore;

/// <summary>
/// An <see cref="ICredentialStore"/> over any <see cref="DbContext"/> whose model includes the FIDO2 entity
/// configurations (<see cref="Fido2UserConfiguration"/> and <see cref="StoredCredentialConfiguration"/>).
/// </summary>
/// <remarks>
/// Register it with the context's own lifetime (scoped, normally): see
/// <see cref="Microsoft.Extensions.DependencyInjection.Fido2EntityFrameworkCoreServiceCollectionExtensions.AddFido2EntityFrameworkCoreStore{TContext}"/>.
/// <see cref="UpdateCredentialRecordAsync"/> is a single conditional <c>UPDATE</c>, so it needs a relational
/// provider; the EF Core InMemory provider cannot run it.
/// </remarks>
/// <typeparam name="TContext">The context holding the FIDO2 tables.</typeparam>
/// <param name="context">The database context.</param>
public class EntityFrameworkCoreCredentialStore<TContext>(TContext context) : ICredentialStore
    where TContext : DbContext
{
    private DbSet<Fido2User> Users => context.Set<Fido2User>();

    private DbSet<StoredCredential> Credentials => context.Set<StoredCredential>();

    /// <inheritdoc/>
    public async Task<Fido2User?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        return await Users.FirstOrDefaultAsync(u => u.Name == username, cancellationToken);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Two requests adding the same name at once cannot both succeed: the user name is unique, so the one that
    /// loses the race reads back the user the other added instead of creating a second account.
    /// </remarks>
    public async Task<Fido2User> GetOrAddUserAsync(string username, Func<Fido2User> addCallback, CancellationToken cancellationToken = default)
    {
        var existing = await GetUserAsync(username, cancellationToken);
        if (existing != null)
            return existing;

        var user = addCallback();
        var entry = Users.Add(user);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
            return user;
        }
        catch (DbUpdateException)
        {
            entry.State = EntityState.Detached;

            return await GetUserAsync(username, cancellationToken) ?? throw new InvalidOperationException($"Could not add or find the user '{username}'.");
        }
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserAsync(Fido2User user, CancellationToken cancellationToken = default)
    {
        return await Credentials.Where(c => c.UserId == user.Id).ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<StoredCredential?> GetCredentialByIdAsync(byte[] id, CancellationToken cancellationToken = default)
    {
        return await Credentials.FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        return await Credentials.Where(c => c.UserHandle == userHandle).ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var userIds = Credentials.Where(c => c.Id == credentialId).Select(c => c.UserId);

        return await Users.Where(u => userIds.Contains(u.Id)).ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task AddCredentialToUserAsync(Fido2User user, StoredCredential credential, CancellationToken cancellationToken = default)
    {
        credential.UserId = user.Id;
        Credentials.Add(credential);
        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// One conditional <c>UPDATE</c>, applied only while the stored counter is still below this assertion's (or both
    /// are zero), so concurrent sign-ins cannot move it backwards. A <see cref="StoredCredential"/> this context
    /// already tracks is reloaded afterwards, so reading it again in the same request sees the new values.
    /// </remarks>
    public async Task UpdateCredentialRecordAsync(VerifyAssertionResult assertionResult, bool uvInitializationAuthorized = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResult);

        var credentialId = assertionResult.CredentialId;
        var signCount = assertionResult.SignCount;
        var isBackedUp = assertionResult.IsBackedUp;
        var promoteUv = uvInitializationAuthorized && assertionResult.IsUserVerified;

        // The same rule as step 21 of the assertion ceremony, applied atomically against the current row.
        var updated = await Credentials
            .Where(c => c.Id == credentialId && ((signCount == 0 && c.SignCount == 0) || c.SignCount < signCount))
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(c => c.SignCount, signCount)
                    .SetProperty(c => c.IsBackedUp, isBackedUp)
                    .SetProperty(c => c.UvInitialized, c => c.UvInitialized || promoteUv),
                cancellationToken);

        if (updated > 0)
        {
            // The UPDATE bypassed change tracking; without this a credential loaded earlier in the same request
            // would keep answering with the old counter.
            foreach (var entry in context.ChangeTracker.Entries<StoredCredential>().ToList())
            {
                if (entry.Entity.Id.AsSpan().SequenceEqual(credentialId))
                    await entry.ReloadAsync(cancellationToken);
            }

            return;
        }

        if (!await Credentials.AnyAsync(c => c.Id == credentialId, cancellationToken))
            throw new InvalidOperationException("No stored credential matches the asserted credential ID.");

        throw new Fido2VerificationException(Fido2ErrorCode.InvalidSignCount, StaleSignCountMessage);
    }

    internal const string StaleSignCountMessage = "Another sign-in has already stored a signature counter at or above this assertion's; it may be a replay or a cloned authenticator";

    /// <inheritdoc/>
    public async Task<bool> RemoveCredentialAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        return await Credentials.Where(c => c.Id == credentialId).ExecuteDeleteAsync(cancellationToken) > 0;
    }
}

/// <summary>
/// An <see cref="ICredentialStore"/> over <see cref="Fido2DbContext"/>.
/// </summary>
/// <param name="context">The database context.</param>
public sealed class EntityFrameworkCoreCredentialStore(Fido2DbContext context) : EntityFrameworkCoreCredentialStore<Fido2DbContext>(context);
