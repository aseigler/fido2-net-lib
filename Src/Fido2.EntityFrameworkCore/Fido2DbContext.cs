using Microsoft.EntityFrameworkCore;

namespace Fido2NetLib.EntityFrameworkCore;

/// <summary>
/// A <see cref="DbContext"/> holding only FIDO2 data: <see cref="Fido2User"/>s and their <see cref="StoredCredential"/>s.
/// </summary>
/// <remarks>
/// To keep the tables in your own context instead, call
/// <c>modelBuilder.ApplyConfigurationsFromAssembly(typeof(Fido2DbContext).Assembly)</c> in its
/// <c>OnModelCreating</c> and use <see cref="EntityFrameworkCoreCredentialStore{TContext}"/> with it.
/// Schema changes are yours to manage with EF Core migrations, as for the rest of your model.
/// </remarks>
/// <param name="options">The context options.</param>
public class Fido2DbContext(DbContextOptions<Fido2DbContext> options) : DbContext(options)
{
    /// <summary>
    /// Registered accounts.
    /// </summary>
    public DbSet<Fido2User> Fido2Users => Set<Fido2User>();

    /// <summary>
    /// Registered credentials.
    /// </summary>
    public DbSet<StoredCredential> Fido2Credentials => Set<StoredCredential>();

    /// <inheritdoc/>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfiguration(new Fido2UserConfiguration());
        modelBuilder.ApplyConfiguration(new StoredCredentialConfiguration());
    }
}
