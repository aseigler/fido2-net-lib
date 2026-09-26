using System.Text.Json;

using Fido2NetLib.Objects;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Fido2NetLib.EntityFrameworkCore;

/// <summary>
/// Maps <see cref="Fido2User"/> to the <c>Fido2Users</c> table: keyed by user handle, with a unique user name.
/// </summary>
/// <remarks>
/// Picked up by <c>modelBuilder.ApplyConfigurationsFromAssembly(typeof(Fido2DbContext).Assembly)</c> in your own
/// <see cref="DbContext"/>, or applied by <see cref="Fido2DbContext"/>.
/// </remarks>
public sealed class Fido2UserConfiguration : IEntityTypeConfiguration<Fido2User>
{
    /// <summary>
    /// The longest user handle WebAuthn allows, in bytes.
    /// </summary>
    public const int MaxUserHandleLength = 64;

    /// <summary>
    /// The longest user name stored, in characters. Bounded so the name can carry a unique index on every provider.
    /// </summary>
    public const int MaxUserNameLength = 256;

    /// <inheritdoc/>
    public void Configure(EntityTypeBuilder<Fido2User> user)
    {
        user.ToTable("Fido2Users");
        user.HasKey(u => u.Id);
        user.Property(u => u.Id).ValueGeneratedNever().HasMaxLength(MaxUserHandleLength);
        user.Property(u => u.Name).IsRequired().HasMaxLength(MaxUserNameLength);
        user.HasIndex(u => u.Name).IsUnique();
    }
}

/// <summary>
/// Maps <see cref="StoredCredential"/> to the <c>Fido2Credentials</c> table.
/// </summary>
/// <remarks>
/// <para>
/// The primary key is a database-generated surrogate (the shadow property <see cref="KeyPropertyName"/>), with a
/// unique index on the credential ID: credential IDs can be up to 1023 bytes, more than some databases allow in a
/// clustered key (SQL Server: 900 bytes). The credential's user is a foreign key to <c>Fido2Users</c>, deleted with it.
/// </para>
/// <para>
/// Picked up by <c>modelBuilder.ApplyConfigurationsFromAssembly(typeof(Fido2DbContext).Assembly)</c> in your own
/// <see cref="DbContext"/>, or applied by <see cref="Fido2DbContext"/>.
/// </para>
/// </remarks>
public sealed class StoredCredentialConfiguration : IEntityTypeConfiguration<StoredCredential>
{
    /// <summary>
    /// The name of the surrogate key shadow property.
    /// </summary>
    public const string KeyPropertyName = "Key";

    /// <summary>
    /// The longest credential ID WebAuthn allows, in bytes.
    /// </summary>
    public const int MaxCredentialIdLength = 1023;

    /// <inheritdoc/>
    public void Configure(EntityTypeBuilder<StoredCredential> credential)
    {
        credential.ToTable("Fido2Credentials");

        credential.Property<long>(KeyPropertyName).ValueGeneratedOnAdd();
        credential.HasKey(KeyPropertyName);

        credential.Property(c => c.Id).IsRequired().HasMaxLength(MaxCredentialIdLength);
        credential.HasIndex(c => c.Id).IsUnique();

        credential.Property(c => c.UserId).IsRequired().HasMaxLength(Fido2UserConfiguration.MaxUserHandleLength);
        credential.HasIndex(c => c.UserId);
        credential.HasOne<Fido2User>().WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);

        credential.Property(c => c.UserHandle).HasMaxLength(Fido2UserConfiguration.MaxUserHandleLength);
        credential.HasIndex(c => c.UserHandle);

        credential.Ignore(c => c.Descriptor);

        var transportsComparer = new ValueComparer<AuthenticatorTransport[]>(
            (a, b) => (a ?? Array.Empty<AuthenticatorTransport>()).SequenceEqual(b ?? Array.Empty<AuthenticatorTransport>()),
            v => (v ?? Array.Empty<AuthenticatorTransport>()).Aggregate(0, (hash, transport) => HashCode.Combine(hash, transport)),
            v => (AuthenticatorTransport[])(v ?? Array.Empty<AuthenticatorTransport>()).Clone());

        credential.Property(c => c.Transports)
            .HasConversion(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => JsonSerializer.Deserialize<AuthenticatorTransport[]>(v, (JsonSerializerOptions?)null) ?? Array.Empty<AuthenticatorTransport>())
            .Metadata.SetValueComparer(transportsComparer);
    }
}
