using Fido2NetLib;
using Fido2NetLib.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the EF Core <see cref="ICredentialStore"/>.
/// </summary>
public static class Fido2EntityFrameworkCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="EntityFrameworkCoreCredentialStore{TContext}"/> as the scoped <see cref="ICredentialStore"/>,
    /// over a context registered separately (e.g. with <c>AddDbContext&lt;TContext&gt;()</c>).
    /// </summary>
    /// <typeparam name="TContext">
    /// <see cref="Fido2DbContext"/>, or your own context whose model applies <see cref="Fido2UserConfiguration"/> and
    /// <see cref="StoredCredentialConfiguration"/>.
    /// </typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2EntityFrameworkCoreStore<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<ICredentialStore, EntityFrameworkCoreCredentialStore<TContext>>();
        return services;
    }
}
