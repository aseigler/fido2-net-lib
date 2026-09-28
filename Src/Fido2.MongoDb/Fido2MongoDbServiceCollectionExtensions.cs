using Fido2NetLib;
using Fido2NetLib.MongoDb;

using MongoDB.Driver;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the MongoDB <see cref="ICredentialStore"/>.
/// </summary>
public static class Fido2MongoDbServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="MongoDbCredentialStore"/> as the scoped <see cref="ICredentialStore"/>, over an
    /// <see cref="IMongoDatabase"/> resolved from the container (register one separately, e.g. with the MongoDB
    /// driver's own client registration helpers).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The collection names to use; defaults are used when omitted.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2MongoDbStore(this IServiceCollection services, MongoDbCredentialStoreOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        options ??= new MongoDbCredentialStoreOptions();

        services.AddScoped<ICredentialStore>(sp => new MongoDbCredentialStore(sp.GetRequiredService<IMongoDatabase>(), options));
        return services;
    }
}
