using Fido2NetLib;
using Fido2NetLib.Redis;

using StackExchange.Redis;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the Redis <see cref="ICredentialStore"/>.
/// </summary>
public static class Fido2RedisServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="RedisCredentialStore"/> as the singleton <see cref="ICredentialStore"/>, over an
    /// <see cref="IConnectionMultiplexer"/> registered separately.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="keyPrefix">A prefix applied to every key the store writes, to share a Redis instance with other data.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2RedisStore(this IServiceCollection services, string keyPrefix = "fido2:")
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ICredentialStore>(provider =>
            new RedisCredentialStore(provider.GetRequiredService<IConnectionMultiplexer>(), keyPrefix));

        return services;
    }
}
