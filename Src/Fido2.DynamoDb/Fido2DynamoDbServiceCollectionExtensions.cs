using Amazon.DynamoDBv2;

using Fido2NetLib;
using Fido2NetLib.DynamoDb;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the DynamoDB <see cref="ICredentialStore"/>.
/// </summary>
public static class Fido2DynamoDbServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="DynamoDbCredentialStore"/> as the singleton <see cref="ICredentialStore"/>, over an
    /// <see cref="IAmazonDynamoDB"/> registered separately.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Overrides the table and index names; see <see cref="DynamoDbCredentialStoreOptions"/>.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2DynamoDbStore(this IServiceCollection services, Action<DynamoDbCredentialStoreOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new DynamoDbCredentialStoreOptions();
        configureOptions?.Invoke(options);

        services.AddSingleton(options);
        services.AddSingleton<ICredentialStore, DynamoDbCredentialStore>();
        return services;
    }
}
