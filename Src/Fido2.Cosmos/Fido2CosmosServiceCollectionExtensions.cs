using Fido2NetLib;
using Fido2NetLib.Cosmos;

using Microsoft.Azure.Cosmos;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the Azure Cosmos DB <see cref="ICredentialStore"/>.
/// </summary>
public static class Fido2CosmosServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="CosmosCredentialStore"/> as the scoped <see cref="ICredentialStore"/>, over a
    /// <see cref="Container"/> resolved by <paramref name="containerFactory"/>.
    /// </summary>
    /// <remarks>
    /// The container must already exist, with a partition key path of <c>/partitionKey</c>. Provisioning it
    /// (throughput, autoscale, indexing policy) is a deployment concern; this method does not create it. A
    /// <see cref="CosmosClient"/> is expensive to construct and meant to be a long-lived singleton, so
    /// <paramref name="containerFactory"/> would typically resolve one from a <see cref="CosmosClient"/> already
    /// registered elsewhere (e.g. <c>sp.GetRequiredService&lt;CosmosClient&gt;().GetContainer(dbId, containerId)</c>)
    /// rather than constructing a new client per call.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="containerFactory">Resolves the <see cref="Container"/> holding the FIDO2 items.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2CosmosStore(this IServiceCollection services, Func<IServiceProvider, Container> containerFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(containerFactory);

        services.AddScoped<ICredentialStore>(sp => new CosmosCredentialStore(containerFactory(sp)));
        return services;
    }
}
