using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

using Microsoft.Azure.Cosmos;

namespace Fido2NetLib.Cosmos.Tests;

/// <summary>
/// Starts the Linux Cosmos DB emulator in a disposable container for the test run, so
/// <see cref="CosmosCredentialStore"/> is exercised against real service behaviour (partitioning, ETag
/// preconditions, cross-partition query semantics) rather than a mock of the SDK.
/// </summary>
/// <remarks>
/// The emulator image is large and can be slow -- or unable -- to start in a sandboxed or Docker-less
/// environment. <see cref="Available"/> reports whether startup succeeded; tests that depend on it check the
/// flag and return early rather than failing the whole run when it did not, since that failure mode is an
/// environment limitation, not a defect in the store.
/// </remarks>
public sealed class CosmosEmulatorFixture : IAsyncLifetime
{
    // The Cosmos DB emulator's key is a well-known, publicly documented fixed value; it is not a secret.
    private const string EmulatorKey = "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";

    private IContainer? _emulator;
    private CosmosClient? _client;

    /// <summary>Whether the emulator started successfully and <see cref="Container"/> is usable.</summary>
    public bool Available { get; private set; }

    /// <summary>The container FIDO2 items are stored in, once <see cref="Available"/>.</summary>
    public Container Container { get; private set; } = null!;

    /// <inheritdoc/>
    public async Task InitializeAsync()
    {
        try
        {
            _emulator = new ContainerBuilder()
                .WithImage("mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:latest")
                .WithPortBinding(8081, true)
                .WithEnvironment("AZURE_COSMOS_EMULATOR_PARTITION_COUNT", "1")
                .WithEnvironment("AZURE_COSMOS_EMULATOR_ENABLE_DATA_PERSISTENCE", "false")
                .WithWaitStrategy(Wait.ForUnixContainer().UntilPortIsAvailable(8081))
                .Build();

            await _emulator.StartAsync().WaitAsync(TimeSpan.FromSeconds(90));

            var endpoint = $"https://localhost:{_emulator.GetMappedPublicPort(8081)}";
            _client = new CosmosClient(endpoint, EmulatorKey, new CosmosClientOptions
            {
                ConnectionMode = ConnectionMode.Gateway,
                HttpClientFactory = () => new HttpClient(new HttpClientHandler
                {
                    // The emulator presents a self-signed certificate.
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                }),
            });

            var database = await _client.CreateDatabaseIfNotExistsAsync("fido2-tests");
            var response = await database.Database.CreateContainerIfNotExistsAsync("credentials", "/partitionKey");
            Container = response.Container;
            Available = true;
        }
        catch
        {
            Available = false;
        }
    }

    /// <inheritdoc/>
    public async Task DisposeAsync()
    {
        _client?.Dispose();
        if (_emulator != null)
            await _emulator.DisposeAsync();
    }
}

/// <summary>Groups the tests that share one running emulator instance.</summary>
[CollectionDefinition(Name)]
public sealed class CosmosEmulatorCollection : ICollectionFixture<CosmosEmulatorFixture>
{
    /// <summary>The xUnit collection name tests opt into with <c>[Collection(Name)]</c>.</summary>
    public const string Name = "Cosmos emulator";
}
