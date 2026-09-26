using Amazon.DynamoDBv2;
using Amazon.Runtime;

using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

using Fido2NetLib.DynamoDb;

namespace Fido2NetLib.DynamoDb.Tests;

/// <summary>
/// Starts a real <c>amazon/dynamodb-local</c> container for the test class to run against, so the store's
/// conditional writes and index queries are exercised against real DynamoDB behavior rather than a mock. If
/// Docker is not available in the current environment, tests using this fixture are skipped rather than failed.
/// </summary>
public sealed class DynamoDbLocalFixture : IAsyncLifetime
{
    private IContainer? _container;

    /// <summary>
    /// Whether the container started successfully. Tests should call
    /// <c>Skip.IfNot(fixture.IsAvailable, fixture.SkipReason)</c> before using <see cref="Client"/>.
    /// </summary>
    public bool IsAvailable { get; private set; }

    /// <summary>
    /// Why the fixture is unavailable, set only when <see cref="IsAvailable"/> is <see langword="false"/>.
    /// </summary>
    public string SkipReason { get; private set; } = "";

    /// <summary>
    /// The DynamoDB client pointed at the local container. Only valid when <see cref="IsAvailable"/> is <see langword="true"/>.
    /// </summary>
    public IAmazonDynamoDB Client { get; private set; } = null!;

    /// <summary>
    /// The options identifying the table and indexes this fixture created.
    /// </summary>
    public DynamoDbCredentialStoreOptions Options { get; } = new();

    /// <inheritdoc/>
    public async Task InitializeAsync()
    {
        try
        {
            _container = new ContainerBuilder()
                .WithImage("amazon/dynamodb-local:latest")
                .WithPortBinding(8000, true)
                .WithWaitStrategy(Wait.ForUnixContainer().UntilPortIsAvailable(8000))
                .Build();

            await _container.StartAsync();

            Client = new AmazonDynamoDBClient(
                new BasicAWSCredentials("fake", "fake"),
                new AmazonDynamoDBConfig
                {
                    // Setting RegionEndpoint alongside ServiceURL makes the SDK's endpoint resolution prefer the
                    // real regional AWS endpoint over this custom URL -- silently sending every request to real
                    // AWS instead of the local container. AuthenticationRegion (plus UseHttp, since ServiceURL is
                    // plain HTTP) gets SigV4 the region string it needs without that override.
                    ServiceURL = $"http://localhost:{_container.GetMappedPublicPort(8000)}",
                    UseHttp = true,
                    AuthenticationRegion = "us-east-1",
                });

            await DynamoDbTableSchema.EnsureTableExistsAsync(Client, Options);
            IsAvailable = true;
        }
        catch (Exception ex)
        {
            IsAvailable = false;
            SkipReason = $"DynamoDB Local container could not be started (is Docker available?): {ex.Message}";
        }
    }

    /// <inheritdoc/>
    public async Task DisposeAsync()
    {
        if (_container != null)
            await _container.DisposeAsync();
    }
}
