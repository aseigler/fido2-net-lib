using StackExchange.Redis;

using Testcontainers.Redis;

namespace Fido2NetLib.Redis.Tests;

/// <summary>
/// Starts one ephemeral Redis container for the whole test run. If Docker is not reachable in this environment,
/// <see cref="Available"/> is <see langword="false"/> and tests skip themselves instead of failing the suite.
/// </summary>
public sealed class RedisContainerFixture : IAsyncLifetime
{
    private RedisContainer? _container;

    /// <summary>
    /// Whether a Redis container was actually started. <see langword="false"/> when Docker is unavailable.
    /// </summary>
    public bool Available { get; private set; }

    /// <summary>
    /// The reason <see cref="Available"/> is <see langword="false"/>, for tests to report when they skip.
    /// </summary>
    public string? UnavailableReason { get; private set; }

    /// <summary>
    /// A fresh connection to the running container. Only valid when <see cref="Available"/> is <see langword="true"/>.
    /// </summary>
    public IConnectionMultiplexer Connect() => ConnectionMultiplexer.Connect(_container!.GetConnectionString());

    /// <inheritdoc/>
    public async Task InitializeAsync()
    {
        try
        {
            _container = new RedisBuilder().Build();
            await _container.StartAsync();
            Available = true;
        }
        catch (Exception ex)
        {
            // No Docker daemon reachable in this environment; tests using this fixture skip themselves.
            UnavailableReason = ex.Message;
            Available = false;
        }
    }

    /// <inheritdoc/>
    public async Task DisposeAsync()
    {
        if (_container is not null)
            await _container.DisposeAsync();
    }
}
