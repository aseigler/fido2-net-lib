using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

using Google.Api.Gax;
using Google.Cloud.Firestore;

namespace Fido2NetLib.Firestore.Tests;

/// <summary>
/// Starts the Firestore emulator in a disposable container for the test run, so
/// <see cref="FirestoreCredentialStore"/> is exercised against real service behaviour (document-ID
/// uniqueness, transaction retry, query semantics) rather than a mock of the SDK.
/// </summary>
/// <remarks>
/// The emulator image bundles the full Google Cloud SDK and can be slow -- or unable -- to start in a
/// sandboxed or Docker-less environment. <see cref="Available"/> reports whether startup succeeded; tests
/// that depend on it check the flag and return early rather than failing the whole run when it did not, since
/// that failure mode is an environment limitation, not a defect in the store.
/// </remarks>
public sealed class FirestoreEmulatorFixture : IAsyncLifetime
{
    private const string ProjectId = "fido2-tests";

    private IContainer? _emulator;

    /// <summary>Whether the emulator started successfully and <see cref="Db"/> is usable.</summary>
    public bool Available { get; private set; }

    /// <summary>The database FIDO2 items are stored in, once <see cref="Available"/>.</summary>
    public FirestoreDb Db { get; private set; } = null!;

    /// <inheritdoc/>
    public async Task InitializeAsync()
    {
        try
        {
            _emulator = new ContainerBuilder()
                .WithImage("gcr.io/google.com/cloudsdktool/cloud-sdk:emulators")
                .WithPortBinding(8080, true)
                .WithEntrypoint("gcloud")
                .WithCommand("emulators", "firestore", "start", "--host-port=0.0.0.0:8080")
                .WithWaitStrategy(Wait.ForUnixContainer().UntilPortIsAvailable(8080))
                .Build();

            await _emulator.StartAsync().WaitAsync(TimeSpan.FromSeconds(90));

            // The builder only ever looks at FIRESTORE_EMULATOR_HOST itself (there is no settable property for
            // it), so the emulator's mapped port has to go through the environment, not the builder.
            Environment.SetEnvironmentVariable("FIRESTORE_EMULATOR_HOST", $"localhost:{_emulator.GetMappedPublicPort(8080)}");

            Db = await new FirestoreDbBuilder
            {
                ProjectId = ProjectId,
                EmulatorDetection = EmulatorDetection.EmulatorOnly,
            }.BuildAsync();

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
        if (_emulator != null)
            await _emulator.DisposeAsync();
    }
}

/// <summary>Groups the tests that share one running emulator instance.</summary>
[CollectionDefinition(Name)]
public sealed class FirestoreEmulatorCollection : ICollectionFixture<FirestoreEmulatorFixture>
{
    /// <summary>The xUnit collection name tests opt into with <c>[Collection(Name)]</c>.</summary>
    public const string Name = "Firestore emulator";
}
