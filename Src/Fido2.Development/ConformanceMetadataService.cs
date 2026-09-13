using System.Collections.Concurrent;

namespace Fido2NetLib;

/// <summary>
/// An <see cref="IMetadataService"/> that loads every repository's entries and statements up front, with no caching. Meant for running the FIDO conformance tool and the demo; use <c>DistributedCacheMetadataService</c> in production.
/// </summary>
public class ConformanceMetadataService : IMetadataService
{
    /// <summary>
    /// The metadata sources.
    /// </summary>
    protected readonly List<IMetadataRepository> _repositories;
    /// <summary>
    /// The loaded statements, by AAGUID.
    /// </summary>
    protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
    /// <summary>
    /// The loaded entries, by AAGUID.
    /// </summary>
    protected readonly ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry> _entries;
    /// <summary>
    /// Whether <see cref="InitializeAsync"/> has completed.
    /// </summary>
    protected bool _initialized;

    /// <summary>
    /// Initializes the service over the given sources. Call <see cref="InitializeAsync"/> before looking anything up.
    /// </summary>
    public ConformanceMetadataService(IEnumerable<IMetadataRepository> repositories)
    {
        _repositories = repositories.ToList();
        _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
        _entries = new ConcurrentDictionary<Guid, MetadataBLOBPayloadEntry>();
    }

    /// <summary>
    /// Whether any repository is the conformance tool's, in which case verification applies the tool's rules.
    /// </summary>
    public bool ConformanceTesting()
    {
        return _repositories[0] is ConformanceMetadataRepository;
    }

    /// <summary>
    /// The loaded entry for <paramref name="aaguid"/>, or <see langword="null"/> if no repository listed it.
    /// </summary>
    protected virtual MetadataBLOBPayloadEntry? GetEntry(Guid aaguid)
    {
        if (!IsInitialized())
            throw new InvalidOperationException("MetadataService must be initialized");

        if (_entries.TryGetValue(aaguid, out MetadataBLOBPayloadEntry? entry))
        {
            if (_metadataStatements.TryGetValue(aaguid, out var metadataStatement))
            {
                entry.MetadataStatement = metadataStatement;
            }

            return entry;
        }
        else
        {
            return null;
        }
    }

    /// <summary>
    /// Fetches and keeps the metadata statement for one entry.
    /// </summary>
    protected virtual async Task LoadEntryStatementAsync(IMetadataRepository repository, MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken)
    {
        if (entry.AaGuid.HasValue)
        {
            var statement = await repository.GetMetadataStatementAsync(blob, entry, cancellationToken);

            if (statement?.AaGuid is Guid aaGuid)
            {
                _metadataStatements.TryAdd(aaGuid, statement);
            }
        }
    }

    /// <summary>
    /// Fetches a repository's BLOB and loads every entry it lists.
    /// </summary>
    protected virtual async Task InitializeRepositoryAsync(IMetadataRepository repository, CancellationToken cancellationToken)
    {
        var blob = await repository.GetBLOBAsync(cancellationToken);

        foreach (var entry in blob.Entries)
        {
            if (entry.AaGuid is Guid aaGuid)
            {
                if (_entries.TryAdd(aaGuid, entry))
                {
                    // Load if it doesn't already exist
                    await LoadEntryStatementAsync(repository, blob, entry, cancellationToken);
                }
            }
        }
    }

    /// <summary>
    /// Loads every repository. Does nothing if already initialized.
    /// </summary>
    public virtual async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        foreach (var repository in _repositories)
        {
            await InitializeRepositoryAsync(repository, cancellationToken);
        }
        _initialized = true;
    }

    /// <summary>
    /// Whether <see cref="InitializeAsync"/> has completed.
    /// </summary>
    public virtual bool IsInitialized()
    {
        return _initialized;
    }

    /// <inheritdoc/>
    public virtual Task<MetadataBLOBPayloadEntry?> GetEntryAsync(Guid aaGuid, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(GetEntry(aaGuid));
    }
}
