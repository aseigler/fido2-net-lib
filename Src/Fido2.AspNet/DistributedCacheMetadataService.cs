using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// An <see cref="IMetadataService"/> that reads its repositories' BLOBs through two caches: a memory cache for fast lookups, and a distributed cache that keeps the last good BLOB across restarts and outages of the metadata source. Registered by <c>AddCachedMetadataService()</c>.
/// </summary>
/// <remarks>
/// A BLOB is refreshed no later than its own <c>nextUpdate</c>; a fetch that fails falls back to the distributed copy, so a metadata outage does not fail registrations.
/// </remarks>
public class DistributedCacheMetadataService : IMetadataService, IMetadataServiceAttestationCertificateLookup
{
    /// <summary>
    /// The cache that outlives the process.
    /// </summary>
    protected readonly IDistributedCache _distributedCache;
    /// <summary>
    /// The in-process cache of parsed BLOBs.
    /// </summary>
    protected readonly IMemoryCache _memoryCache;
    /// <summary>
    /// The clock cache expiry is computed against.
    /// </summary>
    protected readonly ISystemClock _systemClock;

    /// <summary>
    /// The metadata sources, consulted in order.
    /// </summary>
    protected readonly List<IMetadataRepository> _repositories;
    /// <summary>
    /// Where fetch failures are reported.
    /// </summary>
    protected readonly ILogger<DistributedCacheMetadataService> _logger;

    /// <summary>
    /// Default in-process memory cache interval, capped by the BLOB's NextUpdate value if sooner.
    /// </summary>
    protected readonly TimeSpan _defaultMemoryCacheInterval = TimeSpan.FromHours(1);

    /// <summary>
    /// Grace period after NextUpdate before a refetch is attempted, to avoid hammering the MDS endpoint
    /// the moment NextUpdate elapses (the new BLOB may not be published exactly on time).
    /// FIDO Alliance does not publish a specific rate limit; their own guidance
    /// (https://fidoalliance.org/metadata/) is to fetch the BLOB about once a month and cache it, since
    /// MDS data changes infrequently. This buffer is a conservative allowance, not a documented requirement.
    /// </summary>
    protected readonly TimeSpan _nextUpdateBufferPeriod = TimeSpan.FromHours(24);

    /// <summary>
    /// Default distributed cache interval used when the BLOB has no NextUpdate value. Aligned with FIDO
    /// Alliance's published guidance to fetch the BLOB about once a month (https://fidoalliance.org/metadata/).
    /// </summary>
    protected readonly TimeSpan _defaultDistributedCacheInterval = TimeSpan.FromDays(30);

    /// <summary>
    /// The prefix of every cache key this service writes, versioned so a change in cached shape does not read stale entries.
    /// </summary>
    protected const string CACHE_PREFIX = nameof(DistributedCacheMetadataService) + ":V2";

    /// <summary>
    /// Initializes the service.
    /// </summary>
    /// <param name="repositories">The metadata sources, consulted in order.</param>
    /// <param name="distributedCache">Keeps the last good BLOB of each repository across restarts.</param>
    /// <param name="memoryCache">Keeps the parsed BLOB of each repository for fast lookups.</param>
    /// <param name="logger">Where fetch failures are reported.</param>
    /// <param name="systemClock">The clock cache expiry is computed against.</param>
    public DistributedCacheMetadataService(
        IEnumerable<IMetadataRepository> repositories,
        IDistributedCache distributedCache,
        IMemoryCache memoryCache,
        ILogger<DistributedCacheMetadataService> logger,
        ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(repositories);

        _repositories = repositories.ToList();
        _distributedCache = distributedCache;
        _memoryCache = memoryCache;
        _logger = logger;
        _systemClock = systemClock;
    }

    /// <summary>
    /// Whether any repository is the conformance tool's, in which case verification applies the tool's rules.
    /// </summary>
    public virtual bool ConformanceTesting()
    {
        return _repositories.Any(o => o.GetType() == typeof(ConformanceMetadataRepository));
    }

    /// <summary>
    /// The cache key under which <paramref name="repository"/>'s BLOB is stored.
    /// </summary>
    protected virtual string GetBlobCacheKey(IMetadataRepository repository)
    {
        return $"{CACHE_PREFIX}:{repository.GetType().Name}:TOC";
    }

    /// <summary>
    /// When the BLOB says it will next be updated, or <see langword="null"/> if it does not say.
    /// </summary>
    protected virtual DateTimeOffset? GetNextUpdateTimeFromPayload(MetadataBLOBPayload blob)
    {
        if (!string.IsNullOrWhiteSpace(blob?.NextUpdate)
            && DateTimeOffset.TryParseExact(
                blob.NextUpdate,
                new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "o" }, // Should be ISO8601 date but allow for other ISO-like formats too
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var parsedDate))
        {
            return parsedDate;
        }

        return null;
    }

    /// <summary>
    /// When the memory copy of a BLOB should expire: the default interval from now, but no later than the BLOB's own next update.
    /// </summary>
    protected virtual DateTimeOffset GetMemoryCacheAbsoluteExpiryTime(DateTimeOffset? nextUpdateTime)
    {
        var expiryTime = _systemClock.UtcNow.GetNextIncrement(_defaultMemoryCacheInterval);

        //Ensure that memory cache expiry time never exceeds the next update time from the service
        if (nextUpdateTime.HasValue && expiryTime > nextUpdateTime.Value)
            expiryTime = nextUpdateTime.Value;

        return expiryTime;
    }

    /// <summary>
    /// Gets the absolute expiry time for the distributed cache.
    /// </summary>
    /// <param name="nextUpdateTime">The next update time from the MDS BLOB payload.</param>
    /// <returns>The absolute expiry time for the cached data.</returns>
    /// <remarks>
    /// When the BLOB has a NextUpdate value, the distributed cache expires at NextUpdate + <see cref="_nextUpdateBufferPeriod"/>,
    /// allowing multiple servers to share the cached BLOB without each independently refetching the moment NextUpdate passes.
    /// Otherwise it falls back to <see cref="_defaultDistributedCacheInterval"/>.
    /// </remarks>
    protected virtual DateTimeOffset GetDistributedCacheAbsoluteExpiryTime(DateTimeOffset? nextUpdateTime)
    {
        if (nextUpdateTime.HasValue)
        {
            return nextUpdateTime.Value.Add(_nextUpdateBufferPeriod);
        }

        return _systemClock.UtcNow.Add(_defaultDistributedCacheInterval);
    }

    /// <summary>
    /// Fetches the BLOB from <paramref name="repository"/>, logging and rethrowing any failure.
    /// </summary>
    protected virtual async Task<MetadataBLOBPayload> GetRepositoryPayloadWithErrorHandling(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        try
        {
            return await repository.GetBLOBAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not fetch metadata from {0}", repository.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// Writes a freshly fetched BLOB to the distributed cache.
    /// </summary>
    protected virtual async Task StoreDistributedCachedBlob(IMetadataRepository repository, MetadataBLOBPayload payload, CancellationToken cancellationToken = default)
    {
        await _distributedCache.SetStringAsync(
            GetBlobCacheKey(repository),
            JsonSerializer.Serialize(payload),
            new DistributedCacheEntryOptions()
            {
                AbsoluteExpiration = GetDistributedCacheAbsoluteExpiryTime(GetNextUpdateTimeFromPayload(payload))
            },
            cancellationToken);
    }

    /// <summary>
    /// Returns the BLOB from the distributed cache if it is current, fetching and storing a fresh one otherwise; a failed fetch falls back to a stale cached copy rather than failing.
    /// </summary>
    protected virtual async Task<MetadataBLOBPayload> GetDistributedCachedBlob(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        var cacheKey = GetBlobCacheKey(repository);

        var distributedCacheEntry = await _distributedCache.GetStringAsync(cacheKey, cancellationToken);
        if (distributedCacheEntry != null)
        {
            try
            {
                var cachedBlob = JsonSerializer.Deserialize<MetadataBLOBPayload>(distributedCacheEntry);
                var nextUpdateTime = GetNextUpdateTimeFromPayload(cachedBlob);

                //If the cache until time is in the past then update and return new data, otherwise return the cached value
                if (nextUpdateTime == null || nextUpdateTime.Value.Add(_nextUpdateBufferPeriod) < _systemClock.UtcNow)
                {
                    var payload = await GetRepositoryPayloadWithErrorHandling(repository, cancellationToken);
                    if (payload != null)
                    {
                        await StoreDistributedCachedBlob(repository, payload, cancellationToken);
                        return payload;
                    }
                }

                return cachedBlob;
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "{0}: Invalid BLOB value in distributed cache", nameof(DistributedCacheMetadataService));
            }
        }

        var repoBlob = await GetRepositoryPayloadWithErrorHandling(repository, cancellationToken);
        if (repoBlob != null)
        {
            await StoreDistributedCachedBlob(repository, repoBlob, cancellationToken);
        }

        return repoBlob;
    }

    /// <summary>
    /// Returns the BLOB from the memory cache, filling it from the distributed cache or the repository when needed.
    /// </summary>
    protected virtual async Task<MetadataBLOBPayload> GetMemoryCachedPayload(IMetadataRepository repository, CancellationToken cancellationToken = default)
    {
        var cacheKey = GetBlobCacheKey(repository);

        var memCacheEntry = await _memoryCache.GetOrCreateAsync<MetadataBLOBPayload>(cacheKey, async memCacheEntry =>
        {
            var distributedCacheBlob = await GetDistributedCachedBlob(repository, cancellationToken);

            if (distributedCacheBlob != null)
            {
                var nextUpdateTime = GetNextUpdateTimeFromPayload(distributedCacheBlob);

                memCacheEntry.AbsoluteExpiration = GetMemoryCacheAbsoluteExpiryTime(nextUpdateTime);

                return distributedCacheBlob;
            }

            return null;
        });

        return memCacheEntry;
    }

    /// <inheritdoc/>
    public async Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        return await GetEntryAsync(aaguid, attestationCertificates: null, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<MetadataBLOBPayloadEntry> GetEntryAsync(Guid aaguid, X509Certificate2[] attestationCertificates, CancellationToken cancellationToken = default)
    {
        var memCacheEntry = await _memoryCache.GetOrCreateAsync<MetadataBLOBPayloadEntry>(
            $"{CACHE_PREFIX}:{aaguid}",
            async entry =>
            {
                foreach (var repo in _repositories)
                {
                    var cachedPayload = await GetMemoryCachedPayload(repo, cancellationToken);
                    if (cachedPayload != null)
                    {
                        var matchingEntry = FindMatchingEntry(cachedPayload, aaguid, attestationCertificates);
                        if (matchingEntry != null)
                        {
                            entry.AbsoluteExpiration = GetMemoryCacheAbsoluteExpiryTime(GetNextUpdateTimeFromPayload(cachedPayload));
                            return matchingEntry;
                        }
                    }
                }

                return null;

            });

        return memCacheEntry;
    }

    /// <summary>
    /// Finds the entry matching <paramref name="aaguid"/>, falling back to matching
    /// <paramref name="attestationCertificates"/> against entries identified only by
    /// <see cref="MetadataBLOBPayloadEntry.AttestationCertificateKeyIdentifiers"/> (e.g. FIDO U2F authenticators,
    /// which have neither an AAID nor an AAGUID in MDS).
    /// </summary>
    protected virtual MetadataBLOBPayloadEntry FindMatchingEntry(MetadataBLOBPayload payload, Guid aaguid, X509Certificate2[] attestationCertificates)
    {
        if (payload.Entries is null)
            return null;

        var matchingEntry = payload.Entries.FirstOrDefault(o => o.AaGuid == aaguid);
        if (matchingEntry != null)
            return matchingEntry;

        if (attestationCertificates is not { Length: > 0 })
            return null;

        return payload.Entries.FirstOrDefault(entry =>
            entry.AaGuid is null &&
            attestationCertificates.Any(entry.MatchesAttestationCertificate));
    }
}
