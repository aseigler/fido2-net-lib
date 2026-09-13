using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Serialization;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Fido2NetLib;

public sealed class FileSystemMetadataRepository : IMetadataRepository
{
    private readonly string _directoryPath;
    private readonly Dictionary<Guid, MetadataBLOBPayloadEntry> _entries;
    private readonly ILogger _logger;
    private MetadataBLOBPayload? _blob;

    /// <param name="directoryPath">The directory holding one metadata statement JSON file per authenticator.</param>
    /// <param name="logger">Where loading is reported; see <see cref="MetadataLog"/> for the events.</param>
    public FileSystemMetadataRepository(string directoryPath, ILogger<FileSystemMetadataRepository>? logger = null)
    {
        _directoryPath = directoryPath;
        _entries = new Dictionary<Guid, MetadataBLOBPayloadEntry>();
        _logger = logger ?? NullLogger<FileSystemMetadataRepository>.Instance;
    }

    public async Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default)
    {
        if (_blob is null)
            await GetBLOBAsync(cancellationToken);

        if (entry.AaGuid is Guid aaGuid && _entries.TryGetValue(aaGuid, out var found))
        {
            return found.MetadataStatement;
        }

        return null;
    }

    public async Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_directoryPath))
        {
            _logger.MetadataDirectoryMissing(_directoryPath);
        }
        else
        {
            foreach (var filename in Directory.GetFiles(_directoryPath))
            {
                await using var fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);
                MetadataStatement statement = await JsonSerializer.DeserializeAsync(fileStream, FidoModelSerializerContext.Default.MetadataStatement, cancellationToken: cancellationToken) ?? throw new NullReferenceException(nameof(statement));
                var conformanceEntry = new MetadataBLOBPayloadEntry
                {
                    AaGuid = statement.AaGuid,
                    MetadataStatement = statement,
                    StatusReports =
                    [
                        new StatusReport
                        {
                            Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                        }
                    ]
                };
                if (conformanceEntry.AaGuid is Guid aaGuid)
                {
                    _entries.Add(aaGuid, conformanceEntry);
                    _logger.MetadataStatementLoaded(aaGuid, filename);
                }
                else
                {
                    _logger.MetadataStatementWithoutAaGuid(filename);
                }
            }

            _logger.MetadataStatementsLoaded(_entries.Count, _directoryPath);
        }

        _blob = new MetadataBLOBPayload()
        {
            Entries = _entries.Select(static o => o.Value).ToArray(),
            NextUpdate = "", //Empty means it won't get cached
            LegalHeader = "Local FAKE",
            Number = 1,
            JwtAlg = ""
        };

        return _blob;
    }
}
