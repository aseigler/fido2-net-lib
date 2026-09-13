using System.Threading;
using System.Threading.Tasks;

namespace Fido2NetLib;

/// <summary>
/// A source of authenticator metadata: the FIDO Metadata Service, the conformance tool's service, a directory of statements, or a source of your own.
/// </summary>
public interface IMetadataRepository
{
    /// <summary>
    /// Fetches the metadata BLOB: the list of authenticators with their status reports, verified as far as the source allows.
    /// </summary>
    /// <exception cref="Fido2MetadataException">The BLOB cannot be fetched or does not verify.</exception>
    Task<MetadataBLOBPayload> GetBLOBAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches the metadata statement for one entry of <paramref name="blob"/>, or <see langword="null"/> if the entry has none.
    /// </summary>
    Task<MetadataStatement?> GetMetadataStatementAsync(MetadataBLOBPayload blob, MetadataBLOBPayloadEntry entry, CancellationToken cancellationToken = default);
}
