using System.Text.Json.Serialization;

namespace Fido2NetLib.Internal;

/// <summary>
/// The body of the conformance tool's getEndpoints request.
/// </summary>
/// <param name="endpoint">The relying party's origin, which the tool ties its endpoints to.</param>
[method: JsonConstructor]
public readonly struct GetBLOBRequest(string endpoint)
{
    /// <summary>
    /// The relying party's origin.
    /// </summary>
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; } = endpoint;
}
