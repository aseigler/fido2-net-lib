using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// The conformance tool's answer to a getEndpoints request.
/// </summary>
/// <param name="status"><c>ok</c> on success.</param>
/// <param name="result">The metadata BLOB endpoints provisioned for the relying party.</param>
[method: JsonConstructor]
public sealed class MDSGetEndpointResponse(string status, string[] result)
{
    /// <summary>
    /// <c>ok</c> on success.
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; } = status;

    /// <summary>
    /// The metadata BLOB endpoints provisioned for the relying party.
    /// </summary>
    [JsonPropertyName("result")]
    public string[] Result { get; } = result;
}
