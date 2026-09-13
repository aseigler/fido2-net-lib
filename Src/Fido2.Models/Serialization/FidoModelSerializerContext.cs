using System.Text.Json.Serialization;

namespace Fido2NetLib.Serialization;

/// <summary>
/// Source-generated <see cref="System.Text.Json"/> metadata for the library's models, so that serialization works when trimming or AOT-compiling.
/// </summary>
[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(MetadataBLOBPayload))]
[JsonSerializable(typeof(CredentialCreateOptions))]
[JsonSerializable(typeof(MetadataStatement))]
public partial class FidoModelSerializerContext : JsonSerializerContext
{
}
