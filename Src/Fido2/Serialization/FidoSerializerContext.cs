using System.Text.Json.Serialization;

using Fido2NetLib.Internal;

namespace Fido2NetLib.Serialization;

/// <summary>
/// Source-generated <see cref="System.Text.Json"/> metadata for the conformance tool's request and response types, so that serialization works when trimming or AOT-compiling.
/// </summary>
[JsonSerializable(typeof(AuthenticatorResponse))]
[JsonSerializable(typeof(MDSGetEndpointResponse))]
[JsonSerializable(typeof(GetBLOBRequest))]
public partial class FidoSerializerContext : JsonSerializerContext
{
}
