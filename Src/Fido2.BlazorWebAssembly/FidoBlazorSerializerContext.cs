namespace Fido2.BlazorWebAssembly;

using System.Text.Json.Serialization;

using Fido2NetLib;

/// <summary>
/// Source-generated <see cref="System.Text.Json"/> metadata for the options and responses the module passes to and from JavaScript, so that serialization works in a trimmed WebAssembly app.
/// </summary>
[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(AuthenticatorAttestationRawResponse))]
[JsonSerializable(typeof(CredentialCreateOptions))]
public partial class FidoBlazorSerializerContext : JsonSerializerContext
{
}
