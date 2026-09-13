#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Transport class for AssertionResponse
/// </summary>
public class AuthenticatorAssertionRawResponse
{
    /// <summary>
    /// A string containing the credential's identifier. Base64UrlEncoding of <seealso cref="RawId"/>.
    /// </summary>
    [JsonPropertyName("id"), Required]
    public string Id { get; init; }

    /// <summary>
    /// The credential ID as raw bytes, base64url-encoded on the wire. This is the value to look the credential up by.
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId"), Required]
    public byte[] RawId { get; init; }

    /// <summary>
    /// The signed material the authenticator produced for this assertion.
    /// </summary>
    [JsonPropertyName("response")]
    public AssertionResponse Response { get; init; }

    /// <summary>
    /// The credential type. Always <see cref="PublicKeyCredentialType.PublicKey"/> for WebAuthn.
    /// </summary>
    [JsonPropertyName("type"), Required]
    public PublicKeyCredentialType Type { get; init; }

    /// <summary>
    /// Obsolete alias of <see cref="ClientExtensionResults"/>.
    /// </summary>
    [JsonPropertyName("extensions")]
    [Obsolete("Use ClientExtensionResults instead")]
    public AuthenticationExtensionsClientOutputs Extensions
    {
        get => ClientExtensionResults;
        set => ClientExtensionResults = value;
    }

    /// <summary>
    /// The client extension outputs, as returned by <c>getClientExtensionResults()</c>.
    /// </summary>
    [JsonPropertyName("clientExtensionResults"), Required]
    public AuthenticationExtensionsClientOutputs ClientExtensionResults { get; set; }

#nullable enable

    /// <summary>
    /// The <c>AuthenticatorAssertionResponse</c> members, each base64url-encoded on the wire.
    /// </summary>
    public sealed class AssertionResponse
    {
        /// <summary>
        /// The authenticator data returned by the authenticator: RP ID hash, flags, signature counter and any extension outputs.
        /// </summary>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("authenticatorData")]
        public required byte[] AuthenticatorData { get; init; }

        /// <summary>
        /// The signature over the authenticator data and the hash of the client data, made with the credential's private key.
        /// </summary>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("signature")]
        public required byte[] Signature { get; init; }

        /// <summary>
        /// The JSON-compatible serialization of the client data, byte for byte as the client produced it: its hash is what was signed.
        /// </summary>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("clientDataJSON")]
        public required byte[] ClientDataJson { get; init; }

        /// <summary>
        /// The user handle the authenticator returned, or <see langword="null"/> if it returned none. Identifies the user in a discoverable-credential ceremony.
        /// </summary>
        [JsonPropertyName("userHandle")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[]? UserHandle { get; init; }
    }
}
