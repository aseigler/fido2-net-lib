#nullable disable

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// The <c>PublicKeyCredential</c> a registration ceremony produces, in the JSON shape <c>PublicKeyCredential.toJSON()</c> emits. Pass it to <c>IFido2.MakeNewCredentialAsync</c>.
/// </summary>
public sealed class AuthenticatorAttestationRawResponse
{
    /// <summary>
    /// A string containing the credential's identifier. Base64UrlEncoding of <seealso cref="RawId"/>.
    /// </summary>
    [JsonPropertyName("id"), Required]
    public string Id { get; init; }

    /// <summary>
    /// The new credential's ID as raw bytes, base64url-encoded on the wire.
    /// </summary>
    [JsonConverter(typeof(Base64UrlConverter))]
    [JsonPropertyName("rawId"), Required]
    public byte[] RawId { get; init; }

    /// <summary>
    /// The credential type. Always <see cref="PublicKeyCredentialType.PublicKey"/> for WebAuthn.
    /// </summary>
    [JsonPropertyName("type"), Required]
    public PublicKeyCredentialType Type { get; init; }

    /// <summary>
    /// The attestation the authenticator produced for the new credential.
    /// </summary>
    [JsonPropertyName("response"), Required]
    public AttestationResponse Response { get; init; }

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

    /// <summary>
    /// The <c>AuthenticatorAttestationResponse</c> members, each base64url-encoded on the wire.
    /// </summary>
    public sealed class AttestationResponse
    {
        /// <summary>
        /// The CBOR attestation object: the authenticator data with the new credential's public key, plus the attestation statement over it.
        /// </summary>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("attestationObject")]
        public required byte[] AttestationObject { get; init; }

        /// <summary>
        /// The JSON-compatible serialization of the client data, byte for byte as the client produced it: its hash is what the attestation covers.
        /// </summary>
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("clientDataJSON")]
        public required byte[] ClientDataJson { get; init; }

        /// <summary>
        /// The transports the authenticator reports supporting, from <c>getTransports()</c>. Store them and offer them back in <see cref="PublicKeyCredentialDescriptor.Transports"/> to help the client reach the right authenticator.
        /// </summary>
        [JsonPropertyName("transports"), Required]
        public AuthenticatorTransport[] Transports { get; init; }
    }
}
