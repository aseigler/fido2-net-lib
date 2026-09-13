using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// PublicKeyCredentialType.
/// https://www.w3.org/TR/webauthn-2/#enum-credentialType
/// </summary>
#if NET9_0_OR_GREATER
[JsonConverter(typeof(JsonStringEnumConverter<PublicKeyCredentialType>))]
#else
[JsonConverter(typeof(FidoEnumConverter<PublicKeyCredentialType>))]
#endif
public enum PublicKeyCredentialType
{
    /// <summary>
    /// A public key credential; the only type WebAuthn defines.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("public-key")]
#endif
    [EnumMember(Value = "public-key")]
    PublicKey,

    /// <summary>
    /// Not a WebAuthn credential type. Used in tests to exercise rejection of an unknown type.
    /// </summary>
#if NET9_0_OR_GREATER
    [JsonStringEnumMemberName("invalid")]
#endif
    [EnumMember(Value = "invalid")]
    Invalid
}
