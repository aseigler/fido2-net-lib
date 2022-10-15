﻿using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Objects
{
    public sealed class AuthenticationExtensionsDevicePublicKeyOutputs
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("authenticatorOutput")]
        public byte[] AuthenticatorOutput { get; set; } 

        [JsonConverter(typeof(Base64UrlConverter))]
        [JsonPropertyName("signature")]
        public byte[] Signature { get; set; }
    }
}
