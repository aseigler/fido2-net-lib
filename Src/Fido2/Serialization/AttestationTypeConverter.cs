using System;
using System.Text.Json;
using System.Text.Json.Serialization;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Serialization;

/// <summary>
/// Serializes an <see cref="AttestationType"/> as its name.
/// </summary>
public sealed class AttestationTypeConverter : JsonConverter<AttestationType>
{
    /// <inheritdoc/>
    public override AttestationType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return AttestationType.Get(reader.GetString()!);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, AttestationType value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}
