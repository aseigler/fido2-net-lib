using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Serializes an enum by the wire names its members declare with <see cref="System.Runtime.Serialization.EnumMemberAttribute"/>, such as <c>public-key</c> or <c>cross-platform</c>, rather than by the C# member names.
/// </summary>
/// <remarks>
/// On .NET 9 and later the enums carry <c>JsonStringEnumMemberName</c> as well, so the built-in <see cref="System.Text.Json.Serialization.JsonStringEnumConverter"/> produces the same names there.
/// </remarks>
/// <typeparam name="T">An enum whose members carry <see cref="System.Runtime.Serialization.EnumMemberAttribute"/>.</typeparam>
public sealed class FidoEnumConverter<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] T> : JsonConverter<T>
    where T : struct, Enum
{
    /// <summary>
    /// Reads a wire name, case-insensitively, as its enum member.
    /// </summary>
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.String:
                string text = reader.GetString()!;
                if (EnumNameMapper<T>.TryGetValue(text, out T value))
                    return value;
                else
                    throw new JsonException($"Invalid enum value = \"{text}\"");

            case JsonTokenType.Number:
                if (!reader.TryGetInt32(out var number))
                    throw new JsonException($"Invalid enum value = {reader.GetString()}");
                var casted = (T)(object)number; // ints can always be casted to enum, even when the value is not defined
                if (Enum.IsDefined(casted))
                    return casted;
                else
                    throw new JsonException($"Invalid enum value = {number}");

            default:
                throw new JsonException($"Invalid enum value ({reader.TokenType})");
        }
    }

    /// <summary>
    /// Writes the member's wire name.
    /// </summary>
    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(EnumNameMapper<T>.GetName(value));
    }
}
