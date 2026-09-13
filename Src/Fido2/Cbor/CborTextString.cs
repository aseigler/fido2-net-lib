using System;

namespace Fido2NetLib.Cbor;

/// <summary>
/// A CBOR text string (major type 3).
/// </summary>
public sealed class CborTextString(string value) : CborObject
{
    /// <inheritdoc/>
    public override CborType Type => CborType.TextString;

    /// <summary>
    /// The length of the string in UTF-16 code units.
    /// </summary>
    public int Length => Value.Length;

    /// <summary>
    /// The string.
    /// </summary>
    public string Value { get; } = value ?? throw new ArgumentNullException(nameof(value));

    /// <summary>
    /// Unwraps the string.
    /// </summary>
    public static implicit operator string(CborTextString value) => value.Value;

    /// <summary>
    /// Two text strings are equal when their values are.
    /// </summary>
    public override bool Equals(object? obj)
    {
        return obj is CborTextString other && other.Value.Equals(Value, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Value);
    }
}
