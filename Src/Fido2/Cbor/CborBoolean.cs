using System;

namespace Fido2NetLib.Cbor;

/// <summary>
/// A CBOR boolean (major type 7, simple values 20 and 21). Use <see cref="True"/> and <see cref="False"/> rather than constructing one.
/// </summary>
public sealed class CborBoolean(bool value) : CborObject
{
    /// <summary>
    /// The CBOR value <c>true</c>.
    /// </summary>
    public static readonly CborBoolean True = new(true);
    /// <summary>
    /// The CBOR value <c>false</c>.
    /// </summary>
    public static readonly CborBoolean False = new(false);

    /// <inheritdoc/>
    public override CborType Type => CborType.Boolean;

    /// <summary>
    /// The boolean.
    /// </summary>
    public bool Value { get; } = value;

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Value);
    }

    /// <summary>
    /// Wraps a boolean as <see cref="True"/> or <see cref="False"/>.
    /// </summary>
    public static explicit operator CborBoolean(bool value) => value ? True : False;

    /// <summary>
    /// Unwraps the boolean.
    /// </summary>
    public static implicit operator bool(CborBoolean value) => value.Value;
}
