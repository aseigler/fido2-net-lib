using System;

namespace Fido2NetLib.Cbor;

/// <summary>
/// A CBOR byte string (major type 2).
/// </summary>
public sealed class CborByteString(byte[] value) : CborObject
{
    /// <inheritdoc/>
    public override CborType Type => CborType.ByteString;

    /// <summary>
    /// The bytes.
    /// </summary>
    public byte[] Value { get; } = value ?? throw new ArgumentNullException(nameof(value));

    /// <summary>
    /// The number of bytes.
    /// </summary>
    public int Length => Value.Length;

    /// <summary>
    /// Unwraps the bytes.
    /// </summary>
    public static implicit operator byte[](CborByteString value) => value.Value;
}
