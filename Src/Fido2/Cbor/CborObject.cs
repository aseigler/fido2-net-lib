using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Fido2NetLib.Cbor;

/// <summary>
/// A CBOR data item, as WebAuthn's attestation objects and authenticator data use them (RFC 8949, CTAP2 canonical form).
/// </summary>
public abstract class CborObject
{
    /// <summary>
    /// Which kind of item this is.
    /// </summary>
    public abstract CborType Type { get; }

    /// <summary>
    /// Decodes one CBOR item from the start of <paramref name="data"/>. Bytes after the item are ignored; use the
    /// overload that reports how many were read when more may follow.
    /// </summary>
    /// <exception cref="System.Formats.Cbor.CborContentException">The bytes are not well-formed CBOR.</exception>
    public static CborObject Decode(ReadOnlyMemory<byte> data)
    {
        var reader = new CborReader(data);

        return Read(reader);
    }

    /// <summary>
    /// Decodes one CBOR item from the start of <paramref name="data"/>, reporting how many bytes it occupied. Authenticator data relies on this, as extension data can follow the credential public key.
    /// </summary>
    /// <exception cref="System.Formats.Cbor.CborContentException">The bytes are not well-formed CBOR.</exception>
    public static CborObject Decode(ReadOnlyMemory<byte> data, out int bytesRead)
    {
        var reader = new CborReader(data);

        var result = Read(reader);

        bytesRead = data.Length - reader.BytesRemaining;

        return result;
    }

    /// <summary>
    /// The item at <paramref name="index"/> of an array; <see langword="null"/> for every other kind of item.
    /// </summary>
    public virtual CborObject this[int index] => null!;

    /// <summary>
    /// The value under a text-string key of a map; <see langword="null"/> for every other kind of item, or if there is no such key.
    /// </summary>
    public virtual CborObject? this[string name] => null;

    /// <summary>
    /// The value of a text string.
    /// </summary>
    /// <exception cref="InvalidCastException">The item is not a text string.</exception>
    public static explicit operator string(CborObject obj)
    {
        return ((CborTextString)obj).Value;
    }

    /// <summary>
    /// The value of a byte string.
    /// </summary>
    /// <exception cref="InvalidCastException">The item is not a byte string.</exception>
    public static explicit operator byte[](CborObject obj)
    {
        return ((CborByteString)obj).Value;
    }

    /// <summary>
    /// The value of an integer, truncated to 32 bits.
    /// </summary>
    /// <exception cref="InvalidCastException">The item is not an integer.</exception>
    public static explicit operator int(CborObject obj)
    {
        return (int)((CborInteger)obj).Value;
    }

    /// <summary>
    /// The value of an integer.
    /// </summary>
    /// <exception cref="InvalidCastException">The item is not an integer.</exception>
    public static explicit operator long(CborObject obj)
    {
        return ((CborInteger)obj).Value;
    }

    /// <summary>
    /// The value of a boolean.
    /// </summary>
    /// <exception cref="InvalidCastException">The item is not a boolean.</exception>
    public static explicit operator bool(CborObject obj)
    {
        return ((CborBoolean)obj).Value;
    }

    private static CborObject Read(CborReader reader)
    {
        CborReaderState s = reader.PeekState();

        return s switch
        {
            CborReaderState.StartMap => ReadMap(reader),
            CborReaderState.StartArray => ReadArray(reader),
            CborReaderState.TextString => new CborTextString(reader.ReadTextString()),
            CborReaderState.Boolean => (CborBoolean)reader.ReadBoolean(),
            CborReaderState.ByteString => new CborByteString(reader.ReadByteString()),
            CborReaderState.UnsignedInteger => new CborInteger(reader.ReadInt64()),
            CborReaderState.NegativeInteger => new CborInteger(reader.ReadInt64()),
            CborReaderState.Null => ReadNull(reader),
            _ => throw new Exception($"Unhandled state. Was {s}")
        };
    }

    private static CborNull ReadNull(CborReader reader)
    {
        reader.ReadNull();

        return CborNull.Instance;
    }

    private static CborArray ReadArray(CborReader reader)
    {
        int? count = reader.ReadStartArray();

        var items = count != null
            ? new List<CborObject>(count.Value)
            : [];

        while (!(reader.PeekState() is CborReaderState.EndArray or CborReaderState.Finished))
        {
            items.Add(Read(reader));
        }

        reader.ReadEndArray();

        return new CborArray(items);
    }

    private static CborMap ReadMap(CborReader reader)
    {
        int? count = reader.ReadStartMap();

        var map = count.HasValue ? new CborMap(count.Value) : new CborMap();

        while (!(reader.PeekState() is CborReaderState.EndMap or CborReaderState.Finished))
        {
            CborObject k = Read(reader);
            CborObject v = Read(reader);

            map.Add(k, v);
        }

        reader.ReadEndMap();

        return map;
    }

    /// <summary>
    /// Encodes the item as CBOR, in the definite-length form the writer produces by default.
    /// </summary>
    public byte[] Encode()
    {
        var writer = new CborWriter();

        writer.WriteObject(this);

        return writer.Encode();
    }
}
