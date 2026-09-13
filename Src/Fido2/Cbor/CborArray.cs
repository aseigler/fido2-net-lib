using System.Collections;
using System.Collections.Generic;

namespace Fido2NetLib.Cbor;

/// <summary>
/// A CBOR array (major type 4).
/// </summary>
public sealed class CborArray : CborObject, IEnumerable<CborObject>
{
    /// <summary>
    /// Initializes an empty array.
    /// </summary>
    public CborArray()
    {
        Values = [];
    }

    /// <summary>
    /// Initializes an array over an existing list of items.
    /// </summary>
    public CborArray(List<CborObject> values)
    {
        Values = values;
    }

    /// <inheritdoc/>
    public override CborType Type => CborType.Array;

    /// <summary>
    /// The number of items.
    /// </summary>
    public int Length => Values.Count;

    /// <summary>
    /// The items, in order.
    /// </summary>
    public List<CborObject> Values { get; }

    /// <summary>
    /// The item at <paramref name="index"/>.
    /// </summary>
    public override CborObject this[int index] => Values[index];

    /// <summary>
    /// Appends an item.
    /// </summary>
    public void Add(CborObject value)
    {
        Values.Add(value);
    }

    /// <summary>
    /// Appends a byte string.
    /// </summary>
    public void Add(byte[] value)
    {
        Values.Add(new CborByteString(value));
    }

    /// <summary>
    /// Appends a text string.
    /// </summary>
    public void Add(string value)
    {
        Values.Add(new CborTextString(value));
    }

    /// <inheritdoc/>
    public IEnumerator<CborObject> GetEnumerator() => Values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => Values.GetEnumerator();
}
