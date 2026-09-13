using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Cbor;

/// <summary>
/// A CBOR map (major type 5). Keys are compared by value; insertion order is kept, and lookups are linear.
/// </summary>
public sealed class CborMap : CborObject, IReadOnlyDictionary<CborObject, CborObject>
{
    private readonly List<KeyValuePair<CborObject, CborObject>> _items;

    /// <summary>
    /// Initializes an empty map.
    /// </summary>
    public CborMap()
    {
        _items = [];
    }

    /// <summary>
    /// Initializes an empty map with room for <paramref name="capacity"/> entries.
    /// </summary>
    public CborMap(int capacity)
    {
        _items = new(capacity);
    }

    /// <inheritdoc/>
    public override CborType Type => CborType.Map;

    /// <summary>
    /// The number of entries.
    /// </summary>
    public int Count => _items.Count;

    /// <summary>
    /// The keys, in insertion order.
    /// </summary>
    public IEnumerable<CborObject> Keys
    {
        get
        {
            foreach (var item in _items)
            {
                yield return item.Key;
            }
        }
    }

    /// <summary>
    /// The values, in insertion order.
    /// </summary>
    public IEnumerable<CborObject> Values
    {
        get
        {
            foreach (var item in _items)
            {
                yield return item.Value;
            }
        }
    }

    /// <summary>
    /// Adds an entry under a text-string key.
    /// </summary>
    public void Add(string key, CborObject value)
    {
        _items.Add(new(new CborTextString(key), value));
    }

    /// <summary>
    /// Adds a boolean under a text-string key.
    /// </summary>
    public void Add(string key, bool value)
    {
        _items.Add(new(new CborTextString(key), (CborBoolean)value));
    }

    /// <summary>
    /// Adds an entry under an integer key.
    /// </summary>
    public void Add(long key, CborObject value)
    {
        _items.Add(new(new CborInteger(key), value));
    }

    /// <summary>
    /// Adds a byte string under an integer key.
    /// </summary>
    public void Add(long key, byte[] value)
    {
        _items.Add(new(new CborInteger(key), new CborByteString(value)));
    }

    /// <summary>
    /// Adds a text string under an integer key.
    /// </summary>
    public void Add(long key, string value)
    {
        _items.Add(new(new CborInteger(key), new CborTextString(value)));
    }

    /// <summary>
    /// Adds an integer under an integer key.
    /// </summary>
    public void Add(long key, long value)
    {
        _items.Add(new(new CborInteger(key), new CborInteger(value)));
    }

    /// <summary>
    /// Adds an integer under a text-string key.
    /// </summary>
    public void Add(string key, int value)
    {
        _items.Add(new(new CborTextString(key), new CborInteger(value)));
    }

    /// <summary>
    /// Adds a text string under a text-string key.
    /// </summary>
    public void Add(string key, string value)
    {
        _items.Add(new(new CborTextString(key), new CborTextString(value)));
    }

    /// <summary>
    /// Adds a byte string under a text-string key.
    /// </summary>
    public void Add(string key, byte[] value)
    {
        _items.Add(new(new CborTextString(key), new CborByteString(value)));
    }

    internal void Add(CborObject key, CborObject value)
    {
        _items.Add(new(key, value));
    }

    internal void Add(string key, COSE.Algorithm value)
    {
        _items.Add(new(new CborTextString(key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyCommonParameter key, COSE.KeyType value)
    {
        _items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyCommonParameter key, COSE.Algorithm value)
    {
        _items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyTypeParameter key, COSE.EllipticCurve value)
    {
        _items.Add(new(new CborInteger((int)key), new CborInteger((int)value)));
    }

    internal void Add(COSE.KeyTypeParameter key, byte[] value)
    {
        _items.Add(new(new CborInteger((int)key), new CborByteString(value)));
    }

    /// <inheritdoc/>
    public bool ContainsKey(CborObject key)
    {
        foreach (var (k, _) in _items)
        {
            if (k.Equals(key))
                return true;
        }

        return false;
    }

    /// <inheritdoc/>
    public bool TryGetValue(CborObject key, [MaybeNullWhen(false)] out CborObject value)
    {
        value = this[key];

        return value != null;
    }

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<CborObject, CborObject>> GetEnumerator()
    {
        return _items.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return _items.GetEnumerator();
    }

    internal CborObject this[COSE.KeyCommonParameter key] => GetValue((long)key);

    internal CborObject this[COSE.EllipticCurve key] => GetValue((long)key);

    internal CborObject this[COSE.KeyType key] => GetValue((long)key);

    internal CborObject this[COSE.KeyTypeParameter key] => GetValue((long)key);

    /// <summary>
    /// The value under an integer key.
    /// </summary>
    /// <exception cref="KeyNotFoundException">There is no such key.</exception>
    public CborObject GetValue(long key)
    {
        foreach (var item in _items)
        {
            if (item.Key is CborInteger integerKey && integerKey.Value == key)
            {
                return item.Value;
            }
        }

        throw new KeyNotFoundException($"Key '{key}' not found");
    }


    /// <summary>
    /// The value under <paramref name="key"/>, or <see langword="null"/> if there is none.
    /// </summary>
    public CborObject? this[CborObject key]
    {
#pragma warning disable CS8766
        get
        {
            foreach (var item in _items)
            {
                if (item.Key.Equals(key))
                {
                    return item.Value;
                }
            }

            return null;
        }
#pragma warning restore CS8766
    }

    /// <summary>
    /// The value under a text-string key, or <see langword="null"/> if there is none.
    /// </summary>
    public override CborObject? this[string name]
    {
        get
        {
            foreach (var item in _items)
            {
                if (item.Key is CborTextString keyText && keyText.Value.Equals(name, StringComparison.Ordinal))
                {
                    return item.Value;
                }
            }

            return null;
        }
    }

    internal void Remove(string key)
    {
        for (int i = 0; i < _items.Count; i++)
        {
            if (_items[i].Key is CborTextString textKey && textKey.Value.Equals(key, StringComparison.Ordinal))
            {
                _items.RemoveAt(i);

                return;
            }
        }
    }

    internal void Set(string key, CborObject value)
    {
        for (int i = 0; i < _items.Count; i++)
        {
            if (_items[i].Key is CborTextString textKey && textKey.Value.Equals(key, StringComparison.Ordinal))
            {
                _items[i] = new KeyValuePair<CborObject, CborObject>(new CborTextString(key), value);

                return;
            }
        }

        _items.Add(new(new CborTextString(key), value));
    }
}
