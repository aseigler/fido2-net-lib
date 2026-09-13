namespace Fido2NetLib.Cbor;

/// <summary>
/// The kinds of CBOR item the library models.
/// </summary>
public enum CborType
{
    /// <summary>
    /// A map of items to items.
    /// </summary>
    Map,
    /// <summary>
    /// An array of items.
    /// </summary>
    Array,
    /// <summary>
    /// <c>true</c> or <c>false</c>.
    /// </summary>
    Boolean,
    /// <summary>
    /// A signed integer.
    /// </summary>
    Integer,
    /// <summary>
    /// A UTF-8 string.
    /// </summary>
    TextString,
    /// <summary>
    /// A byte string.
    /// </summary>
    ByteString,
    /// <summary>
    /// <c>null</c>.
    /// </summary>
    Null
}
