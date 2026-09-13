namespace Fido2NetLib.Ctap2;

/// <summary>
/// Names the CBOR map key -- an integer for command parameters, a string for option maps -- a property is encoded under.
/// </summary>
public sealed class CborMember : Attribute
{
    /// <summary>
    /// The key: a <see cref="byte"/> or a <see cref="string"/>.
    /// </summary>
    public object _key;

    /// <summary>
    /// Uses an integer key, as CTAP command parameters do.
    /// </summary>
    public CborMember(byte key)
    {
        _key = key;
    }

    /// <summary>
    /// Uses a text key, as CTAP option maps do.
    /// </summary>
    public CborMember(string key)
    {
        _key = key;
    }
}
