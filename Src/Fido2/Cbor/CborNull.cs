namespace Fido2NetLib.Cbor;

/// <summary>
/// The CBOR value <c>null</c> (major type 7, simple value 22).
/// </summary>
public sealed class CborNull : CborObject
{
    /// <summary>
    /// The one instance.
    /// </summary>
    public static readonly CborNull Instance = new();

    /// <inheritdoc/>
    public override CborType Type => CborType.Null;
}
