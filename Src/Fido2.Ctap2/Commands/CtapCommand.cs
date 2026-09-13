using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// A CTAP2 command: a one-byte command code followed by CBOR-encoded parameters, if the command takes any.
/// </summary>
public abstract class CtapCommand
{
    /// <summary>
    /// The command code.
    /// </summary>
    public abstract CtapCommandType Type { get; }

    /// <summary>
    /// The command's parameters as a CBOR map, or <see langword="null"/> for a command that takes none.
    /// </summary>
    protected virtual CborObject? GetParameters() => null;

    /// <summary>
    /// The bytes to send: the command code followed by the encoded parameters.
    /// </summary>
    public byte[] GetPayload()
    {
        CborObject? parameters = GetParameters();

        if (parameters is null)
        {
            return [(byte)Type];
        }

        var encodedObject = parameters.Encode();

        var result = new byte[encodedObject.Length + 1];

        result[0] = (byte)Type;

        encodedObject.AsSpan().CopyTo(result.AsSpan(1));

        return result;
    }
}
