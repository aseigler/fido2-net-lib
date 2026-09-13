using Fido2NetLib.Cbor;
using Fido2NetLib.Ctap2.Exceptions;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// What an authenticator answered: a status byte, followed by CBOR-encoded data when the status is <see cref="CtapStatusCode.OK"/>.
/// </summary>
public sealed class FidoAuthenticatorResponse
{
    /// <summary>
    /// A response carrying only a status and no data.
    /// </summary>
    public FidoAuthenticatorResponse(CtapStatusCode status)
    {
        Status = status;
        Data = Array.Empty<byte>().AsMemory();
    }

    /// <summary>
    /// Splits a raw response into its status byte and the data that follows.
    /// </summary>
    public FidoAuthenticatorResponse(byte[] message)
    {
        Status = (CtapStatusCode)message[0];
        Data = message.AsMemory(1);
    }

    /// <summary>
    /// The status byte.
    /// </summary>
    public CtapStatusCode Status { get; }

    /// <summary>
    /// The response data after the status byte; empty on error.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>
    /// Decodes <see cref="Data"/> as CBOR.
    /// </summary>
    public CborObject GetCborObject()
    {
        return CborObject.Decode(Data);
    }

    /// <summary>
    /// Throws unless the status is <see cref="CtapStatusCode.OK"/>.
    /// </summary>
    /// <exception cref="Fido2NetLib.Ctap2.Exceptions.CtapException">The status is an error.</exception>
    public void CheckStatus()
    {
        if (Status != CtapStatusCode.OK)
        {
            throw new CtapException(Status);
        }
    }
}
