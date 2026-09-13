using System;

namespace Fido2NetLib.Objects;

/// <summary>
/// <see href="https://www.w3.org/TR/webauthn/#extensions"/>
/// </summary>
public sealed class Extensions
{
    private readonly byte[] _extensionBytes;

    /// <summary>
    /// Wraps the CBOR-encoded extension outputs from authenticator data.
    /// </summary>
    public Extensions(byte[] extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        _extensionBytes = extensions;
    }

    /// <summary>
    /// The length of the encoded outputs in bytes.
    /// </summary>
    public int Length => _extensionBytes.Length;

    /// <summary>
    /// The CBOR-encoded outputs, as the authenticator returned them.
    /// </summary>
    public byte[] GetBytes()
    {
        return _extensionBytes;
    }
}
