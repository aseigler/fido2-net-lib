using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Request for the authenticatorConfig (0x0D) command, used to enumerate and configure
/// authenticator-level settings such as the minimum PIN length, whether user verification is
/// always required, and enterprise attestation.
/// <para>New in CTAP 2.1, extended in CTAP 2.3 (see §6.11 of the CTAP 2.3 Proposed Standard).</para>
/// </summary>
public sealed class AuthenticatorConfigCommand(
    AuthenticatorConfigSubCommand subCommand,
    CborMap? subCommandParams = null,
    uint? pinUvAuthProtocol = null,
    byte[]? pinUvAuthParam = null) : CtapCommand
{
    /// <summary>
    /// The config sub command currently being requested.
    /// </summary>
    [CborMember(0x01)]
    public AuthenticatorConfigSubCommand SubCommand { get; } = subCommand;

    /// <summary>
    /// Sub command specific parameters, if any.
    /// </summary>
    [CborMember(0x02)]
    public CborMap? SubCommandParams { get; } = subCommandParams;

    /// <summary>
    /// PIN/UV protocol version chosen by the platform.
    /// </summary>
    [CborMember(0x03)]
    public uint? PinUvAuthProtocol { get; } = pinUvAuthProtocol;

    /// <summary>
    /// The result of calling <c>authenticate(pinUvAuthToken, 32×0xff || 0x0D || subCommand || subCommandParams)</c>.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? PinUvAuthParam { get; } = pinUvAuthParam;

    /// <inheritdoc/>
    public override CtapCommandType Type => CtapCommandType.AuthenticatorConfig;

    /// <inheritdoc/>
    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, (int)SubCommand }
        };

        if (SubCommandParams != null)
        {
            cbor.Add(0x02, SubCommandParams);
        }

        if (PinUvAuthProtocol.HasValue)
        {
            cbor.Add(0x03, (int)PinUvAuthProtocol.Value);
        }

        if (PinUvAuthParam != null)
        {
            cbor.Add(0x04, PinUvAuthParam);
        }

        return cbor;
    }
}

/// <summary>
/// The operations of authenticatorConfig (CTAP 2.3 §6.11).
/// </summary>
public enum AuthenticatorConfigSubCommand
{
    #pragma warning disable format
    /// <summary>
    /// Turns enterprise attestation on.
    /// </summary>
    EnableEnterpriseAttestation = 0x01,
    /// <summary>
    /// Toggles whether the authenticator requires user verification for every operation.
    /// </summary>
    ToggleAlwaysUv              = 0x02,
    /// <summary>
    /// Sets the minimum PIN length, and optionally which RP IDs may read it and whether a PIN change is forced.
    /// </summary>
    SetMinPinLength             = 0x03,

    /// <summary>New in CTAP 2.3.</summary>
    EnableLongTouchForReset     = 0x04,

    /// <summary>
    /// Reserved for a vendor's own configuration operations.
    /// </summary>
    VendorPrototype             = 0xFF,
    #pragma warning restore format
}
