using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Request for the authenticatorCredentialManagement (0x0A) command, used to enumerate, delete,
/// and update discoverable credentials stored on the authenticator.
/// <para>New in CTAP 2.1 (see §6.8 of the CTAP 2.3 Proposed Standard).</para>
/// </summary>
public sealed class AuthenticatorCredentialManagementCommand(
    AuthenticatorCredentialManagementSubCommand subCommand,
    CborMap? subCommandParams = null,
    uint? pinUvAuthProtocol = null,
    byte[]? pinUvAuthParam = null) : CtapCommand
{
    /// <summary>
    /// The credential management sub command currently being requested.
    /// </summary>
    [CborMember(0x01)]
    public AuthenticatorCredentialManagementSubCommand SubCommand { get; } = subCommand;

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
    /// The output of calling authenticate on some context specific to the sub command. Unlike
    /// authenticatorConfig, this is NOT prefixed with 32×0xff or the command's own opcode: it is
    /// <c>authenticate(pinUvAuthToken, subCommand || subCommandParams)</c>, where
    /// <c>subCommandParams</c> is only included, CBOR-encoded, when present.
    /// </summary>
    [CborMember(0x04)]
    public byte[]? PinUvAuthParam { get; } = pinUvAuthParam;

    /// <inheritdoc/>
    public override CtapCommandType Type => CtapCommandType.AuthenticatorCredentialManagement;

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
/// The operations of authenticatorCredentialManagement (CTAP 2.3 §6.8), which manage the discoverable credentials on the authenticator.
/// </summary>
public enum AuthenticatorCredentialManagementSubCommand
{
    #pragma warning disable format
    /// <summary>
    /// Reports how many discoverable credentials exist and how many more fit.
    /// </summary>
    GetCredsMetadata                      = 0x01,
    /// <summary>
    /// Starts listing the relying parties with discoverable credentials, returning the first.
    /// </summary>
    EnumerateRPsBegin                     = 0x02,
    /// <summary>
    /// Returns the next relying party in the listing.
    /// </summary>
    EnumerateRPsGetNextRP                 = 0x03,
    /// <summary>
    /// Starts listing one relying party's credentials, returning the first.
    /// </summary>
    EnumerateCredentialsBegin             = 0x04,
    /// <summary>
    /// Returns the next credential in the listing.
    /// </summary>
    EnumerateCredentialsGetNextCredential = 0x05,
    /// <summary>
    /// Deletes a credential.
    /// </summary>
    DeleteCredential                      = 0x06,
    /// <summary>
    /// Replaces the user name and display name stored with a credential.
    /// </summary>
    UpdateUserInformation                 = 0x07,
    #pragma warning restore format
}
