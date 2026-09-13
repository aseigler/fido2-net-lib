using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// The authenticatorGetAssertion command (CTAP 2.3 §6.2): asks the authenticator to sign a challenge with an existing credential.
/// </summary>
public sealed class AuthenticatorGetAssertionCommand : CtapCommand
{
    /// <summary>
    /// Initializes the command.
    /// </summary>
    /// <param name="rpId">The relying party's identifier.</param>
    /// <param name="clientDataHash">The SHA-256 hash of the client data the signature must cover.</param>
    /// <param name="allowList">The credentials acceptable to the relying party; empty to let the authenticator pick a discoverable credential.</param>
    /// <param name="extensions">Extension inputs, or <see langword="null"/> for none.</param>
    /// <param name="options">The <c>up</c> and <c>uv</c> options, or <see langword="null"/> for the authenticator's defaults.</param>
    /// <param name="pinUvAuthParam">The authentication of <paramref name="clientDataHash"/> under a pinUvAuthToken, when user verification is done by PIN or built-in sensor.</param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol <paramref name="pinUvAuthParam"/> was made with.</param>
    public AuthenticatorGetAssertionCommand(
        string rpId,
        byte[] clientDataHash,
        PublicKeyCredentialDescriptor[] allowList,
        CtapGetAssertionExtensions? extensions = null,
        AuthenticatorGetAssertionOptions? options = null,
        byte[]? pinUvAuthParam = null,
        uint? pinUvAuthProtocol = null)
    {
        ArgumentNullException.ThrowIfNull(rpId);
        ArgumentNullException.ThrowIfNull(clientDataHash);

        RpId = rpId;
        ClientDataHash = clientDataHash;
        AllowList = allowList;
        Extensions = extensions;
        Options = options;
        PinUvAuthParam = pinUvAuthParam;
        PinUvAuthProtocol = pinUvAuthProtocol;
    }

    /// <summary>
    /// Relying party identifier.
    /// </summary>
    [CborMember(0x01)]
    public string RpId { get; }

    /// <summary>
    /// Hash of the serialized client data collected by the host.
    /// </summary>
    [CborMember(0x02)]
    public byte[] ClientDataHash { get; }

    /// <summary>
    /// A sequence of PublicKeyCredentialDescriptor structures, each denoting a credential, as specified in [WebAuthn].
    /// If this parameter is present and has 1 or more entries, the authenticator MUST only generate an assertion using one of the denoted credentials.
    /// </summary>
    [CborMember(0x03)]
    public PublicKeyCredentialDescriptor[] AllowList { get; }

    /// <summary>
    /// CBOR map of extension identifier → authenticator extension input values.
    /// </summary>
    [CborMember(0x04)]
    public CtapGetAssertionExtensions? Extensions { get; }

    /// <summary>
    /// Map of authenticator options.
    /// </summary>
    [CborMember(0x05)]
    public AuthenticatorGetAssertionOptions? Options { get; }

    /// <summary>
    /// First 16 bytes of HMAC-SHA-256 of clientDataHash using pinUvAuthToken which platform got from the authenticator:
    /// HMAC-SHA-256(pinUvAuthToken, clientDataHash).
    /// </summary>
    [CborMember(0x06)]
    public byte[]? PinUvAuthParam { get; }

    /// <summary>
    /// PIN protocol version selected by client.
    /// </summary>
    [CborMember(0x07)]
    public uint? PinUvAuthProtocol { get; }

    /// <inheritdoc/>
    public override CtapCommandType Type => CtapCommandType.AuthenticatorGetAssertion;

    /// <inheritdoc/>
    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap
        {
            { 0x01, RpId },
            { 0x02, ClientDataHash },
            { 0x03, AllowList.ToCborArray() } // allowList
        };

        if (Extensions?.ToCborObject() is CborMap extensions)
        {
            cbor.Add(0x04, extensions);
        }

        if (Options != null)
        {
            cbor.Add(0x05, Options.ToCborObject());
        }

        if (PinUvAuthParam is not null)
        {
            cbor.Add(0x06, PinUvAuthParam);           // pinUvAuthParam(0x08)
            cbor.Add(0x07, PinUvAuthProtocol ?? 1);  // pinUvAuthProtocol(0x09)
        }

        return cbor;
    }
}

/// <summary>
/// The <c>options</c> map of authenticatorGetAssertion.
/// </summary>
public sealed class AuthenticatorGetAssertionOptions
{
    /// <summary>
    /// Instructs the authenticator to require user consent to complete the operation.
    /// </summary>
    [CborMember("up")]
    public bool? UserPresence { get; init; }

    /// <summary>
    /// Instructs the authenticator to require a gesture that verifies the user to complete the request. Examples of such gestures are fingerprint scan or a PIN.
    /// </summary>
    [CborMember("uv")]
    public bool? UserVerification { get; init; }

    /// <summary>
    /// Encodes the options that are set as a CBOR map.
    /// </summary>
    public CborMap ToCborObject()
    {
        var result = new CborMap();

        if (UserPresence is bool up)
        {
            result.Add("up", up);
        }

        if (UserVerification is bool uv)
        {
            result.Add("uv", uv);
        }

        return result;
    }
}
