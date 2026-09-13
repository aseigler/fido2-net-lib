namespace Fido2NetLib.Ctap2;

/// <summary>
/// The authenticatorGetInfo command (CTAP 2.3 §6.4): asks the authenticator what it supports. It has no parameters.
/// </summary>
public sealed class AuthenticatorGetInfoCommand : CtapCommand
{
    /// <inheritdoc/>
    public override CtapCommandType Type => CtapCommandType.AuthenticatorGetInfo;
}
