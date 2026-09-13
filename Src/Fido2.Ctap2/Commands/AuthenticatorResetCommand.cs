namespace Fido2NetLib.Ctap2;

/// <summary>
/// The authenticatorReset command (CTAP 2.3 §6.6): wipes every credential, PIN and biometric enrollment. It has no parameters.
/// </summary>
public sealed class AuthenticatorResetCommand : CtapCommand
{
    /// <inheritdoc/>
    public override CtapCommandType Type => CtapCommandType.AuthenticatorReset;
}
