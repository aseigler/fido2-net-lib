namespace Fido2NetLib.Ctap2;

/// <summary>
/// The authenticatorGetNextAssertion command (CTAP 2.3 §6.3): fetches the next of several assertions a getAssertion produced. It has no parameters.
/// </summary>
public sealed class AuthenticatorGetNextAssertionCommand : CtapCommand
{
    /// <inheritdoc/>
    public override CtapCommandType Type => CtapCommandType.AuthenticatorGetNextAssertion;
}
