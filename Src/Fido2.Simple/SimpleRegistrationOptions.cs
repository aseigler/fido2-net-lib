using Fido2NetLib.Objects;

namespace Fido2NetLib.Simple;

/// <summary>
/// The registration-time defaults <see cref="ISimpleFido2Authentication.InitiateRegistrationAsync"/> applies,
/// and the only two of them it lets a caller override. Everything else about a registration ceremony (the
/// exclude list, the WebAuthn extensions, attestation formats, hints) is intentionally not exposed here -- a
/// caller who needs those uses <see cref="IFido2.RequestNewCredential"/> directly instead.
/// </summary>
public sealed class SimpleRegistrationOptions
{
    /// <summary>
    /// The attestation conveyance preference to request. Defaults to <see cref="AttestationConveyancePreference.None"/>,
    /// since requesting attestation adds privacy prompts and verification complexity most callers of this
    /// simplified surface do not want.
    /// </summary>
    public AttestationConveyancePreference AttestationPreference { get; init; } = AttestationConveyancePreference.None;

    /// <summary>
    /// The key types and signature algorithms to accept, most preferred first. Defaults to
    /// <see cref="PubKeyCredParam.Defaults"/>.
    /// </summary>
    public IReadOnlyList<PubKeyCredParam> PubKeyCredParams { get; init; } = PubKeyCredParam.Defaults;

    /// <summary>
    /// Which authenticators are eligible. Defaults to <see cref="AuthenticatorSelection.Default"/>.
    /// </summary>
    public AuthenticatorSelection AuthenticatorSelection { get; init; } = AuthenticatorSelection.Default;
}
