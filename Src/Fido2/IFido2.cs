using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// The relying party operations: issue options for a ceremony, then verify the response.
/// </summary>
public interface IFido2
{
    /// <summary>
    /// Returns AssertionOptions including a challenge to be sent to the browser/authenticator to authenticate a user.
    /// </summary>
    AssertionOptions GetAssertionOptions(GetAssertionOptionsParams getAssertionOptionsParams);

    /// <summary>
    /// Verifies an authentication response against the options it answers and the stored credential, returning the values to store back.
    /// </summary>
    /// <exception cref="Fido2VerificationException">The response does not verify.</exception>
    Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a registration response against the options it answers, returning the credential to store.
    /// </summary>
    /// <exception cref="Fido2VerificationException">The response does not verify.</exception>
    Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns CredentialCreateOptions including a challenge to be sent to the browser/authenticator to create new credentials.
    /// </summary>
    CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams requestNewCredentialParams);
}
