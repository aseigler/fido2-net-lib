using Fido2NetLib.Objects;

namespace Fido2NetLib.Simple;

/// <summary>
/// A simple, opinionated facade over <see cref="IFido2"/> and <see cref="ICredentialStore"/>: four methods
/// covering the common registration and authentication ceremonies, with the storage lookups and the
/// uniqueness/ownership callbacks <see cref="IFido2"/> otherwise asks the caller to supply done internally
/// against whichever <see cref="ICredentialStore"/> is registered.
/// </summary>
/// <remarks>
/// This does not replace <see cref="IFido2"/> -- both are fully supported side by side. Use <see cref="IFido2"/>
/// directly instead of this facade when a ceremony needs WebAuthn extensions (PRF, credProtect, largeBlob, and
/// so on), attestation formats/hints, or any other control this interface's four methods do not expose. All
/// exceptions this facade's methods can throw are the same types <see cref="IFido2"/> and
/// <see cref="ICredentialStore"/> already throw (chiefly <see cref="Fido2VerificationException"/>) -- there is
/// no separate error-handling convention to learn.
/// </remarks>
public interface ISimpleFido2Authentication
{
    /// <summary>
    /// Starts a registration ceremony for <paramref name="username"/>, creating the account (via
    /// <see cref="ICredentialStore.GetOrAddUserAsync"/>) if it does not already exist.
    /// </summary>
    /// <param name="username">
    /// The account's username. If the account already has credentials registered, they are added to
    /// the resulting options' exclude list, so the client does not create a redundant credential on an
    /// authenticator that already holds one for this account.
    /// </param>
    /// <param name="displayName">
    /// The account's display name, used only if this call creates a new account. Defaults to
    /// <paramref name="username"/> when not given.
    /// </param>
    /// <param name="options">Overrides for the registration defaults; see <see cref="SimpleRegistrationOptions"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The options to send to the client's <c>navigator.credentials.create()</c> call.</returns>
    /// <remarks>
    /// The caller is still responsible for holding on to the returned options (e.g. in session state) and
    /// passing them back to <see cref="CompleteRegistrationAsync"/> -- a registration ceremony is inherently a
    /// two-step, stateless-in-between exchange, the same as with <see cref="IFido2"/> directly.
    /// </remarks>
    Task<CredentialCreateOptions> InitiateRegistrationAsync(
        string username,
        string? displayName = null,
        SimpleRegistrationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the client's registration response, then persists the new credential via
    /// <see cref="ICredentialStore.AddCredentialToUserAsync"/>.
    /// </summary>
    /// <param name="originalOptions">The options <see cref="InitiateRegistrationAsync"/> returned for this ceremony.</param>
    /// <param name="attestationResponse">The client's response.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The account the credential was registered to (<paramref name="originalOptions"/>'s user).</returns>
    /// <exception cref="Fido2VerificationException">The response does not verify.</exception>
    Task<Fido2User> CompleteRegistrationAsync(
        CredentialCreateOptions originalOptions,
        AuthenticatorAttestationRawResponse attestationResponse,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts an authentication ceremony, either for a named account or, when <paramref name="username"/> is
    /// omitted, as a discoverable-credential ("passkey", usernameless) ceremony.
    /// </summary>
    /// <param name="username">
    /// The account to authenticate, if already known (e.g. the user typed one in). When given, that account's
    /// stored credentials become the options' allowed-credentials list. When omitted, the allowed-credentials
    /// list is left empty and the client lets the user pick from whichever discoverable credentials it has for
    /// this Relying Party; <see cref="CompleteAuthenticationAsync"/> then resolves who signed in from the
    /// assertion's user handle. Both flows are first-class -- this is not a fallback path.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The options to send to the client's <c>navigator.credentials.get()</c> call.</returns>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="username"/> was given but no such account exists. This is deliberately not treated the
    /// same as an omitted username (which means "let the client pick a discoverable credential") -- silently
    /// falling back to a discoverable ceremony for a caller who named a specific, nonexistent account would be
    /// a confusing, hard-to-debug behavior change instead of a clear error.
    /// </exception>
    Task<AssertionOptions> InitiateAuthenticationAsync(
        string? username = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the client's authentication response against the credential's stored record, then applies the
    /// resulting signature-counter/backup-state update via <see cref="ICredentialStore.UpdateCredentialRecordAsync"/>.
    /// </summary>
    /// <param name="originalOptions">The options <see cref="InitiateAuthenticationAsync"/> returned for this ceremony.</param>
    /// <param name="assertionResponse">The client's response.</param>
    /// <param name="uvInitializationAuthorized">
    /// Whether promoting the credential's <c>uvInitialized</c> flag (when this assertion had user verification)
    /// has been authorized. Passed straight through to
    /// <see cref="ICredentialStore.UpdateCredentialRecordAsync"/> -- see that parameter's own remarks: this is a
    /// real Relying Party security decision the spec says "SHOULD require authorization by an additional
    /// authentication factor equivalent to WebAuthn user verification", so it is never defaulted to
    /// <see langword="true"/> and never hidden.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The account that authenticated.</returns>
    /// <exception cref="InvalidOperationException">
    /// The assertion's credential ID does not match any stored credential, or (should the store's data ever be
    /// inconsistent) that credential could not be resolved back to an owning account.
    /// </exception>
    /// <exception cref="Fido2VerificationException">The response does not verify.</exception>
    Task<Fido2User> CompleteAuthenticationAsync(
        AssertionOptions originalOptions,
        AuthenticatorAssertionRawResponse assertionResponse,
        bool uvInitializationAuthorized = false,
        CancellationToken cancellationToken = default);
}
