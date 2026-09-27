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
    /// Starts signing up a new account named <paramref name="username"/>, with a passkey as its first credential.
    /// The account is created by <see cref="CompleteRegistrationAsync"/>, once that credential has verified.
    /// </summary>
    /// <param name="username">The new account's username.</param>
    /// <param name="displayName">The new account's display name. Defaults to <paramref name="username"/>.</param>
    /// <param name="options">Overrides for the registration defaults; see <see cref="SimpleRegistrationOptions"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The options to send to the client's <c>navigator.credentials.create()</c> call.</returns>
    /// <exception cref="InvalidOperationException">
    /// An account named <paramref name="username"/> already exists. Signing up never adds a credential to an
    /// existing account -- otherwise anyone could add their own passkey to someone else's account just by entering
    /// its username. Use <see cref="InitiateAddCredentialAsync"/> for a user who has signed in.
    /// </exception>
    /// <remarks>
    /// The caller is still responsible for holding on to the returned options server-side (e.g. in session state,
    /// never round-tripped through the client) and passing them back to <see cref="CompleteRegistrationAsync"/> --
    /// a registration ceremony is inherently a two-step, stateless-in-between exchange, the same as with
    /// <see cref="IFido2"/> directly.
    /// <para>
    /// Like any sign-up form, this tells the caller whether a username is taken.
    /// </para>
    /// </remarks>
    Task<CredentialCreateOptions> InitiateRegistrationAsync(
        string username,
        string? displayName = null,
        SimpleRegistrationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts adding another credential (a passkey on a second device, or a security key) to an existing account.
    /// </summary>
    /// <param name="authenticatedUsername">
    /// The account to add the credential to. <b>This must be the user the caller has already signed in</b> -- taken
    /// from the authenticated session, never from the request -- since whoever completes this ceremony can sign in
    /// to that account afterwards. The account's existing credentials go in the options' exclude list, so the client
    /// does not create a redundant credential on an authenticator that already holds one for it.
    /// </param>
    /// <param name="options">Overrides for the registration defaults; see <see cref="SimpleRegistrationOptions"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The options to send to the client's <c>navigator.credentials.create()</c> call; complete it with <see cref="CompleteRegistrationAsync"/>.</returns>
    /// <exception cref="InvalidOperationException">No account named <paramref name="authenticatedUsername"/> exists.</exception>
    /// <remarks>
    /// This is also how accounts provisioned outside this library get their first passkey: the user signs in
    /// some other way first (a password, an existing SSO session), then adds one.
    /// </remarks>
    Task<CredentialCreateOptions> InitiateAddCredentialAsync(
        string authenticatedUsername,
        SimpleRegistrationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the client's registration response, creates the account if this was a sign-up, then persists the
    /// new credential via <see cref="ICredentialStore.AddCredentialToUserAsync"/>.
    /// </summary>
    /// <param name="originalOptions">
    /// The options <see cref="InitiateRegistrationAsync"/> or <see cref="InitiateAddCredentialAsync"/> returned for
    /// this ceremony, as held server-side. Remove them from wherever they are held before calling this, so the same
    /// challenge cannot be answered twice.
    /// </param>
    /// <param name="attestationResponse">The client's response.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The account the credential was registered to (<paramref name="originalOptions"/>'s user).</returns>
    /// <exception cref="Fido2VerificationException">The response does not verify.</exception>
    /// <exception cref="InvalidOperationException">
    /// The account named in <paramref name="originalOptions"/> is no longer the one the ceremony was started for:
    /// another sign-up took the name first, or the account was replaced. Nothing is stored.
    /// </exception>
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
    /// <remarks>
    /// With a username, this tells the caller whether that account exists, and the options list its credential
    /// IDs, as any username-first sign-in does. The usernameless ceremony reveals neither.
    /// </remarks>
    Task<AssertionOptions> InitiateAuthenticationAsync(
        string? username = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the client's authentication response against the credential's stored record, then applies the
    /// resulting signature-counter/backup-state update via <see cref="ICredentialStore.UpdateCredentialRecordAsync"/>.
    /// </summary>
    /// <param name="originalOptions">
    /// The options <see cref="InitiateAuthenticationAsync"/> returned for this ceremony, as held server-side. Remove
    /// them from wherever they are held before calling this: a passkey whose signature counter is always 0 has no
    /// counter to catch a replayed response, so a challenge that stays usable is the only thing that would.
    /// </param>
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
