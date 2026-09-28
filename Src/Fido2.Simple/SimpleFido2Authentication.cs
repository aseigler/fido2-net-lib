using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Simple;

/// <summary>
/// The default <see cref="ISimpleFido2Authentication"/>, over an injected <see cref="IFido2"/> and
/// <see cref="ICredentialStore"/>.
/// </summary>
/// <param name="fido2">Verifies ceremonies.</param>
/// <param name="credentialStore">Persists accounts and their credentials.</param>
public sealed class SimpleFido2Authentication(IFido2 fido2, ICredentialStore credentialStore) : ISimpleFido2Authentication
{
    /// <inheritdoc/>
    public async Task<CredentialCreateOptions> InitiateRegistrationAsync(
        string username,
        string? displayName = null,
        SimpleRegistrationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        // Signing up is not a way into an account that already exists: that would let anyone add their own
        // passkey to someone else's account by entering its username. Adding a credential to an existing
        // account is InitiateAddCredentialAsync, for a user the caller has already signed in.
        if (await credentialStore.GetUserAsync(username, cancellationToken).ConfigureAwait(false) is not null)
        {
            throw new InvalidOperationException(
                $"An account named '{username}' already exists. To add a credential to it, sign the user in and call {nameof(InitiateAddCredentialAsync)}.");
        }

        // Not stored yet: CompleteRegistrationAsync creates the account once a credential for it has verified, so
        // an abandoned sign-up does not leave the name taken.
        var user = new Fido2User
        {
            Name = username,
            DisplayName = displayName ?? username,
            // The user handle: a fresh, random identifier, not derived from the username, per
            // https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy.
            Id = RandomNumberGenerator.GetBytes(32),
        };

        return RequestNewCredential(user, [], options);
    }

    /// <inheritdoc/>
    public async Task<CredentialCreateOptions> InitiateAddCredentialAsync(
        string authenticatedUsername,
        SimpleRegistrationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(authenticatedUsername);

        var user = await credentialStore.GetUserAsync(authenticatedUsername, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"No account named '{authenticatedUsername}' is registered.");

        var existingCredentials = await credentialStore.GetCredentialsByUserAsync(user, cancellationToken).ConfigureAwait(false);

        return RequestNewCredential(user, existingCredentials.ConvertAll(c => c.Descriptor), options);
    }

    private CredentialCreateOptions RequestNewCredential(Fido2User user, IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials, SimpleRegistrationOptions? options)
    {
        options ??= new SimpleRegistrationOptions();

        return fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = user,
            ExcludeCredentials = excludeCredentials,
            AttestationPreference = options.AttestationPreference,
            PubKeyCredParams = options.PubKeyCredParams,
            AuthenticatorSelection = options.AuthenticatorSelection,
        });
    }

    // The account a verified registration belongs to: the existing one the ceremony was started for, or -- for a
    // sign-up -- a new one, created now. Either way it must still be the account whose user handle the options
    // carry: if another sign-up took the name in the meantime, or the account was replaced, the credential is not
    // attached to whoever holds the name now.
    private async Task<Fido2User> ResolveRegisteringUserAsync(Fido2User optionsUser, CancellationToken cancellationToken)
    {
        var user = await credentialStore.GetUserAsync(optionsUser.Name, cancellationToken).ConfigureAwait(false)
            ?? await credentialStore.GetOrAddUserAsync(optionsUser.Name, () => optionsUser, cancellationToken).ConfigureAwait(false);

        if (!user.Id.AsSpan().SequenceEqual(optionsUser.Id))
        {
            throw new InvalidOperationException(
                $"The account named '{optionsUser.Name}' is not the one this registration was started for; start the registration again.");
        }

        return user;
    }

    /// <inheritdoc/>
    public async Task<Fido2User> CompleteRegistrationAsync(
        CredentialCreateOptions originalOptions,
        AuthenticatorAttestationRawResponse attestationResponse,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(originalOptions);
        ArgumentNullException.ThrowIfNull(attestationResponse);

        var registered = await fido2.MakeNewCredentialAsync(
            new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = originalOptions,
                IsCredentialIdUniqueToUserCallback = async (p, ct) =>
                {
                    var owners = await credentialStore.GetUsersByCredentialIdAsync(p.CredentialId, ct).ConfigureAwait(false);
                    return owners.Count == 0;
                },
            },
            cancellationToken)
            .ConfigureAwait(false);

        var user = await ResolveRegisteringUserAsync(originalOptions.User, cancellationToken).ConfigureAwait(false);

        var credential = new StoredCredential
        {
            Id = registered.Id,
            RpId = registered.RpId,
            PublicKey = registered.PublicKey,
            Transports = registered.Transports,
            SignCount = registered.SignCount,
            AuthenticatorAttachment = registered.AuthenticatorAttachment,
            UvInitialized = registered.UvInitialized,
            IsBackupEligible = registered.IsBackupEligible,
            IsBackedUp = registered.IsBackedUp,
            AttestationObject = registered.AttestationObject,
            AttestationClientDataJson = registered.AttestationClientDataJson,
            AttestationFormat = registered.AttestationFormat,
            AaGuid = registered.AaGuid,
            UserId = user.Id,
            UserHandle = user.Id,
            RegDate = DateTimeOffset.UtcNow,
            // credProps is a client extension output, carried on the raw response the client sent -- not on
            // what MakeNewCredentialAsync returns, which only models authenticator-side outputs.
            IsDiscoverable = attestationResponse.ClientExtensionResults?.CredProps?.Rk,
        };

        await credentialStore.AddCredentialToUserAsync(user, credential, cancellationToken).ConfigureAwait(false);

        return user;
    }

    /// <inheritdoc/>
    public async Task<AssertionOptions> InitiateAuthenticationAsync(
        string? username = null,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials = [];

        if (username is not null)
        {
            var user = await credentialStore.GetUserAsync(username, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException($"No account named '{username}' is registered.");

            var credentials = await credentialStore.GetCredentialsByUserAsync(user, cancellationToken).ConfigureAwait(false);
            allowedCredentials = credentials.ConvertAll(c => c.Descriptor);
        }

        return fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials,
        });
    }

    /// <inheritdoc/>
    public async Task<Fido2User> CompleteAuthenticationAsync(
        AssertionOptions originalOptions,
        AuthenticatorAssertionRawResponse assertionResponse,
        bool uvInitializationAuthorized = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(originalOptions);
        ArgumentNullException.ThrowIfNull(assertionResponse);

        var stored = await credentialStore.GetCredentialByIdAsync(assertionResponse.RawId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("No stored credential matches the asserted credential ID.");

        var result = await fido2.MakeAssertionAsync(
            new MakeAssertionParams
            {
                AssertionResponse = assertionResponse,
                OriginalOptions = originalOptions,
                StoredPublicKey = stored.PublicKey,
                StoredSignatureCounter = stored.SignCount,
                StoredBackupEligible = stored.IsBackupEligible,
                IsUserHandleOwnerOfCredentialIdCallback = async (p, ct) =>
                {
                    var credentials = await credentialStore.GetCredentialsByUserHandleAsync(p.UserHandle, ct).ConfigureAwait(false);
                    return credentials.Exists(c => c.Id.AsSpan().SequenceEqual(p.CredentialId));
                },
            },
            cancellationToken)
            .ConfigureAwait(false);

        await credentialStore.UpdateCredentialRecordAsync(result, uvInitializationAuthorized, cancellationToken).ConfigureAwait(false);

        // ICredentialStore has no "get user by ID" lookup (only by username, which we may not have been
        // given -- this could be a discoverable-credential ceremony) -- GetUsersByCredentialIdAsync is the
        // interface's own way to resolve a credential back to its owner.
        var owners = await credentialStore.GetUsersByCredentialIdAsync(stored.Id, cancellationToken).ConfigureAwait(false);
        return owners.Count > 0
            ? owners[0]
            : throw new InvalidOperationException("The authenticated credential's owning account could not be resolved.");
    }
}
