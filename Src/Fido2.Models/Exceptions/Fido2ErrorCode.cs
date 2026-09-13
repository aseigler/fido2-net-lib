namespace Fido2NetLib.Exceptions;

/// <summary>
/// Identifies which verification step a <see cref="Fido2VerificationException"/> failed at.
/// </summary>
[Flags]
public enum Fido2ErrorCode
{
    /// <summary>
    /// No specific step; see the exception message.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The RP ID hash in the authenticator data is not the hash of the configured RP ID.
    /// </summary>
    InvalidRpidHash,
    /// <summary>
    /// The signature does not verify under the credential's public key.
    /// </summary>
    InvalidSignature,
    /// <summary>
    /// The signature counter did not increase, which may mean a cloned authenticator.
    /// </summary>
    InvalidSignCount,
    /// <summary>
    /// User verification was required but the UV flag is not set.
    /// </summary>
    UserVerificationRequirementNotMet,
    /// <summary>
    /// The UP flag is not set: the authenticator did not test user presence.
    /// </summary>
    UserPresentFlagNotSet,
    /// <summary>
    /// Extension outputs were returned that were not requested.
    /// </summary>
    UnexpectedExtensions,
    /// <summary>
    /// No stored public key was supplied to verify the assertion with.
    /// </summary>
    MissingStoredPublicKey,
    /// <summary>
    /// The attestation statement does not verify.
    /// </summary>
    InvalidAttestation,
    /// <summary>
    /// The attestation object has an unexpected shape or contents.
    /// </summary>
    InvalidAttestationObject,
    /// <summary>
    /// The attestation object is not well-formed CBOR.
    /// </summary>
    MalformedAttestationObject,
    /// <summary>
    /// The AT flag is not set, so the authenticator data carries no new credential.
    /// </summary>
    AttestedCredentialDataFlagNotSet,
    /// <summary>
    /// The attestation statement format is not one the library implements.
    /// </summary>
    UnknownAttestationType,
    /// <summary>
    /// The attestation object names no format.
    /// </summary>
    MissingAttestationType,
    /// <summary>
    /// The ED flag is set but the extension data is missing or empty.
    /// </summary>
    MalformedExtensionsDetected,
    /// <summary>
    /// Extension data is present but the ED flag is not set.
    /// </summary>
    UnexpectedExtensionsDetected,
    /// <summary>
    /// The assertion response is missing a member or has one of the wrong kind.
    /// </summary>
    InvalidAssertionResponse,
    /// <summary>
    /// The attestation response is missing a member or has one of the wrong kind.
    /// </summary>
    InvalidAttestationResponse,
    /// <summary>
    /// The attested credential data cannot be parsed.
    /// </summary>
    InvalidAttestedCredentialData,
    /// <summary>
    /// The client data has the wrong type or origin, or the response is otherwise unusable.
    /// </summary>
    InvalidAuthenticatorResponse,
    /// <summary>
    /// The client data is not well-formed JSON.
    /// </summary>
    MalformedAuthenticatorResponse,
    /// <summary>
    /// The response carries no authenticator data.
    /// </summary>
    MissingAuthenticatorData,
    /// <summary>
    /// The authenticator data cannot be parsed.
    /// </summary>
    InvalidAuthenticatorData,
    /// <summary>
    /// The client data carries no challenge.
    /// </summary>
    MissingAuthenticatorResponseChallenge,
    /// <summary>
    /// The challenge in the client data is not the one the options were issued with.
    /// </summary>
    InvalidAuthenticatorResponseChallenge,
    /// <summary>
    /// The credential ID is already registered, per the relying party's uniqueness callback.
    /// </summary>
    NonUniqueCredentialId,
    /// <summary>
    /// The AAGUID is not in the metadata, and the configuration requires it to be.
    /// </summary>
    AaGuidNotFound,
    /// <summary>
    /// The credential uses a COSE algorithm the library does not implement.
    /// </summary>
    UnimplementedAlgorithm,
    /// <summary>
    /// The BE flag does not satisfy the configured backup eligibility policy.
    /// </summary>
    BackupEligibilityRequirementNotMet,
    /// <summary>
    /// The BS flag does not satisfy the configured backed-up policy.
    /// </summary>
    BackupStateRequirementNotMet,
    /// <summary>
    /// The credential's algorithm is not one of those the options offered.
    /// </summary>
    CredentialAlgorithmRequirementNotMet
}
