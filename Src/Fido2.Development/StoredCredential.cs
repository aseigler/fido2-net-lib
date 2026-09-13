#nullable disable

using Fido2NetLib.Objects;

namespace Fido2NetLib.Development;

/// <summary>
/// What the demos store per credential: the fields of <see cref="RegisteredPublicKeyCredential"/> a relying party needs later, plus bookkeeping. Not published as a package; model your own storage on it.
/// </summary>
public class StoredCredential
{
    /// <summary>
    /// The Credential ID of the public key credential source.
    /// </summary>
    public required byte[] Id { get; set; }

    /// <summary>
    /// The credential public key of the public key credential source.
    /// </summary>
    public byte[] PublicKey { get; set; }

    /// <summary>
    /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public uint SignCount { get; set; }

    /// <summary>
    /// The value returned from getTransports() when the public key credential source was registered.
    /// </summary>
    public AuthenticatorTransport[] Transports { get; set; }

    /// <summary>
    /// The value of the BE flag when the public key credential source was created.
    /// </summary>
    public bool IsBackupEligible { get; set; }

    /// <summary>
    /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
    /// </summary>
    public bool IsBackedUp { get; set; }

    /// <summary>
    /// The value of the attestationObject attribute when the public key credential source was registered.
    /// Storing this enables the Relying Party to reference the credential's attestation statement at a later time.
    /// </summary>
    public byte[] AttestationObject { get; set; }

    /// <summary>
    /// The value of the clientDataJSON attribute when the public key credential source was registered.
    /// Storing this in combination with the above attestationObject item enables the Relying Party to re-verify the attestation signature at a later time.
    /// </summary>
    public byte[] AttestationClientDataJson { get; set; }

    /// <summary>
    /// The ID of the user the credential is registered to.
    /// </summary>
    public byte[] UserId { get; set; }

    /// <summary>
    /// Exposes an Descriptor Object for this credential, used as input to the library for certain operations.
    /// </summary>
    public PublicKeyCredentialDescriptor Descriptor => new(PublicKeyCredentialType.PublicKey, Id, Transports);

    /// <summary>
    /// The user handle the credential was created with, which the authenticator returns in a discoverable-credential ceremony.
    /// </summary>
    public byte[] UserHandle { get; set; }

    /// <summary>
    /// The attestation statement format the registration used.
    /// </summary>
    public string AttestationFormat { get; set; }

    /// <summary>
    /// When the credential was registered.
    /// </summary>
    public DateTimeOffset RegDate { get; set; }

    /// <summary>
    /// The AAGUID of the authenticator model that created the credential.
    /// </summary>
    public Guid AaGuid { get; set; }
}
