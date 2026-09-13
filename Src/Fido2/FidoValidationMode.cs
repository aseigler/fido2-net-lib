/// <summary>
/// Which set of rules verification applies.
/// </summary>
public enum FidoValidationMode
{
    /// <summary>
    /// The rules of WebAuthn Level 3 and the FIDO metadata specification, as written.
    /// </summary>
    WebAuthNLevel3,
    /// <summary>
    /// The rules the 2024 FIDO conformance tool expects, where they differ from the specification: revocation of attestation certificates is not checked, since the tool's certificates name CRL distribution points that do not exist.
    /// </summary>
    FidoConformance2024,
    /// <summary>
    /// <see cref="WebAuthNLevel3"/>.
    /// </summary>
    Default = WebAuthNLevel3
}
