namespace Fido2NetLib.Ctap2;

#pragma warning disable format
/// <summary>
/// The CTAP2 command codes (CTAP 2.3 §6). Every command except authenticatorGetInfo, authenticatorReset, authenticatorGetNextAssertion and authenticatorSelection takes parameters.
/// </summary>
public enum CtapCommandType : byte
{
    //                                    | value    | has parameters
    /// <summary>
    /// Creates a credential.
    /// </summary>
    AuthenticatorMakeCredential        = 0x01, // | yes
    /// <summary>
    /// Signs with an existing credential.
    /// </summary>
    AuthenticatorGetAssertion          = 0x02, // | yes
    /// <summary>
    /// Reports what the authenticator supports.
    /// </summary>
    AuthenticatorGetInfo               = 0x04, // | no
    /// <summary>
    /// Manages the PIN and issues pinUvAuthTokens.
    /// </summary>
    AuthenticatorClientPin             = 0x06, // | yes
    /// <summary>
    /// Wipes the authenticator.
    /// </summary>
    AuthenticatorReset                 = 0x07, // | no
    /// <summary>
    /// Fetches the next of several assertions.
    /// </summary>
    AuthenticatorGetNextAssertion      = 0x08, // | no
    /// <summary>
    /// Manages biometric enrollments.
    /// </summary>
    AuthenticatorBioEnrollment         = 0x09, // | yes
    /// <summary>
    /// Manages discoverable credentials.
    /// </summary>
    AuthenticatorCredentialManagement  = 0x0A, // | yes
    /// <summary>
    /// Asks the user to touch this authenticator, to pick it among several.
    /// </summary>
    AuthenticatorSelection             = 0x0B, // | no
    /// <summary>
    /// Reads and writes the large-blob array.
    /// </summary>
    AuthenticatorLargeBlobs            = 0x0C, // | yes
    /// <summary>
    /// Changes the authenticator's configuration.
    /// </summary>
    AuthenticatorConfig                = 0x0D, // | yes
    /// <summary>
    /// The first of the codes reserved for vendor-specific commands.
    /// </summary>
    AuthenticatorVendorFirst           = 0x40, // | NA
    /// <summary>
    /// The last of the codes reserved for vendor-specific commands.
    /// </summary>
    AuthenticatorVendorLast            = 0xBF, // | NA
};
