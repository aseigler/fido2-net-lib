namespace Fido2NetLib.Ctap2;

/// <summary>
/// The CTAP status codes, per the error response values table in
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html">CTAP 2.3</see>.
/// </summary>
/// <remarks>
/// A few values CTAP 2.0 defined no longer appear in the 2.3 table. They are kept here, marked as such, so that
/// a response from an older authenticator still reports a name rather than a bare number.
/// </remarks>
#pragma warning disable format
public enum CtapStatusCode
{
    /// <summary>
    /// Indicates successful response.
    /// </summary>
    OK                              = 0x00,
    /// <summary>
    /// The command is not a valid CTAP command.
    /// </summary>
    CTAP1_ERR_INVALID_COMMAND       = 0x01,
    /// <summary>
    /// The command included an invalid parameter.
    /// </summary>
    CTAP1_ERR_INVALID_PARAMETER     = 0x02,
    /// <summary>
    /// Invalid message or item length.
    /// </summary>
    CTAP1_ERR_INVALID_LENGTH        = 0x03,
    /// <summary>
    /// Invalid message sequencing.
    /// </summary>
    CTAP1_ERR_INVALID_SEQ           = 0x04,
    /// <summary>
    /// Message timed out.
    /// </summary>
    CTAP1_ERR_TIMEOUT               = 0x05,
    /// <summary>
    /// Channel busy.
    /// </summary>
    CTAP1_ERR_CHANNEL_BUSY          = 0x06,
    /// <summary>
    /// Command requires channel lock.
    /// </summary>
    CTAP1_ERR_LOCK_REQUIRED         = 0x0A,
    /// <summary>
    /// Command not allowed on this cid.
    /// </summary>
    CTAP1_ERR_INVALID_CHANNEL       = 0x0B,
    /// <summary>
    /// Invalid/unexpected CBOR error.
    /// </summary>
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE  = 0x11,
    /// <summary>
    /// Error when parsing CBOR.
    /// </summary>
    CTAP2_ERR_INVALID_CBOR          = 0x12,
    /// <summary>
    /// Missing non-optional parameter.
    /// </summary>
    CTAP2_ERR_MISSING_PARAMETER     = 0x14,
    /// <summary>
    /// Limit for number of items exceeded.
    /// </summary>
    CTAP2_ERR_LIMIT_EXCEEDED        = 0x15,
    /// <summary>
    /// Unsupported extension. CTAP 2.0 only; absent from the CTAP 2.3 table.
    /// </summary>
    CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16,
    /// <summary>
    /// Fingerprint database is full, e.g. during enrollment.
    /// </summary>
    CTAP2_ERR_FP_DATABASE_FULL      = 0x17,
    /// <summary>
    /// Large blob storage is full.
    /// </summary>
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = 0x18,
    /// <summary>
    /// Valid credential found in the exclude list.
    /// </summary>
    CTAP2_ERR_CREDENTIAL_EXCLUDED   = 0x19,
    /// <summary>
    /// Processing (Lengthy operation is in progress).
    /// </summary>
    CTAP2_ERR_PROCESSING            = 0x21,
    /// <summary>
    /// Credential not valid for the authenticator.
    /// </summary>
    CTAP2_ERR_INVALID_CREDENTIAL    = 0x22,
    /// <summary>
    /// Authentication is waiting for user interaction.
    /// </summary>
    CTAP2_ERR_USER_ACTION_PENDING   = 0x23,
    /// <summary>
    /// Processing, lengthy operation is in progress.
    /// </summary>
    CTAP2_ERR_OPERATION_PENDING     = 0x24,
    /// <summary>
    /// No request is pending.
    /// </summary>
    CTAP2_ERR_NO_OPERATIONS         = 0x25,
    /// <summary>
    /// Authenticator does not support requested algorithm.
    /// </summary>
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26,
    /// <summary>
    /// Not authorized for requested operation.
    /// </summary>
    CTAP2_ERR_OPERATION_DENIED      = 0x27,
    /// <summary>
    /// Internal key storage is full.
    /// </summary>
    CTAP2_ERR_KEY_STORE_FULL        = 0x28,
    /// <summary>
    /// No outstanding operations. CTAP 2.0 only; absent from the CTAP 2.3 table.
    /// </summary>
    CTAP2_ERR_NO_OPERATION_PENDING  = 0x2A,
    /// <summary>
    /// Unsupported option.
    /// </summary>
    CTAP2_ERR_UNSUPPORTED_OPTION    = 0x2B,
    /// <summary>
    /// Not a valid option for current operation.
    /// </summary>
    CTAP2_ERR_INVALID_OPTION        = 0x2C,
    /// <summary>
    /// Pending keep alive was cancelled.
    /// </summary>
    CTAP2_ERR_KEEPALIVE_CANCEL      = 0x2D,
    /// <summary>
    /// No valid credentials provided.
    /// </summary>
    CTAP2_ERR_NO_CREDENTIALS        = 0x2E,
    /// <summary>
    /// Timeout waiting for user interaction.
    /// </summary>
    CTAP2_ERR_USER_ACTION_TIMEOUT   = 0x2F,
    /// <summary>
    /// Continuation command, such as, authenticatorGetNextAssertion not allowed.
    /// </summary>
    CTAP2_ERR_NOT_ALLOWED           = 0x30,
    /// <summary>
    /// PIN Invalid.
    /// </summary>
    CTAP2_ERR_PIN_INVALID           = 0x31,
    /// <summary>
    /// PIN Blocked.
    /// </summary>
    CTAP2_ERR_PIN_BLOCKED           = 0x32,
    /// <summary>
    /// PIN authentication,pinUvAuthParam, verification failed.
    /// </summary>
    CTAP2_ERR_PIN_AUTH_INVALID      = 0x33,
    /// <summary>
    /// PIN authentication using pinUvAuthToken blocked. Requires power cycle to reset.
    /// </summary>
    CTAP2_ERR_PIN_AUTH_BLOCKED      = 0x34,
    /// <summary>
    /// No PIN has been set.
    /// </summary>
    CTAP2_ERR_PIN_NOT_SET           = 0x35,
    /// <summary>
    /// A pinUvAuthToken is required for the selected operation (CTAP 2.0 named this CTAP2_ERR_PIN_REQUIRED).
    /// </summary>
    CTAP2_ERR_PUAT_REQUIRED         = 0x36,
    /// <summary>
    /// PIN policy violation. Currently only enforces minimum length.
    /// </summary>
    CTAP2_ERR_PIN_POLICY_VIOLATION  = 0x37,
    /// <summary>
    /// pinToken expired. CTAP 2.0 only; 0x38 is reserved for future use in CTAP 2.3.
    /// </summary>
    CTAP2_ERR_PIN_TOKEN_EXPIRED     = 0x38,
    /// <summary>
    /// Authenticator cannot handle this request due to memory constraints.
    /// </summary>
    CTAP2_ERR_REQUEST_TOO_LARGE     = 0x39,
    /// <summary>
    /// The current operation has timed out.
    /// </summary>
    CTAP2_ERR_ACTION_TIMEOUT        = 0x3A,
    /// <summary>
    /// User presence is required for the requested operation.
    /// </summary>
    CTAP2_ERR_UP_REQUIRED           = 0x3B,
    /// <summary>
    /// built-in user verification is blocked.
    /// </summary>
    CTAP2_ERR_UV_BLOCKED            = 0x3C,
    /// <summary>
    /// A checksum did not match.
    /// </summary>
    CTAP2_ERR_INTEGRITY_FAILURE     = 0x3D,
    /// <summary>
    /// The requested subcommand is either invalid or not implemented.
    /// </summary>
    CTAP2_ERR_INVALID_SUBCOMMAND    = 0x3E,
    /// <summary>
    /// built-in user verification unsuccessful. The platform SHOULD retry.
    /// </summary>
    CTAP2_ERR_UV_INVALID            = 0x3F,
    /// <summary>
    /// The permission set has not been granted for the pinUvAuthToken.
    /// </summary>
    CTAP2_ERR_UNAUTHORIZED_PERMISSION = 0x40,
    /// <summary>
    /// Other unspecified error.
    /// </summary>
    CTAP1_ERR_OTHER                 = 0x7F,
    /// <summary>
    /// CTAP 2 spec last error.
    /// </summary>
    CTAP2_ERR_SPEC_LAST             = 0xDF,
    /// <summary>
    /// Extension specific error.
    /// </summary>
    CTAP2_ERR_EXTENSION_FIRST       = 0xE0,
    /// <summary>
    /// Extension specific error.
    /// </summary>
    CTAP2_ERR_EXTENSION_LAST        = 0xEF,
    /// <summary>
    /// Vendor specific error.
    /// </summary>
    CTAP2_ERR_VENDOR_FIRST          = 0xF0,
    /// <summary>
    /// Vendor specific error.
    /// </summary>
    CTAP2_ERR_VENDOR_LAST           = 0xFF,
}
