using Fido2NetLib.Exceptions;

namespace Fido2NetLib;

/// <summary>
/// Thrown when a registration or authentication response fails verification. <see cref="Code"/> says at which step.
/// </summary>
public class Fido2VerificationException : Exception
{
    /// <summary>
    /// Initializes the exception with no message and <see cref="Fido2ErrorCode.Unknown"/>.
    /// </summary>
    public Fido2VerificationException()
    {
    }

    /// <summary>
    /// Initializes the exception with a message and <see cref="Fido2ErrorCode.Unknown"/>.
    /// </summary>
    public Fido2VerificationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes the exception with the failed step and a message.
    /// </summary>
    public Fido2VerificationException(Fido2ErrorCode code, string message) : base(message)
    {
        Code = code;
    }

    /// <summary>
    /// Initializes the exception with the failed step, a message and the exception that caused it.
    /// </summary>
    public Fido2VerificationException(Fido2ErrorCode code, string message, Exception innerException) : base(message, innerException)
    {
        Code = code;
    }

    /// <summary>
    /// Initializes the exception with a message, the exception that caused it, and <see cref="Fido2ErrorCode.Unknown"/>.
    /// </summary>
    public Fido2VerificationException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// The verification step that failed.
    /// </summary>
    public Fido2ErrorCode Code { get; }
}
