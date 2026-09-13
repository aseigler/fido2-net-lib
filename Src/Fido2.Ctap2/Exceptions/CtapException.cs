namespace Fido2NetLib.Ctap2.Exceptions;

/// <summary>
/// Thrown when an authenticator answers a command with an error status.
/// </summary>
public sealed class CtapException : Exception
{
    /// <summary>
    /// Initializes the exception with the status the authenticator returned.
    /// </summary>
    public CtapException(CtapStatusCode status)
        : base(status.ToString()) { }
}
