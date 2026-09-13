namespace Fido2NetLib;

/// <summary>
/// Thrown when authenticator metadata cannot be fetched, verified or parsed.
/// </summary>
public class Fido2MetadataException : Exception
{
    /// <summary>
    /// Initializes the exception with no message.
    /// </summary>
    public Fido2MetadataException()
    {
    }

    /// <summary>
    /// Initializes the exception with a message.
    /// </summary>
    public Fido2MetadataException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes the exception with a message and the exception that caused it.
    /// </summary>
    public Fido2MetadataException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
