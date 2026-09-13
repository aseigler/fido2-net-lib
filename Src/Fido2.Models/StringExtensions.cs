namespace Fido2NetLib;

/// <summary>
/// Helpers for the strings WebAuthn compares.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Reduces a URL to its origin -- scheme, host and any non-default port -- as a client reports it in the client data. A URI without a recognizable host, such as an Android <c>android:apk-key-hash:</c> origin, is returned unchanged.
    /// </summary>
    /// <exception cref="UriFormatException"><paramref name="origin"/> is not a URI at all.</exception>
    public static string ToFullyQualifiedOrigin(this string origin)
    {
        var uri = new Uri(origin);

        if (UriHostNameType.Unknown != uri.HostNameType)
            return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

        return origin;
    }
}
