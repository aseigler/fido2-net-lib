#nullable disable

using System.ComponentModel.DataAnnotations;

namespace Fido2NetLib.Objects;

/// <summary>
/// The user account a credential is created for, as the <c>PublicKeyCredentialUserEntity</c> dictionary in the creation options.
/// </summary>
public sealed class PublicKeyCredentialUserEntity
{
    /// <summary>
    /// The user handle: an opaque identifier of 1 to 64 bytes that the relying party chooses. Authentication decisions must be made on this, not on the names. It must not contain personally identifying information.
    /// </summary>
#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
    [MinLength(1)]
    [MaxLength(64)]
    public byte[] Id { get; set; }
#pragma warning restore IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code

    /// <summary>
    /// A human-palatable identifier for the account, such as a username or e-mail address, to tell accounts with similar display names apart.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// A human-palatable name for the account, intended only for display, such as "Alex P. Müller".
    /// </summary>
    public string DisplayName { get; set; }

    /// <summary>
    /// A URL for an image of the user, intended only for display. Removed from WebAuthn Level 2; clients ignore it.
    /// </summary>
    public string Icon { get; set; }
}
