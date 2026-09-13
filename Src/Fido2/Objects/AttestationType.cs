using System;
using System.Text.Json.Serialization;

using Fido2NetLib.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The kind of trust an attestation statement establishes (WebAuthn §6.5.4).
/// </summary>
[JsonConverter(typeof(AttestationTypeConverter))]
public sealed class AttestationType : IEquatable<AttestationType>
{
    /// <summary>
    /// No attestation: the authenticator vouched for nothing.
    /// </summary>
    public static readonly AttestationType None = new("none");
    /// <summary>
    /// Basic attestation: signed with a key the manufacturer provisioned into a batch of authenticators.
    /// </summary>
    public static readonly AttestationType Basic = new("basic");
    /// <summary>
    /// Self attestation: signed with the credential's own private key, so it proves possession but not provenance.
    /// </summary>
    public static readonly AttestationType Self = new("self");
    /// <summary>
    /// Attestation CA: signed with a per-credential key certified by a trusted CA, as TPMs do.
    /// </summary>
    public static readonly AttestationType AttCa = new("attca");
    /// <summary>
    /// Elliptic-curve direct anonymous attestation. Removed from WebAuthn Level 2.
    /// </summary>
    public static readonly AttestationType ECDAA = new("ecdaa");

    private readonly string _value;

    internal AttestationType(string value)
    {
        _value = value;
    }

    /// <summary>
    /// The name of the type.
    /// </summary>
    public string Value => _value;

    /// <summary>
    /// The name of the type.
    /// </summary>
    public static implicit operator string(AttestationType op) { return op.Value; }

    /// <summary>
    /// Two types are equal when their names are.
    /// </summary>
    public static bool operator ==(AttestationType e1, AttestationType e2)
    {
        if (e1 is null)
            return e2 is null;

        return e1.Equals(e2);
    }

    /// <summary>
    /// Two types differ when their names do.
    /// </summary>
    public static bool operator !=(AttestationType e1, AttestationType e2)
    {
        return !(e1 == e2);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is AttestationType other && Equals(other);
    }

    /// <summary>
    /// Two types are equal when their names are.
    /// </summary>
    public bool Equals(AttestationType? other)
    {
        if (ReferenceEquals(this, other))
            return true;

        if (other is null)
            return false;

        return string.Equals(Value, other.Value, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override int GetHashCode() => Value.GetHashCode();

    /// <summary>
    /// The name of the type.
    /// </summary>
    public override string ToString() => Value;

    internal static AttestationType Get(string value)
    {
        return value switch
        {
            "none" => None,
            "basic" => Basic,
            "self" => Self,
            "attca" => AttCa,
            "ecdaa" => ECDAA,
            _ => new AttestationType(value)
        };
    }
}
