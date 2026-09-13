using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// The rgbPaletteEntry is an RGB three-sample tuple palette entry.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#rgbpaletteentry-dictionary"/>
/// </remarks>
public readonly struct RgbPaletteEntry : IEquatable<RgbPaletteEntry>
{
    /// <summary>
    /// Initializes an entry from its red, green and blue components.
    /// </summary>
    [JsonConstructor]
    public RgbPaletteEntry(ushort r, ushort g, ushort b)
    {
        R = r;
        G = g;
        B = b;
    }

    /// <summary>
    /// Gets or sets the red channel sample value.
    /// </summary>
    [JsonPropertyName("r")]
    public ushort R { get; }

    /// <summary>
    /// Gets or sets the green channel sample value.
    /// </summary>
    [JsonPropertyName("g")]
    public ushort G { get; }

    /// <summary>
    /// Gets or sets the blue channel sample value.
    /// </summary>
    [JsonPropertyName("b")]
    public ushort B { get; }

    /// <summary>
    /// Two entries are equal when all three components match.
    /// </summary>
    public bool Equals(RgbPaletteEntry other)
    {
        return R == other.R
            && G == other.G
            && B == other.B;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is RgbPaletteEntry other && Equals(other);
    }

    /// <summary>
    /// Two entries are equal when all three components match.
    /// </summary>
    public static bool operator ==(RgbPaletteEntry left, RgbPaletteEntry right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Two entries differ when any component differs.
    /// </summary>
    public static bool operator !=(RgbPaletteEntry left, RgbPaletteEntry right)
    {
        return !left.Equals(right);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(R, G, B);
    }
}
