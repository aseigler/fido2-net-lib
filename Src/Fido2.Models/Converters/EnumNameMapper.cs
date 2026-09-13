using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Maps between the members of <typeparamref name="TEnum"/> and the names their <see cref="System.Runtime.Serialization.EnumMemberAttribute"/> declares, as the WebAuthn and FIDO specifications spell them on the wire.
/// </summary>
/// <typeparam name="TEnum">An enum whose members carry <see cref="System.Runtime.Serialization.EnumMemberAttribute"/>.</typeparam>
public static class EnumNameMapper<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>
    where TEnum : struct, Enum
{
    private static readonly FrozenDictionary<TEnum, string> s_valueToNames = GetIdToNameMap();
    private static readonly FrozenDictionary<string, TEnum> s_namesToValues = Invert(s_valueToNames);

    private static FrozenDictionary<string, TEnum> Invert(FrozenDictionary<TEnum, string> map)
    {
        var items = new KeyValuePair<string, TEnum>[map.Count];
        int i = 0;

        foreach (var item in map)
        {
            items[i++] = new(item.Value, item.Key);
        }

        return items.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Finds the member whose wire name is <paramref name="name"/>, ignoring case.
    /// </summary>
    public static bool TryGetValue(string name, out TEnum value)
    {
        return s_namesToValues.TryGetValue(name, out value);
    }

    /// <summary>
    /// The wire name of <paramref name="value"/>.
    /// </summary>
    public static string GetName(TEnum value)
    {
        return s_valueToNames[value];
    }

    /// <summary>
    /// Every wire name the enum declares.
    /// </summary>
    public static IEnumerable<string> GetNames()
    {
        return s_namesToValues.Keys;
    }

    private static FrozenDictionary<TEnum, string> GetIdToNameMap()
    {
        List<KeyValuePair<TEnum, string>> items = [];

        foreach (var field in typeof(TEnum).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
#if NET9_0_OR_GREATER
            var description = field.GetCustomAttribute<JsonStringEnumMemberNameAttribute>(false)?.Name;
#else
            var description = field.GetCustomAttribute<EnumMemberAttribute>(false)?.Value;
#endif

            var value = (TEnum)field.GetValue(null)!;

            items.Add(new(value, description ?? value.ToString()));
        }

        return items.ToFrozenDictionary();
    }
}
