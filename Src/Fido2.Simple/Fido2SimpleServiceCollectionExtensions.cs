using Fido2NetLib;
using Fido2NetLib.Simple;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers <see cref="ISimpleFido2Authentication"/>.
/// </summary>
public static class Fido2SimpleServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="SimpleFido2Authentication"/> as the scoped <see cref="ISimpleFido2Authentication"/>,
    /// over an <see cref="IFido2"/> and an <see cref="ICredentialStore"/> registered separately (e.g. with
    /// <c>AddFido2()</c> and one of the <c>AddFido2*Store()</c> extensions).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2Simple(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<ISimpleFido2Authentication, SimpleFido2Authentication>();
        return services;
    }
}
