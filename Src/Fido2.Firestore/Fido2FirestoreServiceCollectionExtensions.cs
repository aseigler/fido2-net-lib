using Fido2NetLib;
using Fido2NetLib.Firestore;

using Google.Cloud.Firestore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the Google Cloud Firestore <see cref="ICredentialStore"/>.
/// </summary>
public static class Fido2FirestoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="FirestoreCredentialStore"/> as the scoped <see cref="ICredentialStore"/>, over a
    /// <see cref="FirestoreDb"/> resolved from the container (register one separately, e.g. with
    /// <c>FirestoreDb.Create(projectId)</c> as a singleton).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The collection names to use; defaults are used when omitted.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddFido2FirestoreStore(this IServiceCollection services, FirestoreCredentialStoreOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        options ??= new FirestoreCredentialStoreOptions();

        services.AddScoped<ICredentialStore>(sp => new FirestoreCredentialStore(sp.GetRequiredService<FirestoreDb>(), options));
        return services;
    }
}
