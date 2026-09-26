using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson;

namespace Fido2NetLib.MongoDb;

/// <summary>
/// Registers the BSON class maps <see cref="MongoDbCredentialStore"/> depends on: <see cref="Fido2User.Id"/> and
/// <see cref="StoredCredential.Id"/> as each document's <c>_id</c>, and an explicit <see cref="GuidRepresentation"/>
/// for <see cref="StoredCredential.AaGuid"/> so its serialized form does not depend on driver-wide configuration.
/// </summary>
internal static class Fido2MongoDbClassMaps
{
    private static readonly object _gate = new();
    private static bool _registered;

    /// <summary>
    /// Registers the class maps if they have not been registered yet. Safe to call repeatedly and concurrently.
    /// </summary>
    public static void EnsureRegistered()
    {
        if (_registered)
        {
            return;
        }

        lock (_gate)
        {
            if (_registered)
            {
                return;
            }

            if (!BsonClassMap.IsClassMapRegistered(typeof(Fido2User)))
            {
                BsonClassMap.RegisterClassMap<Fido2User>(map =>
                {
                    map.AutoMap();
                    map.MapIdMember(u => u.Id);
                });
            }

            if (!BsonClassMap.IsClassMapRegistered(typeof(StoredCredential)))
            {
                BsonClassMap.RegisterClassMap<StoredCredential>(map =>
                {
                    map.AutoMap();
                    map.MapIdMember(c => c.Id);
                    map.MapMember(c => c.AaGuid).SetSerializer(new GuidSerializer(GuidRepresentation.Standard));
                    // A fixed representation, rather than whatever the driver defaults to, so the pipeline update in
                    // MongoDbCredentialStore.UpdateCredentialRecordAsync can write a literal of a known BSON type.
                    map.MapMember(c => c.SignCount).SetSerializer(new UInt32Serializer(BsonType.Int64));
                });
            }

            _registered = true;
        }
    }
}
