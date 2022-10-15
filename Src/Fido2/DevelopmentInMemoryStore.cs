﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Development
{
    public class DevelopmentInMemoryStore
    {
        private readonly ConcurrentDictionary<string, Fido2User> _storedUsers = new();
        private readonly List<CredentialRecord> _credentialRecords = new();

        public Fido2User GetOrAddUser(string username, Func<Fido2User> addCallback)
        {
            return _storedUsers.GetOrAdd(username, addCallback());
        }

        public Fido2User? GetUser(string username)
        {
            _storedUsers.TryGetValue(username, out var user);
            return user;
        }

        public List<CredentialRecord> GetCredentialsByUser(Fido2User user)
        {
            return _credentialRecords.Where(c => c.UserId.AsSpan().SequenceEqual(user.Id)).ToList();
        }

        public CredentialRecord? GetCredentialById(byte[] id)
        {
            return _credentialRecords.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(id));
        }

        public Task<List<CredentialRecord>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_credentialRecords.Where(c => c.UserHandle.AsSpan().SequenceEqual(userHandle)).ToList());
        }

        public void UpdateCounter(byte[] credentialId, uint counter)
        {
            var cred = _credentialRecords.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
            cred.SignCount = counter;
        }

        public void AddCredentialToUser(Fido2User user, CredentialRecord credential)
        {
            credential.UserId = user.Id;
            _credentialRecords.Add(credential);
        }

        public Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
        {
            // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
            var cred = _credentialRecords.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

            if (cred is null)
                return Task.FromResult(new List<Fido2User>());

            return Task.FromResult(_storedUsers.Where(u => u.Value.Id.SequenceEqual(cred.UserId)).Select(u => u.Value).ToList());
        }
    }

#nullable disable

    /// <summary>
    /// In order to implement the algorithms defined in § 7 WebAuthn Relying Party Operations, 
    /// the Relying Party MUST store some properties of registered public key credential sources. 
    /// The credential record struct is an abstraction of these properties stored in a user account. 
    /// A credential record is created during a registration ceremony and used in subsequent authentication ceremonies. 
    /// Relying Parties MAY delete credential records as necessary or when requested by users.
    /// <see cref="https://w3c.github.io/webauthn/#credential-record"/>
    /// </summary>
    public class CredentialRecord
    {
        /// <summary>
        /// The type of the public key credential source.
        /// </summary>
        public PublicKeyCredentialType Type { get; set; } = PublicKeyCredentialType.PublicKey;
        /// <summary>
        /// The Credential ID of the public key credential source.
        /// </summary>
        public byte[] Id { get; set; }
        /// <summary>
        /// The credential public key of the public key credential source.
        /// </summary>
        public byte[] PublicKey { get; set; }
        /// <summary>
        /// The latest value of the signature counter in the authenticator data from any ceremony using the public key credential source.
        /// </summary>
        public uint SignCount { get; set; }
        /// <summary>
        /// The value returned from getTransports() when the public key credential source was registered.
        /// </summary>
        public AuthenticatorTransport[] Transports { get; set; }
        /// <summary>
        /// The value of the BE flag when the public key credential source was created.
        /// </summary>
        public bool BE { get; set; }
        /// <summary>
        /// The latest value of the BS flag in the authenticator data from any ceremony using the public key credential source.
        /// </summary>
        public bool BS { get; set; }
        /// <summary>
        /// The value of the attestationObject attribute when the public key credential source was registered. 
        /// Storing this enables the Relying Party to reference the credential's attestation statement at a later time.
        /// </summary>
        public byte[] AttestationObject { get; set; }
        /// <summary>
        /// The value of the clientDataJSON attribute when the public key credential source was registered. 
        /// Storing this in combination with the above attestationObject item enables the Relying Party to re-verify the attestation signature at a later time.
        /// </summary>
        public byte[] AttestationClientDataJSON { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public List<byte[]> DevicePublicKeys { get; set; }

        public byte[] UserId { get; set; }
        public PublicKeyCredentialDescriptor Descriptor { get; set; }
        public byte[] UserHandle { get; set; }
        public uint SignatureCounter => SignCount;
        public string CredType { get; set; }
        public DateTime RegDate { get; set; }
        public Guid AaGuid { get; set; }
    }
}
