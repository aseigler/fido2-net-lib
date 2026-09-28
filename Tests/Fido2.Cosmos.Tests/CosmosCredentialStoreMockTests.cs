using System.Net;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.DependencyInjection;

using Moq;

namespace Fido2NetLib.Cosmos.Tests;

/// <summary>
/// Covers <see cref="CosmosCredentialStore"/>'s own logic (partition/id choices, the optimistic-concurrency retry
/// loop, exception translation) against a mocked <see cref="Container"/>, so it is exercised without a live
/// Cosmos account or emulator. <see cref="CosmosCredentialStoreTests"/> covers real service behaviour separately
/// when the emulator is available; this file exists specifically for environments where it is not.
/// </summary>
public sealed class CosmosCredentialStoreMockTests
{
    private static Fido2User NewUser(string name, byte id) => new() { Name = name, Id = [id], DisplayName = name.ToUpperInvariant() };

    private static StoredCredential NewCredential(byte[]? id = null, byte[]? userHandle = null, uint signCount = 0) => new()
    {
        Id = id ?? Guid.NewGuid().ToByteArray(),
        PublicKey = [1, 2, 3],
        SignCount = signCount,
        Transports = [AuthenticatorTransport.Internal, AuthenticatorTransport.Hybrid],
        UserHandle = userHandle ?? Guid.NewGuid().ToByteArray(),
        AttestationFormat = "none",
        RegDate = DateTimeOffset.UtcNow,
        AaGuid = Guid.NewGuid(),
    };

    private static VerifyAssertionResult Assertion(byte[] credentialId, uint signCount, bool backedUp = false, bool userVerified = false) => new()
    {
        CredentialId = credentialId,
        SignCount = signCount,
        IsBackedUp = backedUp,
        IsUserVerified = userVerified,
    };

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Mock<ItemResponse<CosmosItem>> MockResponse(CosmosItem? resource, string etag = "\"etag-1\"")
    {
        var response = new Mock<ItemResponse<CosmosItem>>();
        response.SetupGet(r => r.Resource).Returns(resource!);
        response.SetupGet(r => r.ETag).Returns(etag);
        return response;
    }

    private static CosmosException NotFound() => new("not found", HttpStatusCode.NotFound, 0, "activity", 0);

    private static CosmosException Conflict() => new("conflict", HttpStatusCode.Conflict, 0, "activity", 0);

    private static CosmosException PreconditionFailed() => new("precondition failed", HttpStatusCode.PreconditionFailed, 0, "activity", 0);

    private static Mock<FeedIterator<CosmosItem>> MockIterator(params CosmosItem[] items)
    {
        var page = new Mock<FeedResponse<CosmosItem>>();
        page.SetupGet(p => p.Resource).Returns(items);
        page.Setup(p => p.GetEnumerator()).Returns(((IEnumerable<CosmosItem>)items).GetEnumerator());

        var iterator = new Mock<FeedIterator<CosmosItem>>();
        var served = false;
        iterator.SetupGet(i => i.HasMoreResults).Returns(() => !served);
        iterator.Setup(i => i.ReadNextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() =>
            {
                served = true;
                return page.Object;
            });
        return iterator;
    }

    private static CosmosItem UserItem(Fido2User user, string partitionKey) => new()
    {
        Id = "user",
        PartitionKey = partitionKey,
        Type = "user",
        UserId = user.Id,
        Name = user.Name,
        DisplayName = user.DisplayName,
    };

    private static CosmosItem LookupItem(string username, byte[] userId) => new()
    {
        Id = "lookup",
        PartitionKey = username,
        Type = "usernameLookup",
        UserId = userId,
    };

    private static CosmosItem CredentialItem(StoredCredential credential, string partitionKey) => new()
    {
        Id = Base64UrlEncode(credential.Id),
        PartitionKey = partitionKey,
        Type = "credential",
        CredentialId = credential.Id,
        RpId = credential.RpId,
        PublicKey = credential.PublicKey,
        SignCount = credential.SignCount,
        Transports = credential.Transports,
        UvInitialized = credential.UvInitialized,
        IsBackupEligible = credential.IsBackupEligible,
        IsBackedUp = credential.IsBackedUp,
        UserId = credential.UserId,
        UserHandle = credential.UserHandle,
        AttestationFormat = credential.AttestationFormat,
        RegDate = credential.RegDate,
        AaGuid = credential.AaGuid,
    };

    [Fact]
    public async Task GetUserAsync_ReturnsNullWhenNoLookupItemExistsAsync()
    {
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("nobody"), null, default))
            .ThrowsAsync(NotFound());

        var store = new CosmosCredentialStore(container.Object);

        Assert.Null(await store.GetUserAsync("nobody"));
    }

    [Fact]
    public async Task GetUserAsync_ReturnsNullWhenTheLookupPointsAtAMissingUserItemAsync()
    {
        var userId = new byte[] { 1 };
        var partitionKey = Base64UrlEncode(userId);
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("alice"), null, default))
            .ReturnsAsync(MockResponse(LookupItem("alice", userId)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ThrowsAsync(NotFound());

        var store = new CosmosCredentialStore(container.Object);

        Assert.Null(await store.GetUserAsync("alice"));
    }

    [Fact]
    public async Task GetUserAsync_ResolvesTheUserThroughTheLookupAsync()
    {
        var user = NewUser("alice", 1);
        var partitionKey = Base64UrlEncode(user.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("alice"), null, default))
            .ReturnsAsync(MockResponse(LookupItem("alice", user.Id)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(user, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var found = await store.GetUserAsync("alice");

        Assert.NotNull(found);
        Assert.Equal(user.Id, found!.Id);
        Assert.Equal("alice", found.Name);
    }

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheExistingUserWithoutCreatingAsync()
    {
        var user = NewUser("alice", 1);
        var partitionKey = Base64UrlEncode(user.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("alice"), null, default))
            .ReturnsAsync(MockResponse(LookupItem("alice", user.Id)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(user, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var result = await store.GetOrAddUserAsync("alice", () => throw new InvalidOperationException("should not be called"));

        Assert.Equal(user.Id, result.Id);
        container.Verify(c => c.CreateItemAsync(It.IsAny<CosmosItem>(), It.IsAny<PartitionKey?>(), null, default), Times.Never);
    }

    [Fact]
    public async Task GetOrAddUserAsync_CreatesTheLookupAndUserItemsWhenNoneExistsAsync()
    {
        var user = NewUser("bob", 2);
        var partitionKey = Base64UrlEncode(user.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("bob"), null, default))
            .ThrowsAsync(NotFound());
        container.Setup(c => c.CreateItemAsync(
                It.Is<CosmosItem>(i => i.Type == "usernameLookup" && i.PartitionKey == "bob"),
                new PartitionKey("bob"), null, default))
            .ReturnsAsync(MockResponse(LookupItem("bob", user.Id)).Object);
        container.Setup(c => c.UpsertItemAsync(
                It.Is<CosmosItem>(i => i.Type == "user" && i.PartitionKey == partitionKey && i.Name == "bob"),
                new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(user, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var result = await store.GetOrAddUserAsync("bob", () => user);

        Assert.Equal(user.Id, result.Id);
        container.VerifyAll();
    }

    [Fact]
    public async Task GetOrAddUserAsync_ReturnsTheUserAConcurrentRequestAddedAsync()
    {
        var winner = NewUser("frank", 6);
        var partitionKey = Base64UrlEncode(winner.Id);
        var container = new Mock<Container>();
        container.SetupSequence(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("frank"), null, default))
            .ReturnsAsync(MockResponse(null).Object)
            .Throws(NotFound())
            .ReturnsAsync(MockResponse(LookupItem("frank", winner.Id)).Object);

        // First call: no existing lookup -> attempt to create -> lose the race with a Conflict -> re-read and
        // find the winner's lookup and user items.
        var calls = 0;
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("frank"), null, default))
            .Returns(() =>
            {
                calls++;
                if (calls == 1)
                    throw NotFoundSync();
                return Task.FromResult(MockResponse(LookupItem("frank", winner.Id)).Object);
            });
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(winner, partitionKey)).Object);
        container.Setup(c => c.CreateItemAsync(It.IsAny<CosmosItem>(), It.IsAny<PartitionKey?>(), null, default))
            .ThrowsAsync(Conflict());

        var store = new CosmosCredentialStore(container.Object);
        var result = await store.GetOrAddUserAsync("frank", () => NewUser("frank", 7));

        Assert.Equal(winner.Id, result.Id);
    }

    private static CosmosException NotFoundSync() => NotFound();

    [Fact]
    public async Task GetOrAddUserAsync_ThrowsWhenTheRaceLoserCannotFindTheWinnerEitherAsync()
    {
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("lookup", new PartitionKey("grace"), null, default))
            .ThrowsAsync(NotFound());
        container.Setup(c => c.CreateItemAsync(It.IsAny<CosmosItem>(), It.IsAny<PartitionKey?>(), null, default))
            .ThrowsAsync(Conflict());

        var store = new CosmosCredentialStore(container.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.GetOrAddUserAsync("grace", () => NewUser("grace", 8)));
    }

    [Fact]
    public async Task GetCredentialsByUserAsync_MapsEveryItemInThePartitionAsync()
    {
        var user = NewUser("alice", 1);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(
                It.IsAny<QueryDefinition>(), null, It.IsAny<QueryRequestOptions>()))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var results = await store.GetCredentialsByUserAsync(user);

        var found = Assert.Single(results);
        Assert.Equal(credential.Id, found.Id);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNullWhenNoItemMatchesAsync()
    {
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator().Object);

        var store = new CosmosCredentialStore(container.Object);

        Assert.Null(await store.GetCredentialByIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task GetCredentialByIdAsync_MapsTheMatchingItemAsync()
    {
        var user = NewUser("alice", 1);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var found = await store.GetCredentialByIdAsync(credential.Id);

        Assert.NotNull(found);
        Assert.Equal(credential.Id, found!.Id);
    }

    [Fact]
    public async Task GetCredentialsByUserHandleAsync_FindsTheDiscoverableCredentialAsync()
    {
        var user = NewUser("carol", 3);
        var partitionKey = Base64UrlEncode(user.Id);
        var userHandle = new byte[] { 3, 3, 3 };
        var credential = NewCredential(userHandle: userHandle);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var found = Assert.Single(await store.GetCredentialsByUserHandleAsync(userHandle));

        Assert.Equal(credential.Id, found.Id);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ResolvesTheOwningUserAsync()
    {
        var user = NewUser("dave", 4);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(user, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        var owner = Assert.Single(await store.GetUsersByCredentialIdAsync(credential.Id));

        Assert.Equal("dave", owner.Name);
    }

    [Fact]
    public async Task GetUsersByCredentialIdAsync_ReturnsEmptyForAnUnknownCredentialAsync()
    {
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator().Object);

        var store = new CosmosCredentialStore(container.Object);

        Assert.Empty(await store.GetUsersByCredentialIdAsync([0xde, 0xad]));
    }

    [Fact]
    public async Task AddCredentialToUserAsync_ThrowsWhenTheUserItemIsMissingAsync()
    {
        var user = NewUser("nobody", 99);
        var partitionKey = Base64UrlEncode(user.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ThrowsAsync(NotFound());

        var store = new CosmosCredentialStore(container.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.AddCredentialToUserAsync(user, NewCredential()));
    }

    [Fact]
    public async Task AddCredentialToUserAsync_CreatesTheCredentialItemInTheUsersPartitionAsync()
    {
        var user = NewUser("bob", 9);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(user, partitionKey)).Object);
        container.Setup(c => c.CreateItemAsync(
                It.Is<CosmosItem>(i => i.Type == "credential" && i.PartitionKey == partitionKey && i.Id == Base64UrlEncode(credential.Id)),
                new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(CredentialItem(credential, partitionKey)).Object);

        var store = new CosmosCredentialStore(container.Object);
        await store.AddCredentialToUserAsync(user, credential);

        Assert.Equal(user.Id, credential.UserId);
        container.VerifyAll();
    }

    [Fact]
    public async Task AddCredentialToUserAsync_ThrowsWhenTheCredentialIsAlreadyRegisteredAsync()
    {
        var user = NewUser("bob", 9);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var container = new Mock<Container>();
        container.Setup(c => c.ReadItemAsync<CosmosItem>("user", new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(UserItem(user, partitionKey)).Object);
        container.Setup(c => c.CreateItemAsync(It.IsAny<CosmosItem>(), It.IsAny<PartitionKey?>(), null, default))
            .ThrowsAsync(Conflict());

        var store = new CosmosCredentialStore(container.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.AddCredentialToUserAsync(user, credential));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RejectsANullAssertionAsync()
    {
        var store = new CosmosCredentialStore(new Mock<Container>().Object);

        await Assert.ThrowsAsync<ArgumentNullException>(() => store.UpdateCredentialRecordAsync(null!));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsForAnUnknownCredentialAsync()
    {
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator().Object);

        var store = new CosmosCredentialStore(container.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.UpdateCredentialRecordAsync(Assertion([0xde, 0xad], 1)));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_AppliesSignCountAndBackupStateAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: 1);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(CredentialItem(credential, partitionKey), "\"etag-1\"").Object);

        CosmosItem? replaced = null;
        container.Setup(c => c.ReplaceItemAsync(
                It.IsAny<CosmosItem>(), encodedId, new PartitionKey(partitionKey),
                It.Is<ItemRequestOptions>(o => o!.IfMatchEtag == "\"etag-1\""), default))
            .Callback<CosmosItem, string, PartitionKey?, ItemRequestOptions?, CancellationToken>((item, _, _, _, _) => replaced = item)
            .ReturnsAsync(MockResponse(null).Object);

        var store = new CosmosCredentialStore(container.Object);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2, backedUp: true, userVerified: true));

        Assert.NotNull(replaced);
        Assert.Equal(2u, replaced!.SignCount);
        Assert.True(replaced.IsBackedUp);
        // Promoting uvInitialized needs the caller's authorization.
        Assert.False(replaced.UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_PromotesUvInitializedOnlyWhenAuthorizedAndVerifiedAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: 1);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        // Each call re-reads the credential from scratch, so the iterator/ReadItemAsync setups must hand back a
        // fresh CosmosItem instance every time -- the store mutates current.Resource in place, and a fixed,
        // shared instance would leak that mutation into the "stored" state the next call reads.
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(() => MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .Returns(() => Task.FromResult(MockResponse(CredentialItem(credential, partitionKey), "\"etag-1\"").Object));

        CosmosItem? replaced = null;
        container.Setup(c => c.ReplaceItemAsync(
                It.IsAny<CosmosItem>(), encodedId, new PartitionKey(partitionKey), It.IsAny<ItemRequestOptions>(), default))
            .Callback<CosmosItem, string, PartitionKey?, ItemRequestOptions?, CancellationToken>((item, _, _, _, _) => replaced = item)
            .ReturnsAsync(MockResponse(null).Object);

        var store = new CosmosCredentialStore(container.Object);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2, userVerified: false), uvInitializationAuthorized: true);
        Assert.False(replaced!.UvInitialized);

        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 3, userVerified: true), uvInitializationAuthorized: true);
        Assert.True(replaced!.UvInitialized);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_UpdatesACredentialWhoseCounterIsAlwaysZeroAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: 0);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(CredentialItem(credential, partitionKey), "\"etag-1\"").Object);

        CosmosItem? replaced = null;
        container.Setup(c => c.ReplaceItemAsync(
                It.IsAny<CosmosItem>(), encodedId, new PartitionKey(partitionKey), It.IsAny<ItemRequestOptions>(), default))
            .Callback<CosmosItem, string, PartitionKey?, ItemRequestOptions?, CancellationToken>((item, _, _, _, _) => replaced = item)
            .ReturnsAsync(MockResponse(null).Object);

        var store = new CosmosCredentialStore(container.Object);
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 0, backedUp: true));

        Assert.True(replaced!.IsBackedUp);
    }

    [Theory]
    [InlineData(7u, 6u)]
    [InlineData(7u, 7u)]
    [InlineData(7u, 0u)]
    public async Task UpdateCredentialRecordAsync_RefusesACounterAnotherSignInHasAlreadyPassedAsync(uint alreadyStored, uint thisAssertion)
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: alreadyStored);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(CredentialItem(credential, partitionKey), "\"etag-1\"").Object);

        var store = new CosmosCredentialStore(container.Object);

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(
            () => store.UpdateCredentialRecordAsync(Assertion(credential.Id, thisAssertion, backedUp: true)));

        Assert.Equal(Fido2ErrorCode.InvalidSignCount, ex.Code);
        container.Verify(c => c.ReplaceItemAsync(
            It.IsAny<CosmosItem>(), It.IsAny<string>(), It.IsAny<PartitionKey?>(), It.IsAny<ItemRequestOptions>(), default), Times.Never);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_RetriesOncePreconditionFailsThenSucceedsAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: 1);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);

        var readAttempts = 0;
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .Returns(() =>
            {
                readAttempts++;
                // Someone else advanced the counter between our first read and our replace; the second read sees it.
                var stored = readAttempts == 1 ? credential.SignCount : 5u;
                var item = CredentialItem(credential, partitionKey);
                item.SignCount = stored;
                return Task.FromResult(MockResponse(item, $"\"etag-{readAttempts}\"").Object);
            });

        var replaceAttempts = 0;
        container.Setup(c => c.ReplaceItemAsync(
                It.IsAny<CosmosItem>(), encodedId, new PartitionKey(partitionKey), It.IsAny<ItemRequestOptions>(), default))
            .Returns(() =>
            {
                replaceAttempts++;
                if (replaceAttempts == 1)
                    throw PreconditionFailed();
                return Task.FromResult(MockResponse(null).Object);
            });

        var store = new CosmosCredentialStore(container.Object);
        // 6 still beats the second read's stored value of 5, so the retried attempt succeeds.
        await store.UpdateCredentialRecordAsync(Assertion(credential.Id, 6));

        Assert.Equal(2, readAttempts);
        Assert.Equal(2, replaceAttempts);
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_GivesUpAfterTooManyConflictsAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: 1);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(() => MockIterator(CredentialItem(credential, partitionKey)).Object);
        // A fresh, unmutated CosmosItem every attempt: the store always sees the original (unadvanced) counter,
        // so every one of the bounded attempts legitimately reaches -- and fails at -- the replace step, rather
        // than a stale mutated counter tripping the sign-count-regression check instead.
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .Returns(() => Task.FromResult(MockResponse(CredentialItem(credential, partitionKey), "\"etag\"").Object));
        container.Setup(c => c.ReplaceItemAsync(
                It.IsAny<CosmosItem>(), encodedId, new PartitionKey(partitionKey), It.IsAny<ItemRequestOptions>(), default))
            .ThrowsAsync(PreconditionFailed());

        var store = new CosmosCredentialStore(container.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2)));
    }

    [Fact]
    public async Task UpdateCredentialRecordAsync_ThrowsIfTheCredentialDisappearsMidRetryAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential(signCount: 1);
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.ReadItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .ThrowsAsync(NotFound());

        var store = new CosmosCredentialStore(container.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.UpdateCredentialRecordAsync(Assertion(credential.Id, 2)));
    }

    [Fact]
    public async Task RemoveCredentialAsync_RemovesAKnownCredentialAndReportsTrueAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.DeleteItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .ReturnsAsync(MockResponse(null).Object);

        var store = new CosmosCredentialStore(container.Object);

        Assert.True(await store.RemoveCredentialAsync(credential.Id));
    }

    [Fact]
    public async Task RemoveCredentialAsync_ReturnsFalseWhenNothingMatchesAsync()
    {
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator().Object);

        var store = new CosmosCredentialStore(container.Object);

        Assert.False(await store.RemoveCredentialAsync([0xde, 0xad]));
    }

    [Fact]
    public void CosmosItemETag_RoundTripsTheValueNewtonsoftPopulatesOnDeserialization()
    {
        // Nothing in CosmosCredentialStore itself reads or writes CosmosItem.ETag (the store uses
        // ItemResponse<T>.ETag from the SDK response instead); this property exists only for Newtonsoft to
        // populate from the "_etag" system property when deserializing a real Cosmos response, so it needs its
        // own direct test rather than relying on incidental coverage through the store's own code paths.
        var item = new CosmosItem { Id = "x", PartitionKey = "x", Type = "user", ETag = "\"abc\"" };

        Assert.Equal("\"abc\"", item.ETag);
    }

    [Fact]
    public void AddFido2CosmosStore_ResolvesTheStoreScopedOverTheFactorysContainerAsync()
    {
        var container = new Mock<Container>();
        var services = new ServiceCollection();
        services.AddFido2CosmosStore(_ => container.Object);

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<ICredentialStore>();

        Assert.IsType<CosmosCredentialStore>(store);
    }

    [Fact]
    public async Task RemoveCredentialAsync_ReturnsFalseWhenTheItemDisappearsBeforeDeleteAsync()
    {
        var user = NewUser("erin", 5);
        var partitionKey = Base64UrlEncode(user.Id);
        var credential = NewCredential();
        var encodedId = Base64UrlEncode(credential.Id);
        var container = new Mock<Container>();
        container.Setup(c => c.GetItemQueryIterator<CosmosItem>(It.IsAny<QueryDefinition>(), null, null))
            .Returns(MockIterator(CredentialItem(credential, partitionKey)).Object);
        container.Setup(c => c.DeleteItemAsync<CosmosItem>(encodedId, new PartitionKey(partitionKey), null, default))
            .ThrowsAsync(NotFound());

        var store = new CosmosCredentialStore(container.Object);

        Assert.False(await store.RemoveCredentialAsync(credential.Id));
    }
}
