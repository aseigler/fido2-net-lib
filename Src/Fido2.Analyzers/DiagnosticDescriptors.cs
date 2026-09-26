using Microsoft.CodeAnalysis;

namespace Fido2NetLib.Analyzers;

internal static class DiagnosticDescriptors
{
    public static readonly DiagnosticDescriptor DiscardedAssertionResult = new(
        id: "FIDO001",
        title: "MakeAssertionAsync result is discarded",
        messageFormat: "The result of MakeAssertionAsync is not used, so the updated sign counter and backup state can't be persisted",
        category: "Fido2NetLib.Usage",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "After a successful assertion, WebAuthn Level 3 step 24 requires storing the credential " +
            "record's updated signature counter (and backup state); an authenticator that later reuses a stale " +
            "counter would otherwise never be caught as cloned. Capture the result and persist its SignCount, " +
            "IsBackedUp, and IsUserVerified fields.");

    public static readonly DiagnosticDescriptor TrivialUniquenessCallback = new(
        id: "FIDO002",
        title: "IsCredentialIdUniqueToUserCallback always reports the credential ID as unique",
        messageFormat: "This callback always returns true, so a credential ID that is already registered will never be rejected",
        category: "Fido2NetLib.Usage",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "WebAuthn Level 3 step 26 requires rejecting registration when the credential ID is " +
            "already registered to any user. A callback that unconditionally returns true (a common " +
            "development-time stub) never enforces this, letting an attacker who obtained a credential ID and " +
            "public key register a victim's credential as their own.");
}
