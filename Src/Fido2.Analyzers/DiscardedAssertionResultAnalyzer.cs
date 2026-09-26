using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Fido2NetLib.Analyzers;

/// <summary>
/// Flags a <c>MakeAssertionAsync</c> call whose <c>VerifyAssertionResult</c> is thrown away -- awaited as a bare
/// statement (with or without <c>ConfigureAwait</c>), assigned to the discard <c>_</c>, waited on synchronously with
/// <c>GetAwaiter().GetResult()</c>, <c>.Result</c> or <c>.Wait()</c>, or not awaited at all -- so the caller has no way to
/// persist the updated sign counter, backup state and UV that WebAuthn Level 3 step 24 requires. See
/// <see cref="DiagnosticDescriptors.DiscardedAssertionResult"/> (FIDO001).
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class DiscardedAssertionResultAnalyzer : DiagnosticAnalyzer
{
    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        [DiagnosticDescriptors.DiscardedAssertionResult];

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;

        if (!IsMakeAssertionAsync(invocation.TargetMethod))
            return;

        // Follow the value up through whatever only unwraps the task, to where it is finally used.
        IOperation value = invocation;
        while (value.Parent is { } parent && Unwraps(parent, value))
            value = parent;

        var discarded = value.Parent switch
        {
            IExpressionStatementOperation => true,
            ISimpleAssignmentOperation { Target: IDiscardOperation } assignment => assignment.Parent is IExpressionStatementOperation,
            _ => false
        };

        if (discarded)
            context.ReportDiagnostic(Diagnostic.Create(DiagnosticDescriptors.DiscardedAssertionResult, value.Syntax.GetLocation()));
    }

    private static bool IsMakeAssertionAsync(IMethodSymbol method)
    {
        if (method.Name != "MakeAssertionAsync")
            return false;

        var containingType = method.ContainingType;
        if (containingType?.ContainingNamespace?.ToDisplayString() != "Fido2NetLib")
            return false;

        return containingType.Name is "Fido2" or "IFido2";
    }

    /// <summary>
    /// Whether <paramref name="parent"/> just passes the task (or its result) along: <c>await</c>,
    /// <c>ConfigureAwait</c>, <c>GetAwaiter</c>, <c>GetResult</c>, <c>Wait</c>, or <c>.Result</c> on it.
    /// </summary>
    private static bool Unwraps(IOperation parent, IOperation value) => parent switch
    {
        IAwaitOperation => true,
        IConversionOperation { IsImplicit: true } => true,
        IInvocationOperation call when call.Instance == value => call.TargetMethod.Name is "ConfigureAwait" or "GetAwaiter" or "GetResult" or "Wait",
        IPropertyReferenceOperation property when property.Instance == value => property.Property.Name == "Result",
        _ => false
    };
}
