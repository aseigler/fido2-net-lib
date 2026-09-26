using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Fido2NetLib.Analyzers;

/// <summary>
/// Flags a <c>MakeNewCredentialParams.IsCredentialIdUniqueToUserCallback</c> assigned a lambda whose body
/// unconditionally returns <see langword="true"/> (e.g. <c>(args, ct) =&gt; Task.FromResult(true)</c>) -- a
/// common development-time stub that, left in place, never enforces WebAuthn Level 3 step 26. See
/// <see cref="DiagnosticDescriptors.TrivialUniquenessCallback"/> (FIDO002).
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class TrivialUniquenessCallbackAnalyzer : DiagnosticAnalyzer
{
    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        [DiagnosticDescriptors.TrivialUniquenessCallback];

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;

        if (assignment.Left is not IdentifierNameSyntax { Identifier.Text: "IsCredentialIdUniqueToUserCallback" } left)
            return;

        if (context.SemanticModel.GetSymbolInfo(left, context.CancellationToken).Symbol is not IPropertySymbol { ContainingType.Name: "MakeNewCredentialParams" } property
            || property.ContainingType.ContainingNamespace?.ToDisplayString() != "Fido2NetLib")
            return;

        if (assignment.Right is not LambdaExpressionSyntax lambda)
            return;

        if (IsAlwaysTrueReturn(lambda.Body))
            context.ReportDiagnostic(Diagnostic.Create(DiagnosticDescriptors.TrivialUniquenessCallback, assignment.Right.GetLocation()));
    }

    private static bool IsAlwaysTrueReturn(SyntaxNode body)
    {
        ExpressionSyntax returnExpression;
        if (body is BlockSyntax block)
        {
            if (block.Statements.Count != 1 || block.Statements[0] is not ReturnStatementSyntax { Expression: { } blockReturn })
                return false;

            returnExpression = blockReturn;
        }
        else if (body is ExpressionSyntax expr)
        {
            returnExpression = expr;
        }
        else
        {
            return false;
        }

        if (returnExpression.IsKind(SyntaxKind.TrueLiteralExpression))
            return true;

        // Task.FromResult(true) (or a same-named static method) with a single literal `true` argument.
        if (returnExpression is InvocationExpressionSyntax invocation
            && invocation.ArgumentList.Arguments.Count == 1
            && invocation.ArgumentList.Arguments[0].Expression is { } argExpr
            && argExpr.IsKind(SyntaxKind.TrueLiteralExpression))
        {
            var methodName = invocation.Expression switch
            {
                MemberAccessExpressionSyntax member => member.Name.Identifier.Text,
                IdentifierNameSyntax id => id.Identifier.Text,
                _ => null
            };

            return methodName == "FromResult";
        }

        return false;
    }
}
