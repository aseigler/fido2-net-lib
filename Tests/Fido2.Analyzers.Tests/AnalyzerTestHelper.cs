using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Test;

/// <summary>
/// Compiles a test source against the real Fido2 and Fido2.Models assemblies -- so a renamed type, method or delegate
/// in the library breaks these tests instead of silently blinding the analyzers -- and runs one analyzer over it.
/// </summary>
internal static class AnalyzerTestHelper
{
    public static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(DiagnosticAnalyzer analyzer, string source)
    {
        var compilation = CSharpCompilation.Create(
            "Fido2AnalyzerTestAssembly",
            [CSharpSyntaxTree.ParseText(source)],
            GetReferences(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Disable));

        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        if (errors.Count > 0)
            throw new InvalidOperationException("Test source failed to compile: " + string.Join("\n", errors));

        return await compilation.WithAnalyzers([analyzer]).GetAnalyzerDiagnosticsAsync();
    }

    private static IEnumerable<MetadataReference> GetReferences()
    {
        var trustedPlatformAssemblies = (string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!;

        return trustedPlatformAssemblies
            .Split(Path.PathSeparator)
            .Append(typeof(Fido2NetLib.Fido2).Assembly.Location)
            .Append(typeof(Fido2NetLib.Fido2User).Assembly.Location)
            .Distinct()
            .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path));
    }
}
