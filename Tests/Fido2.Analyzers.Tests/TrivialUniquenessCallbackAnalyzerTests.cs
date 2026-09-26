using Fido2NetLib.Analyzers;

namespace Test;

public class TrivialUniquenessCallbackAnalyzerTests
{
    private static string WithCallback(string callback) => $$"""
        using System.Threading.Tasks;
        using Fido2NetLib;
        using Fido2NetLib.Objects;

        class C
        {
            MakeNewCredentialParams M(System.Collections.Generic.HashSet<object> known) => new MakeNewCredentialParams
            {
                AttestationResponse = null,
                OriginalOptions = null,
                IsCredentialIdUniqueToUserCallback = {{callback}}
            };
        }
        """;

    [Theory]
    [InlineData("(args, ct) => Task.FromResult(true)")]
    [InlineData("static (args, ct) => Task.FromResult(true)")]
    [InlineData("async (args, ct) => true")]
    [InlineData("(args, ct) => { return Task.FromResult(true); }")]
    [InlineData("async (args, ct) => { return true; }")]
    [InlineData("(_, _) => Task.FromResult<bool>(true)")]
    public async Task FlagsACallbackThatAlwaysReturnsTrueAsync(string callback)
    {
        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new TrivialUniquenessCallbackAnalyzer(), WithCallback(callback));

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal("FIDO002", diagnostic.Id);
    }

    [Theory]
    [InlineData("(args, ct) => Task.FromResult(!known.Contains(args))")]
    [InlineData("(args, ct) => Task.FromResult(false)")]
    [InlineData("async (args, ct) => { await Task.Yield(); return true; }")]
    [InlineData("(args, ct) => Task.Run(() => true)")]
    [InlineData("(args, ct) => Task.FromResult(true && known.Count == 0)")]
    [InlineData("(args, ct) => Check()")]
    [InlineData("(args, ct) => Task.FromResult(args is not null)")]
    [InlineData("Check2")]
    [InlineData("(args, ct) => ((System.Func<Task<bool>>)(() => Task.FromResult(true)))()")]
    public async Task DoesNotFlagACallbackThatDecidesAsync(string callback)
    {
        var source = WithCallback(callback).Replace(
            "class C\n{",
            "class C\n{\n    static Task<bool> Check() => Task.FromResult(true);\n    static Task<bool> Check2(IsCredentialIdUniqueToUserParams p, System.Threading.CancellationToken ct) => Task.FromResult(true);");
        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new TrivialUniquenessCallbackAnalyzer(), source);

        Assert.Empty(diagnostics);
    }

    [Fact]
    public async Task DoesNotFlagAnUnrelatedPropertyNamedTheSameThingAsync()
    {
        const string source = """
            using System.Threading.Tasks;

            class Unrelated
            {
                public System.Func<object, object, Task<bool>> IsCredentialIdUniqueToUserCallback { get; set; }
            }

            namespace Fido2NetLib.Extras
            {
                class MakeNewCredentialParams
                {
                    public System.Func<object, object, Task<bool>> IsCredentialIdUniqueToUserCallback { get; set; }
                }
            }

            class C
            {
                void M()
                {
                    var p = new Unrelated { IsCredentialIdUniqueToUserCallback = (args, ct) => Task.FromResult(true) };
                    var q = new Fido2NetLib.Extras.MakeNewCredentialParams { IsCredentialIdUniqueToUserCallback = (args, ct) => Task.FromResult(true) };
                    p.IsCredentialIdUniqueToUserCallback = (args, ct) => Task.FromResult(true);
                }
            }
            """;

        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new TrivialUniquenessCallbackAnalyzer(), source);

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void DescribesItsDiagnostic()
    {
        var descriptor = Assert.Single(new TrivialUniquenessCallbackAnalyzer().SupportedDiagnostics);

        Assert.Equal("FIDO002", descriptor.Id);
    }
}
