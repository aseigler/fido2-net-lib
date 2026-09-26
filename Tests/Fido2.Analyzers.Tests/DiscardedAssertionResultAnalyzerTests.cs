using Fido2NetLib.Analyzers;

namespace Test;

public class DiscardedAssertionResultAnalyzerTests
{
    private static string InMethod(string statements, string fido2Type = "Fido2NetLib.IFido2") => $$"""
        using System.Threading.Tasks;
        using Fido2NetLib;
        using Fido2NetLib.Objects;

        class C
        {
            async Task M({{fido2Type}} fido2, MakeAssertionParams p)
            {
                {{statements}}
            }
        }
        """;

    [Theory]
    [InlineData("await fido2.MakeAssertionAsync(p);")]
    [InlineData("await fido2.MakeAssertionAsync(p).ConfigureAwait(false);")]
    [InlineData("_ = await fido2.MakeAssertionAsync(p);")]
    [InlineData("_ = await fido2.MakeAssertionAsync(p).ConfigureAwait(false);")]
    [InlineData("fido2.MakeAssertionAsync(p).GetAwaiter().GetResult();")]
    [InlineData("_ = fido2.MakeAssertionAsync(p).Result;")]
    [InlineData("fido2.MakeAssertionAsync(p).Wait();")]
    [InlineData("_ = fido2.MakeAssertionAsync(p);")]
#pragma warning disable xUnit1025 // the same statement against the class rather than the interface
    [InlineData("await fido2.MakeAssertionAsync(p, System.Threading.CancellationToken.None);")]
#pragma warning restore xUnit1025
    public async Task FlagsADiscardedResultAsync(string statement)
    {
        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new DiscardedAssertionResultAnalyzer(), InMethod(statement));

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal("FIDO001", diagnostic.Id);
        Assert.Contains("MakeAssertionAsync", diagnostic.Location.SourceTree!.ToString().Substring(diagnostic.Location.SourceSpan.Start, diagnostic.Location.SourceSpan.Length));
    }

    [Fact]
    public async Task FlagsADiscardedResultThroughTheClassAsync()
    {
        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new DiscardedAssertionResultAnalyzer(), InMethod("await fido2.MakeAssertionAsync(p);", "Fido2NetLib.Fido2"));

        Assert.Single(diagnostics);
    }

    [Theory]
    [InlineData("var result = await fido2.MakeAssertionAsync(p); System.Console.WriteLine(result.SignCount);")]
    [InlineData("var result = await fido2.MakeAssertionAsync(p).ConfigureAwait(false); System.Console.WriteLine(result);")]
    [InlineData("System.Console.WriteLine((await fido2.MakeAssertionAsync(p)).SignCount);")]
    [InlineData("var task = fido2.MakeAssertionAsync(p); await task;")]
    [InlineData("var count = fido2.MakeAssertionAsync(p).Result.SignCount;")]
    [InlineData("await Consume(fido2.MakeAssertionAsync(p)); static Task Consume(Task<VerifyAssertionResult> t) => t;")]
    [InlineData("await fido2.MakeNewCredentialAsync(null);")]
    public async Task DoesNotFlagAResultThatIsUsedOrAnotherMethodAsync(string statements)
    {
        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new DiscardedAssertionResultAnalyzer(), InMethod(statements));

        Assert.Empty(diagnostics);
    }

    [Fact]
    public async Task DoesNotFlagAnUnrelatedMakeAssertionAsyncAsync()
    {
        const string source = """
            using System.Threading.Tasks;

            namespace Elsewhere
            {
                class Fido2 { public Task<int> MakeAssertionAsync() => Task.FromResult(0); }
            }

            namespace Fido2NetLib.Extras
            {
                class IFido2 { public Task<int> MakeAssertionAsync() => Task.FromResult(0); }
            }

            class Wrapper { public Task<int> MakeAssertionAsync() => Task.FromResult(0); }

            class C
            {
                async Task M(Elsewhere.Fido2 a, Fido2NetLib.Extras.IFido2 b, Wrapper c)
                {
                    await a.MakeAssertionAsync();
                    await b.MakeAssertionAsync();
                    await c.MakeAssertionAsync();
                }
            }
            """;

        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(new DiscardedAssertionResultAnalyzer(), source);

        Assert.Empty(diagnostics);
    }

    [Fact]
    public void DescribesItsDiagnostic()
    {
        var descriptor = Assert.Single(new DiscardedAssertionResultAnalyzer().SupportedDiagnostics);

        Assert.Equal("FIDO001", descriptor.Id);
    }
}
