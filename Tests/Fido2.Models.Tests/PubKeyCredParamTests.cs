using System.Linq;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Xunit;

namespace Fido2NetLib.Models.Tests;

/// <summary>
/// Tests for <see cref="PubKeyCredParam.FipsApproved"/>: it must contain exactly the ECDSA/RSA algorithms NIST
/// approves, and must never contain EdDSA, RS1 (SHA-1), or ES256K (not a NIST curve).
/// </summary>
public class PubKeyCredParamTests
{
    [Fact]
    public void FipsApproved_ContainsExactlyTheNistApprovedAlgorithms()
    {
        var algorithms = PubKeyCredParam.FipsApproved.Select(p => p.Alg).ToList();

        Assert.Equal(
        [
            COSE.Algorithm.ES256,
            COSE.Algorithm.RS256,
            COSE.Algorithm.PS256,
            COSE.Algorithm.ES384,
            COSE.Algorithm.RS384,
            COSE.Algorithm.PS384,
            COSE.Algorithm.ES512,
            COSE.Algorithm.RS512,
            COSE.Algorithm.PS512,
        ],
        algorithms);
    }

    [Fact]
    public void FipsApproved_DoesNotContainEdDSA()
    {
        Assert.DoesNotContain(PubKeyCredParam.FipsApproved, p => p.Alg == COSE.Algorithm.EdDSA);
    }

    [Fact]
    public void FipsApproved_DoesNotContainRS1()
    {
        Assert.DoesNotContain(PubKeyCredParam.FipsApproved, p => p.Alg == COSE.Algorithm.RS1);
    }

    [Fact]
    public void FipsApproved_DoesNotContainES256K()
    {
        Assert.DoesNotContain(PubKeyCredParam.FipsApproved, p => p.Alg == COSE.Algorithm.ES256K);
    }

    [Fact]
    public void FipsApproved_IsASubsetOfDefaults()
    {
        Assert.All(PubKeyCredParam.FipsApproved, p => Assert.Contains(PubKeyCredParam.Defaults, d => d.Alg == p.Alg));
    }
}
