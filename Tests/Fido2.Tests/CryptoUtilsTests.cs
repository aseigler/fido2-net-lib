using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

public class CryptoUtilsTests
{
    [Fact]
    public void TestCertInCRLFalseCase()
    {
        byte[] certBytes = Convert.FromBase64String("MIIDAzCCAqigAwIBAgIPBFTYzwOQmHjntsvY0AGOMAoGCCqGSM49BAMCMG8xCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMS8wLQYDVQQLDCZGQUtFIE1ldGFkYXRhIDMgQkxPQiBJTlRFUk1FRElBVEUgRkFLRTEXMBUGA1UEAwwORkFLRSBDQS0xIEZBS0UwHhcNMTcwMjAxMDAwMDAwWhcNMzAwMTMxMjM1OTU5WjCBjjELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxMjAwBgNVBAsMKUZBS0UgTWV0YWRhdGEgMyBCTE9CIFNpZ25pbmcgU2lnbmluZyBGQUtFMTMwMQYDVQQDDCpGQUtFIE1ldGFkYXRhIDMgQkxPQiBTaWduaW5nIFNpZ25lciA0IEZBS0UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATL3eRNA9YIQ3mAsHfcO3x0rHxqg3xkQUb2E4Mo39L6SLXnz82D5Nnq+59Ah1hNfL5OEtxdgy+/kIJyiScl4+T8o4IBBTCCAQEwCwYDVR0PBAQDAgbAMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPl4RxJ2M8prAEvqnSFK4+3nN8SqMB8GA1UdIwQYMBaAFKOEp6Rkook8Cr8XnqIN8BIaptfLMEgGA1UdHwRBMD8wPaA7oDmGN2h0dHBzOi8vbWRzMy5jZXJ0aW5mcmEuZmlkb2FsbGlhbmNlLm9yZy9jcmwvTURTQ0EtMS5jcmwwWgYDVR0gBFMwUTBPBgsrBgEEAYLlHAEDATBAMD4GCCsGAQUFBwIBFjJodHRwczovL21kczMuY2VydGluZnJhLmZpZG9hbGxpYW5jZS5vcmcvcmVwb3NpdG9yeTAKBggqhkjOPQQDAgNJADBGAiEAxIq00OoEowGSIlqPzVQtqKTgCJpqSHu3NYZHgQIIbKICIQCZYm9Z0KnEhzWIc0bwa0sLfZ/AMJ8vhM5B1jrz8mgmBA==");

        byte[] crl = Convert.FromBase64String("MIIB7DCCAZICAQEwCgYIKoZIzj0EAwIwbzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxLzAtBgNVBAsMJkZBS0UgTWV0YWRhdGEgMyBCTE9CIElOVEVSTUVESUFURSBGQUtFMRcwFQYDVQQDDA5GQUtFIENBLTEgRkFLRRcNMTgwMjAxMDAwMDAwWhcNMjIwMjAxMDAwMDAwWjCBwDAuAg8ELS9CzLtxNJTOFTHXiV8XDTE2MDQxMzAwMDAwMFowDDAKBgNVHRUEAwoBADAuAg8ExejzukpclaXnFLGvxDEXDTE3MDMyNTAwMDAwMFowDDAKBgNVHRUEAwoBADAuAg8Er13ouX8KNf3VOr4OzQEXDTE2MDMwMTAwMDAwMFowDDAKBgNVHRUEAwoBADAuAg8EgGdJ3jB7vVF1om1z9fMXDTE4MDMyNTAwMDAwMFowDDAKBgNVHRUEAwoBAKAvMC0wCgYDVR0UBAMCAQEwHwYDVR0jBBgwFoAUo4SnpGSiiTwKvxeeog3wEhqm18swCgYIKoZIzj0EAwIDSAAwRQIgDgtshLf5/82mHcOgl2TsUizHsjLCslmQVDdSPcolS8UCIQDa5MSjQbX1v8MkCPpzxbrBb1I510aSTuZB0RUuwPnOYw==");

        var cert = X509CertificateHelper.CreateFromRawData(certBytes);

        // The FAKE CA-1 certificate that signed this CRL is not on hand, so only decoding and membership are covered here
        var revocationList = CertificateRevocationList.Decode(crl);

        Assert.Contains("FAKE CA-1 FAKE", revocationList.Issuer.Name);
        Assert.Equal(new DateTimeOffset(2018, 2, 1, 0, 0, 0, TimeSpan.Zero), revocationList.ThisUpdate);
        Assert.Equal(new DateTimeOffset(2022, 2, 1, 0, 0, 0, TimeSpan.Zero), revocationList.NextUpdate);
        Assert.Equal(4, revocationList.RevokedCertificateCount);
        Assert.False(revocationList.IsRevoked(cert));
    }

    [Fact]
    public void TestCertInCRLTrueCase()
    {
        byte[] certBytes = Convert.FromBase64String("MIIDAjCCAqigAwIBAgIPBIBnSd4we71RdaJtc / XzMAoGCCqGSM49BAMCMG8xCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMS8wLQYDVQQLDCZGQUtFIE1ldGFkYXRhIDMgQkxPQiBJTlRFUk1FRElBVEUgRkFLRTEXMBUGA1UEAwwORkFLRSBDQS0xIEZBS0UwHhcNMTcwMjAxMDAwMDAwWhcNMzAwMTMxMjM1OTU5WjCBjjELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxMjAwBgNVBAsMKUZBS0UgTWV0YWRhdGEgMyBCTE9CIFNpZ25pbmcgU2lnbmluZyBGQUtFMTMwMQYDVQQDDCpGQUtFIE1ldGFkYXRhIDMgQkxPQiBTaWduaW5nIFNpZ25lciA0IEZBS0UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATL3eRNA9YIQ3mAsHfcO3x0rHxqg3xkQUb2E4Mo39L6SLXnz82D5Nnq + 59Ah1hNfL5OEtxdgy +/ kIJyiScl4 + T8o4IBBTCCAQEwCwYDVR0PBAQDAgbAMAwGA1UdEwEB / wQCMAAwHQYDVR0OBBYEFPl4RxJ2M8prAEvqnSFK4 + 3nN8SqMB8GA1UdIwQYMBaAFKOEp6Rkook8Cr8XnqIN8BIaptfLMEgGA1UdHwRBMD8wPaA7oDmGN2h0dHBzOi8vbWRzMy5jZXJ0aW5mcmEuZmlkb2FsbGlhbmNlLm9yZy9jcmwvTURTQ0EtMS5jcmwwWgYDVR0gBFMwUTBPBgsrBgEEAYLlHAEDATBAMD4GCCsGAQUFBwIBFjJodHRwczovL21kczMuY2VydGluZnJhLmZpZG9hbGxpYW5jZS5vcmcvcmVwb3NpdG9yeTAKBggqhkjOPQQDAgNIADBFAiB3yVejfuPNQT + 5VPY5gDcPXAdwA9Pudwe1M0BcGsa5 + gIhAJ0opi4Y / w26gNaAvsCvalwCqI6QYQCP1bjGSMgu3K1e");

        byte[] crl = Convert.FromBase64String("MIIB7DCCAZICAQEwCgYIKoZIzj0EAwIwbzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxLzAtBgNVBAsMJkZBS0UgTWV0YWRhdGEgMyBCTE9CIElOVEVSTUVESUFURSBGQUtFMRcwFQYDVQQDDA5GQUtFIENBLTEgRkFLRRcNMTgwMjAxMDAwMDAwWhcNMjIwMjAxMDAwMDAwWjCBwDAuAg8ELS9CzLtxNJTOFTHXiV8XDTE2MDQxMzAwMDAwMFowDDAKBgNVHRUEAwoBADAuAg8ExejzukpclaXnFLGvxDEXDTE3MDMyNTAwMDAwMFowDDAKBgNVHRUEAwoBADAuAg8Er13ouX8KNf3VOr4OzQEXDTE2MDMwMTAwMDAwMFowDDAKBgNVHRUEAwoBADAuAg8EgGdJ3jB7vVF1om1z9fMXDTE4MDMyNTAwMDAwMFowDDAKBgNVHRUEAwoBAKAvMC0wCgYDVR0UBAMCAQEwHwYDVR0jBBgwFoAUo4SnpGSiiTwKvxeeog3wEhqm18swCgYIKoZIzj0EAwIDSAAwRQIgDgtshLf5/82mHcOgl2TsUizHsjLCslmQVDdSPcolS8UCIQDa5MSjQbX1v8MkCPpzxbrBb1I510aSTuZB0RUuwPnOYw==");

        var cert = X509CertificateHelper.CreateFromRawData(certBytes);

        Assert.True(CertificateRevocationList.Decode(crl).IsRevoked(cert));
    }

    [Fact]
    public void TestValidateTrustChainRootAnchor()
    {
        var attestationRootCertificates = new X509Certificate2[3]
        {
            X509CertificateHelper.CreateFromRawData(Convert.FromBase64String("MIIBfjCCASWgAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxGVCBGSURPIDAyMDAwIBcNMTYwNTAxMDAwMDAwWhgPMjA1MDA1MDEwMDAwMDBaMBcxFTATBgNVBAMMDEZUIEZJRE8gMDIwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNBmrRqVOxztTJVN19vtdqcL7tKQeol2nnM2/yYgvksZnr50SKbVgIEkzHQVOu80LVEE3lVheO1HjggxAlT6o4WjYDBeMB0GA1UdDgQWBBRJFWQt1bvG3jM6XgmV/IcjNtO/CzAfBgNVHSMEGDAWgBRJFWQt1bvG3jM6XgmV/IcjNtO/CzAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiAwfPqgIWIUB+QBBaVGsdHy0s5RMxlkzpSX/zSyTZmUpQIgB2wJ6nZRM8oX/nA43Rh6SJovM2XwCCH//+LirBAbB0M=")),
            X509CertificateHelper.CreateFromRawData(Convert.FromBase64String("MIIB2DCCAX6gAwIBAgIQFZ97ws2JGPEoa5NI+p8z1jAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQwMTAwMDAwMFoYDzIwNDgwMzMxMjM1OTU5WjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnfAKbjvMX1Ey1b6k+WQQdNVMt9JgGWyJ3PvM4BSK5XqTfo++0oAj/4tnwyIL0HFBR9St+ktjqSXDfjiXAurs86NCMEAwHQYDVR0OBBYEFNGhmE2Bf8O5a/YHZ71QEv6QRfFUMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIQC3sT1lBjGeF+xKTpzV1KYU2ckahTd4mLJyzYOhaHv4igIgD2JYkfyH5Q4Bpo8rroO0It7oYjF2kgy/eSZ3U9Glaqw=")),
            X509CertificateHelper.CreateFromRawData(Convert.FromBase64String("MIIB2DCCAX6gAwIBAgIQGBUrQbdDrm20FZnDsX2CBTAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQwMTAwMDAwMFoYDzIwNDgwMzMxMjM1OTU5WjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsFYEEhiJuqqnMgQjSiivBjV7DGCTf4XBBH/B7uvZsKxXShF0L8uDISWUvcExixRs6gB3oldSrjox6L8T94NOzqNCMEAwHQYDVR0OBBYEFEu9hyYRrRyJzwRYvnDSCIxrFiO3MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIDHSb2mbNDAUNXvpPU0oWKeNye0fQ2l9D01AR2+sLZdhAiEAo3wz684IFMVsCCRmuJqxH6FQRESNqezuo1E+KkGxWuM="))
        };

        var trustPath = new X509Certificate2[2]
        {
            X509CertificateHelper.CreateFromRawData(Convert.FromBase64String("MIICQzCCAemgAwIBAgIQHfK1WlHcS2iFo9meaX/tFjAKBggqhkjOPQQDAjBJMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETyBDQSAwMzAgFw0xODEyMjUwMDAwMDBaGA8yMDMzMTIyNDIzNTk1OVowcDELMAkGA1UEBhMCVVMxHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMR4wHAYDVQQDDBVGVCBCaW9QYXNzIEZJRE8yIDA0NzAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS62hIbyenH9WPnzYHehaBR3C7qswomZkaPzGyUlFRiJIMo3uITeImFOFfNcDuOzoq1wcXXGTmEtEtxF2wo9noko4GJMIGGMB0GA1UdDgQWBBSBI1XoLDY1/HJaba+W32nxhxp3WjAfBgNVHSMEGDAWgBRBt/xNdcqO0p8s0xebzYNRinnYqTAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgRwMCEGCysGAQQBguUcAQEEBBIEEBLe10VL7UfUq6rnE/UdY5MwCgYIKoZIzj0EAwIDSAAwRQIhAI6GSVi10r673uqtso+2oB6f5S5gE0ff44t3NcQ+TN9NAiAC/SCP+eKw1BnmcSgbxcQpYuWjBPMVDfqeg8pbmOdHKw==")),
            X509CertificateHelper.CreateFromRawData(Convert.FromBase64String("MIIB+TCCAaCgAwIBAgIQGBUrQbdDrm20FZnDsX2CCDAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDUyMDAwMDAwMFoYDzIwMzgwNTE5MjM1OTU5WjBJMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETyBDQSAwMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJts1KYQuj66rAszKKLfsOay91gO11vSvfcYd/dQfeTjpSNb55ffoLijQbRXspqE5Uj2NVylED61pjo2tpytOfijZjBkMB0GA1UdDgQWBBRBt/xNdcqO0p8s0xebzYNRinnYqTAfBgNVHSMEGDAWgBRLvYcmEa0cic8EWL5w0giMaxYjtzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiAnSuhaqHgV3Sds/OrwiqLNUWMmU8Lji9Vy7s5hSEg22AIgE1lIdBjq0N+QcZq995uOE4XWxBIrVUio3RAwgDn8KgI="))
        };
        var attestationCert = trustPath[0];
        var intermediateCa = trustPath[1];
        var root = attestationRootCertificates[2]; // the one that issued the intermediate

        // x5c carries the intermediate, and a declared anchor is the root that issued it
        Assert.True(CryptoUtils.ValidateTrustChain(trustPath, attestationRootCertificates));

        // The intermediate CA is itself the declared anchor, with and without the authenticator supplying it
        Assert.True(CryptoUtils.ValidateTrustChain(trustPath, [intermediateCa]));
        Assert.True(CryptoUtils.ValidateTrustChain([attestationCert], [intermediateCa]));

        // The attestation certificate is itself the declared anchor, whatever else x5c carries
        Assert.True(CryptoUtils.ValidateTrustChain(trustPath, [attestationCert]));
        Assert.True(CryptoUtils.ValidateTrustChain([attestationCert], [attestationCert]));

        // The declared anchor is the root, but nothing supplies the intermediate that links to it
        Assert.False(CryptoUtils.ValidateTrustChain([attestationCert], [root]));

        // The declared anchors are the other Feitian roots, which did not issue the intermediate
        Assert.False(CryptoUtils.ValidateTrustChain(trustPath, [attestationRootCertificates[0], attestationRootCertificates[1]]));

        // A root presented as the attestation certificate chains to nothing the metadata declares
        Assert.False(CryptoUtils.ValidateTrustChain(attestationRootCertificates, trustPath));
    }

    [Fact]
    public void TestValidateTrustChainSubAnchor()
    {
        // HID declares an intermediate CA as the trust anchor, and its authenticators send only the attestation
        // certificate, relying on AIA for the rest of the chain. Only Windows follows the AIA link (a PKCS#7 bundle
        // the other platforms' loaders reject), which is why this used to pass on Windows alone.
        byte[] attRootCertBytes = Convert.FromBase64String("MIIDCDCCAq+gAwIBAgIQQAFqUNTHZ8kBN8u/bCk+xDAKBggqhkjOPQQDAjBrMQswCQYDVQQGEwJVUzETMBEGA1UEChMKSElEIEdsb2JhbDEiMCAGA1UECxMZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEjMCEGA1UEAxMaRklETyBBdHRlc3RhdGlvbiBSb290IENBIDEwHhcNMTkwNDI0MTkzMTIzWhcNNDQwNDI3MTkzMTIzWjBmMQswCQYDVQQGEwJVUzETMBEGA1UEChMKSElEIEdsb2JhbDEiMCAGA1UECxMZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEeMBwGA1UEAxMVRklETyBBdHRlc3RhdGlvbiBDQSAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4nK9ctzk6GEGFNQBcrnBBmWU+dCnuHQAARrB2Eyc8MbsljkSFhZtfz/Rw6SuVIDk5VakDzrKBAOJ9v0Rvg/406OCATgwggE0MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMIGEBggrBgEFBQcBAQR4MHYwLgYIKwYBBQUHMAGGImh0dHA6Ly9oaWQuZmlkby5vY3NwLmlkZW50cnVzdC5jb20wRAYIKwYBBQUHMAKGOGh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5jb20vcm9vdHMvSElERklET1Jvb3RjYTEucDdjMB8GA1UdIwQYMBaAFB2m3iwWSYHvWTHbJiHAyKDp+CSjMEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5jb20vY3JsL0hJREZJRE9Sb290Y2ExLmNybDAdBgNVHQ4EFgQUDLCbuLslcclrOZIz57Fu0imSMQ8wCgYIKoZIzj0EAwIDRwAwRAIgDCW5IrbjEI/y35lPjx9a+/sF4lPSoZdBHgFgTWC+8VICIEqs2SPzUHgHVh65Ajl1oIUmhh0C2lyR/Zdk7O3u1TIK");
        var attestationRootCertificates = new X509Certificate2[1] { X509CertificateHelper.CreateFromRawData(attRootCertBytes) };

        byte[] attCert = Convert.FromBase64String("MIIDLjCCAtSgAwIBAgIQQAFs2JXwQcL5Eh4rnp2ASjAKBggqhkjOPQQDAjBmMQswCQYDVQQGEwJVUzETMBEGA1UEChMKSElEIEdsb2JhbDEiMCAGA1UECxMZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEeMBwGA1UEAxMVRklETyBBdHRlc3RhdGlvbiBDQSAyMB4XDTE5MDgyODE0MTY0MFoXDTM5MDgyMzE0MTY0MFowaTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFkhJRCBHbG9iYWwgQ29ycG9yYXRpb24xIjAgBgNVBAsTGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xFTATBgNVBAMTDENyZXNjZW5kb0tleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAGouI654w6qbGonSTStO2cESYTo8Ezr8OJiPkMl02d6K6i44wXCKV2i+w+bpR6vgYQZ/cKQxMS4uGytqPRNPIejggFfMIIBWzAOBgNVHQ8BAf8EBAMCB4AwgYAGCCsGAQUFBwEBBHQwcjAuBggrBgEFBQcwAYYiaHR0cDovL2hpZC5maWRvLm9jc3AuaWRlbnRydXN0LmNvbTBABggrBgEFBQcwAoY0aHR0cDovL3ZhbGlkYXRpb24uaWRlbnRydXN0LmNvbS9jZXJ0cy9oaWRmaWRvY2EyLnA3YzAfBgNVHSMEGDAWgBQMsJu4uyVxyWs5kjPnsW7SKZIxDzAJBgNVHRMEAjAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVzdC5jb20vY3JsL2hpZGZpZG9jYTIuY3JsMBMGCysGAQQBguUcAgEBBAQDAgQwMB0GA1UdDgQWBBR9h/lCWeTiMUhRS1tj31hBXaOurzAhBgsrBgEEAYLlHAEBBAQSBBBpLbVJeuVE1aHl3SCkk7cjMAoGCCqGSM49BAMCA0gAMEUCIQDpDa1ZbAfCTlBMiDUuB5XH8hnhZUF1JCuCmc+ShI4ZTwIga/ApAudL5R8HxOOHgk8AA/JpgCkMmYDQLVq0QF6oxrU=");
        var trustPath = new X509Certificate2[1] { X509CertificateHelper.CreateFromRawData(attCert) };

        Assert.False(0 == attestationRootCertificates[0].Issuer.CompareTo(attestationRootCertificates[0].Subject));

        // Chain building alone, with no revocation checking
        Assert.True(CryptoUtils.ValidateTrustChain(trustPath, attestationRootCertificates, FidoValidationMode.FidoConformance2024));
        Assert.True(CryptoUtils.ValidateTrustChain(trustPath, trustPath, FidoValidationMode.FidoConformance2024));
        Assert.True(CryptoUtils.ValidateTrustChain(attestationRootCertificates, attestationRootCertificates, FidoValidationMode.FidoConformance2024));
        Assert.False(CryptoUtils.ValidateTrustChain(attestationRootCertificates, trustPath, FidoValidationMode.FidoConformance2024));

        // The attestation certificate names a CRL distribution point. On Windows and Linux this also fetches the
        // CRL from IdenTrust; on macOS, X509Chain never attempts the fetch for a CustomRootTrust anchor (see
        // ValidateTrustChainSkipsAttestationCertificateRevocationCheckOnMacOS), so this exercises chain building only.
        Assert.True(CryptoUtils.ValidateTrustChain(trustPath, attestationRootCertificates));
    }

    [Fact]
    public void TestValidateTrustChainSelf()
    {
        byte[] certBytes = Convert.FromBase64String("MIIBzTCCAXOgAwIBAgIJALS3SibGDXTPMAoGCCqGSM49BAMCMDsxIDAeBgNVBAMMF0dvVHJ1c3QgRklETzIgUm9vdCBDQSAxMRcwFQYDVQQKDA5Hb1RydXN0SUQgSW5jLjAeFw0xOTEyMDQwNjU5NDBaFw00OTExMjYwNjU5NDBaMDsxIDAeBgNVBAMMF0dvVHJ1c3QgRklETzIgUm9vdCBDQSAxMRcwFQYDVQQKDA5Hb1RydXN0SUQgSW5jLjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA5mjYsjowAI0jnpi//CJ3KnzhGbTUmstNWqN78ioG1CTK9gPgPl9UiFOJO/v+FfFK+Pxv10c604dvlIDAbKw+ijYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSgWtY0nEcmPmGDLuCwceKeJPScozAfBgNVHSMEGDAWgBSgWtY0nEcmPmGDLuCwceKeJPScozAKBggqhkjOPQQDAgNIADBFAiAxoVs6qj7DX2xixCjjcDUdxBTJmSTLb0f1rRGwrABzTQIhAPt0P32qzAeepF4//tgzxqNoKkWDcaPPSXrg+xzrlVHw");
        var certs = new X509Certificate2[1] { X509CertificateHelper.CreateFromRawData(certBytes) };

        byte[] otherCertBytes = Convert.FromBase64String("MIIDRjCCAu2gAwIBAgIUZPhSDtxI5lg2qgy+7IGDJhGqPOgwCgYIKoZIzj0EAwIwgYcxCzAJBgNVBAYTAlRXMQ8wDQYDVQQIDAZUYWlwZWkxEjAQBgNVBAcMCVNvbWV3aGVyZTEWMBQGA1UECgwNV2lTRUNVUkUgSW5jLjEgMB4GCSqGSIb3DQEJARYRYWRtaW5AZXhhbXBsZS5vcmcxGTAXBgNVBAMMEFdpU0VDVVJFIFJvb3QgQ0EwHhcNMjEwMTI4MDgyNzIwWhcNMzEwMTI2MDgyNzIwWjCBhzELMAkGA1UEBhMCVFcxDzANBgNVBAgMBlRhaXBlaTESMBAGA1UEBwwJU29tZXdoZXJlMRYwFAYDVQQKDA1XaVNFQ1VSRSBJbmMuMSAwHgYJKoZIhvcNAQkBFhFhZG1pbkBleGFtcGxlLm9yZzEZMBcGA1UEAwwQV2lTRUNVUkUgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBiWvFaf/IhFMOWNqlweqr4GfO0mu/1B18J03OG+pSltRix9GjRojBya4LARyXMP8nw2Xh9PvwOBm9QedMC66XGjggEzMIIBLzAdBgNVHQ4EFgQUd+Yvj6I3Y8cKH3QRNLlC8/Op97cwgccGA1UdIwSBvzCBvIAUd+Yvj6I3Y8cKH3QRNLlC8/Op97ehgY2kgYowgYcxCzAJBgNVBAYTAlRXMQ8wDQYDVQQIDAZUYWlwZWkxEjAQBgNVBAcMCVNvbWV3aGVyZTEWMBQGA1UECgwNV2lTRUNVUkUgSW5jLjEgMB4GCSqGSIb3DQEJARYRYWRtaW5AZXhhbXBsZS5vcmcxGTAXBgNVBAMMEFdpU0VDVVJFIFJvb3QgQ0GCFGT4Ug7cSOZYNqoMvuyBgyYRqjzoMAwGA1UdEwEB/wQCMAAwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5leGFtcGxlLm9yZy9leGFtcGxlX2NhLmNybDAKBggqhkjOPQQDAgNHADBEAiBf3p8LJ3PlfMsxTzWgjHaal6uzIo5tx3o+EUybdDY4ogIgV6nR1MUE1wKz1uC7/kENg/FpJOetFaJePcgoneEwsKA=");
        var otherCerts = new X509Certificate2[1] { X509CertificateHelper.CreateFromRawData(otherCertBytes) };

        Assert.True(CryptoUtils.ValidateTrustChain(certs, certs));
        Assert.False(CryptoUtils.ValidateTrustChain(certs, otherCerts));
    }

    [Fact]
    public void ValidateTrustChainAcceptsIntermediateAnchorWithoutRoot()
    {
        using var pki = new TestPki();

        // The anchor is the intermediate; the root exists but nothing here has it
        Assert.True(CryptoUtils.ValidateTrustChain([pki.Leaf, pki.Intermediate], [pki.Intermediate], FidoValidationMode.FidoConformance2024));
        Assert.True(CryptoUtils.ValidateTrustChain([pki.Leaf], [pki.Intermediate], FidoValidationMode.FidoConformance2024));

        // The anchor is the root, reached through the intermediate the authenticator supplied
        Assert.True(CryptoUtils.ValidateTrustChain([pki.Leaf, pki.Intermediate], [pki.Root], FidoValidationMode.FidoConformance2024));

        // The anchor is the root, but the intermediate is missing so the chain cannot reach it
        Assert.False(CryptoUtils.ValidateTrustChain([pki.Leaf], [pki.Root], FidoValidationMode.FidoConformance2024));
    }

    [Fact]
    public void ValidateTrustChainRejectsAnchorThatDidNotSignTheChain()
    {
        using var pki = new TestPki();

        // Same subject name, subject key identifier and issuer as the real intermediate, but a different key
        Assert.False(CryptoUtils.ValidateTrustChain([pki.Leaf], [pki.IntermediateLookalike], FidoValidationMode.FidoConformance2024));
        Assert.False(CryptoUtils.ValidateTrustChain([pki.Leaf, pki.IntermediateLookalike], [pki.IntermediateLookalike], FidoValidationMode.FidoConformance2024));

        // A declared anchor from an unrelated PKI
        using var other = new TestPki();
        Assert.False(CryptoUtils.ValidateTrustChain([pki.Leaf, pki.Intermediate], [other.Root, other.Intermediate], FidoValidationMode.FidoConformance2024));
    }

    [Fact]
    public void ValidateTrustChainRejectsExpiredAttestationCertificate()
    {
        using var pki = new TestPki();

        Assert.False(CryptoUtils.ValidateTrustChain([pki.ExpiredLeaf, pki.Intermediate], [pki.Root], FidoValidationMode.FidoConformance2024));
        Assert.False(CryptoUtils.ValidateTrustChain([pki.ExpiredLeaf], [pki.Intermediate], FidoValidationMode.FidoConformance2024));
    }

    [Fact]
    public async Task ValidateTrustChainChecksRevocationOfTheAttestationCertificateOnly()
    {
        // This is the Windows/Linux behavior specifically; see ValidateTrustChainSkipsAttestationCertificateRevocationCheckOnMacOS
        if (OperatingSystem.IsMacOS())
            return;

        using var pki = new TestPki();
        using var crlServer = await CrlServer.StartAsync(pki.EmptyCrl);

        // The attestation certificate names the CRL served here; the intermediate has no distribution point at all
        var leaf = pki.IssueLeaf(crlServer.Url);

        Assert.True(CryptoUtils.ValidateTrustChain([leaf, pki.Intermediate], [pki.Root]));
        Assert.True(CryptoUtils.ValidateTrustChain([leaf], [pki.Intermediate]));

        // An unreachable distribution point leaves the status unknown, which is not good enough for the attestation certificate
        var unreachableLeaf = pki.IssueLeaf(crlServer.Url + "-missing");
        Assert.False(CryptoUtils.ValidateTrustChain([unreachableLeaf, pki.Intermediate], [pki.Root]));
        Assert.True(CryptoUtils.ValidateTrustChain([unreachableLeaf, pki.Intermediate], [pki.Root], FidoValidationMode.FidoConformance2024));
    }

    [Fact]
    public void ValidateTrustChainSkipsAttestationCertificateRevocationCheckOnMacOS()
    {
        // Confirmed by instrumenting X509Chain directly: on macOS, SecTrust never attempts a CRL fetch for a
        // certificate under a CustomRootTrust anchor, in any combination of RevocationMode/X509VerificationFlags.
        // ValidateTrustChain accounts for this by not enabling Online revocation there at all, so an attestation
        // certificate with an unreachable (or simply unchecked) CRL distribution point is not penalized for it --
        // unlike on Windows/Linux, see ValidateTrustChainChecksRevocationOfTheAttestationCertificateOnly.
        if (!OperatingSystem.IsMacOS())
            return;

        using var pki = new TestPki();
        var leaf = pki.IssueLeaf("http://127.0.0.1:1/unreachable.crl");

        Assert.True(CryptoUtils.ValidateTrustChain([leaf, pki.Intermediate], [pki.Root]));
        Assert.True(CryptoUtils.ValidateTrustChain([leaf], [pki.Intermediate]));
    }

    [Fact]
    public void IsCertInCRLHonorsCrlSignedByTheIssuer()
    {
        using var pki = new TestPki();

        Assert.False(CryptoUtils.IsCertInCRL(pki.EmptyCrl, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));
        Assert.True(CryptoUtils.IsCertInCRL(pki.CrlRevokingLeaf, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));

        // The leaf's serial number has its top bit set, so its DER encoding carries a sign-padding octet
        Assert.Equal(0x00, pki.Leaf.SerialNumberBytes.Span[0]);
        Assert.True(pki.Leaf.SerialNumberBytes.Span[1] >= 0x80);
    }

    [Fact]
    public void IsCertInCRLRejectsCrlNotSignedByTheIssuer()
    {
        using var pki = new TestPki();

        // Right name, wrong key: the signature does not verify
        var ex = Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(pki.CrlRevokingLeaf, pki.Leaf, pki.IntermediateLookalike));
        Assert.Contains("signature", ex.Message);

        // Wrong CA altogether: the issuer names do not match
        using var other = new TestPki();
        Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(other.EmptyCrl, pki.Leaf, other.Intermediate));

        // The CRL was altered after signing
        byte[] tampered = (byte[])pki.EmptyCrl.Clone();
        tampered[tampered.Length / 2] ^= 0x01;
        Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(tampered, pki.Leaf, pki.Intermediate));

        // Not a CRL at all
        Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(pki.Leaf.RawData, pki.Leaf, pki.Intermediate));
    }

    [Fact]
    public void IsCertInCRLRejectsStaleCrlOnlyWhenAskedToCheckTheTime()
    {
        using var pki = new TestPki();

        byte[] staleCrl = pki.BuildCrl(nextUpdate: DateTimeOffset.UtcNow.AddDays(-1), revokeLeaf: true);

        Assert.True(CryptoUtils.IsCertInCRL(staleCrl, pki.Leaf, pki.Intermediate));

        var ex = Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(staleCrl, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));
        Assert.Contains("stale", ex.Message);
    }

    [Fact]
    public void IsCertInCRLReadsCrlWithoutNextUpdateOrExtensions()
    {
        using var pki = new TestPki();

        // Every optional TBSCertList field omitted: version, signature, issuer, thisUpdate, revokedCertificates
        byte[] minimalCrl = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span);

        var revocationList = CertificateRevocationList.Decode(minimalCrl);
        Assert.Null(revocationList.NextUpdate);
        Assert.Equal(1, revocationList.RevokedCertificateCount);

        Assert.True(CryptoUtils.IsCertInCRL(minimalCrl, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void IsCertInCRLVerifiesRsaSignedCrl()
    {
        using var pki = new TestPki(useRsa: true);

        Assert.False(CryptoUtils.IsCertInCRL(pki.EmptyCrl, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));
        Assert.True(CryptoUtils.IsCertInCRL(pki.CrlRevokingLeaf, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));
        Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(pki.CrlRevokingLeaf, pki.Leaf, pki.IntermediateLookalike));
    }

    [Fact]
    public void TryGetCrlDistributionPointUrlFindsFirstHttpUrl()
    {
        using var pki = new TestPki();

        Assert.False(CryptoUtils.TryGetCrlDistributionPointUrl(pki.Leaf, out _));

        Assert.True(CryptoUtils.TryGetCrlDistributionPointUrl(pki.IssueLeaf("http://crl.example/a.crl"), out var url));
        Assert.Equal("http://crl.example/a.crl", url);

        // A non-HTTP location ahead of the HTTP one is passed over
        Assert.True(CryptoUtils.TryGetCrlDistributionPointUrl(pki.IssueLeaf("ldap://ldap.example/cn=crl", "https://crl.example/b.crl"), out url));
        Assert.Equal("https://crl.example/b.crl", url);

        Assert.False(CryptoUtils.TryGetCrlDistributionPointUrl(pki.IssueLeaf("ldap://ldap.example/cn=crl"), out _));
    }

    [Theory]
    [InlineData(COSE.Algorithm.ESP256, "SHA256")]
    [InlineData(COSE.Algorithm.ESP384, "SHA384")]
    [InlineData(COSE.Algorithm.ESP512, "SHA512")]
    [InlineData(COSE.Algorithm.RS1, "SHA1")]
    public void HashAlgFromCOSEAlgNamesTheDigest(COSE.Algorithm alg, string expected)
    {
        Assert.Equal(expected, CryptoUtils.HashAlgFromCOSEAlg(alg).Name);
    }

    [Theory]
    [InlineData(COSE.Algorithm.EdDSA)]
    [InlineData(COSE.Algorithm.Ed25519)]
    [InlineData(COSE.Algorithm.Ed448)]
    [InlineData(COSE.Algorithm.MLDSA44)]
    [InlineData((COSE.Algorithm)4)] // TPM_ALG_SHA1, which used to be smuggled through here
    public void HashAlgFromCOSEAlgRejectsAlgorithmsWithoutASeparateDigest(COSE.Algorithm alg)
    {
        var ex = Assert.Throws<Fido2VerificationException>(() => CryptoUtils.HashAlgFromCOSEAlg(alg));
        Assert.Equal(Fido2ErrorMessages.InvalidCoseAlgorithmValue, ex.Message);
    }

    [Fact]
    public void HashDataRejectsUnknownAlgorithm()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoUtils.HashData(HashAlgorithmName.MD5, [1, 2, 3]));
        Assert.Equal(SHA256.HashData([1, 2, 3]), CryptoUtils.HashData(HashAlgorithmName.SHA256, [1, 2, 3]));
    }

    [Fact]
    public void ValidateTrustChainRequiresAnAttestationCertificate()
    {
        using var pki = new TestPki();

        Assert.Throws<ArgumentException>(() => CryptoUtils.ValidateTrustChain([], [pki.Root]));
    }

    [Fact]
    public void IsCertInCRLRejectsIssuerThatDidNotIssueTheCertificate()
    {
        using var pki = new TestPki();

        // The CRL is the intermediate's, matching the leaf's issuer name, but the root is offered as the issuer
        var ex = Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(pki.EmptyCrl, pki.Leaf, pki.Root));
        Assert.Contains("was issued by", ex.Message);
    }

    [Fact]
    public void CertificateRevocationListDecodesVersion1AndRejectsOthers()
    {
        using var pki = new TestPki();

        // v1 omits the version field entirely
        byte[] v1 = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span, version: null);
        Assert.True(CryptoUtils.IsCertInCRL(v1, pki.Leaf, pki.Intermediate));

        byte[] v3 = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span, version: 2);
        Assert.Throws<CryptographicException>(() => CertificateRevocationList.Decode(v3));
    }

    [Fact]
    public void CertificateRevocationListRejectsSignatureWithPaddingBits()
    {
        using var pki = new TestPki();

        byte[] padded = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span, unusedBitCount: 3);
        Assert.Throws<CryptographicException>(() => CertificateRevocationList.Decode(padded));
    }

    [Fact]
    public void CertificateRevocationListRejectsUnsupportedSignatureAlgorithm()
    {
        using var pki = new TestPki(useRsa: true);

        // RSASSA-PSS carries a salt length .NET cannot honor, so it is refused rather than guessed at
        byte[] pss = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span, signatureAlgorithm: TestPki.RsassaPss);
        var revocationList = CertificateRevocationList.Decode(pss);

        var ex = Assert.Throws<CryptographicException>(() => revocationList.VerifySignature(pki.Intermediate));
        Assert.Contains(TestPki.RsassaPss, ex.Message);
        Assert.Throws<CryptographicException>(() => CryptoUtils.IsCertInCRL(pss, pki.Leaf, pki.Intermediate));
    }

    [Fact]
    public void CertificateRevocationListVerifiesOtherDigests()
    {
        using var pki = new TestPki();

        byte[] sha512 = pki.BuildCrl(DateTimeOffset.UtcNow.AddDays(7), revokeLeaf: true, HashAlgorithmName.SHA512);
        Assert.True(CryptoUtils.IsCertInCRL(sha512, pki.Leaf, pki.Intermediate, DateTimeOffset.UtcNow));

        byte[] sha1 = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span, signatureAlgorithm: TestPki.EcdsaWithSha1, hashAlgorithm: HashAlgorithmName.SHA1);
        Assert.True(CryptoUtils.IsCertInCRL(sha1, pki.Leaf, pki.Intermediate));

        // The algorithm identifier and the signature must agree: a SHA-1 signature labelled as SHA-256 does not verify
        byte[] mislabelled = pki.BuildMinimalCrl(pki.Leaf.SerialNumberBytes.Span, signatureAlgorithm: TestPki.EcdsaWithSha256, hashAlgorithm: HashAlgorithmName.SHA1);
        Assert.False(CertificateRevocationList.Decode(mislabelled).VerifySignature(pki.Intermediate));
    }

    [Fact]
    public void TryGetCrlDistributionPointUrlSkipsNamesThatAreNotUrls()
    {
        using var pki = new TestPki();

        // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint { [0] EXPLICIT { fullName [0] IMPLICIT GeneralNames } }
        // with a directoryName [4] ahead of the uniformResourceIdentifier [6]
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence())
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                writer.WriteEncodedValue(pki.Intermediate.SubjectName.RawData);
            }

            writer.WriteCharacterString(UniversalTagNumber.IA5String, "http://crl.example/after-a-directory-name.crl", new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        Assert.True(CryptoUtils.TryGetCrlDistributionPointUrl(pki.IssueLeafWithRawCrlDistributionPoints(writer.Encode()), out var url));
        Assert.Equal("http://crl.example/after-a-directory-name.crl", url);

        // A distribution point named relative to the CRL issuer ([1]) carries no URL at all
        writer.Reset();
        using (writer.PushSequence())
        using (writer.PushSequence())
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
        using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("2.5.4.3"); // commonName
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "CRL");
        }

        Assert.False(CryptoUtils.TryGetCrlDistributionPointUrl(pki.IssueLeafWithRawCrlDistributionPoints(writer.Encode()), out _));
    }

    [Fact]
    public void TryGetCrlDistributionPointUrlTreatsMalformedExtensionAsAbsent()
    {
        using var pki = new TestPki();

        Assert.False(CryptoUtils.TryGetCrlDistributionPointUrl(pki.IssueLeafWithRawCrlDistributionPoints([0x30, 0x05, 0x30]), out _));
    }

    /// <summary>
    /// Serves one CRL over HTTP on the loopback interface, so that the platform's chain engine can fetch it.
    /// </summary>
    private sealed class CrlServer : IDisposable
    {
        private readonly HttpListener _listener;

        private CrlServer(HttpListener listener, string url)
        {
            _listener = listener;
            Url = url;
        }

        public string Url { get; }

        public static async Task<CrlServer> StartAsync(byte[] crl)
        {
            HttpListener listener = null;
            string url = null;

            // HttpListener cannot pick a free port itself
            for (int attempt = 0; listener is null; attempt++)
            {
                int port = Random.Shared.Next(20000, 60000);
                var candidate = new HttpListener();
                candidate.Prefixes.Add($"http://127.0.0.1:{port}/");

                try
                {
                    candidate.Start();
                    listener = candidate;
                    url = $"http://127.0.0.1:{port}/{Guid.NewGuid():N}.crl";
                }
                catch (HttpListenerException) when (attempt < 10)
                {
                    candidate.Close();
                }
            }

            var server = new CrlServer(listener, url);

            _ = Task.Run(async () =>
            {
                try
                {
                    while (listener.IsListening)
                    {
                        var context = await listener.GetContextAsync();

                        if (context.Request.Url?.AbsoluteUri == url)
                        {
                            context.Response.ContentType = "application/pkix-crl";
                            context.Response.ContentLength64 = crl.Length;
                            await context.Response.OutputStream.WriteAsync(crl);
                        }
                        else
                        {
                            context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                        }

                        context.Response.Close();
                    }
                }
                catch (Exception) when (!listener.IsListening)
                {
                    // Stopped
                }
            });

            await Task.Yield();

            return server;
        }

        public void Dispose()
        {
            _listener.Stop();
            _listener.Close();
        }
    }
}
