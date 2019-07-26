using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Woof.SecurityEx;
using Xunit;

namespace Woof.Security.Tests {
    public class Tests {

        [/*Fun*/Fact]
        public void DistinguishedName() {
            var dn1 = new DistinguishedName(@"CN=test,O=CodeDog\, Ltd.,OU=dev");
            Assert.Equal("test", dn1.CN);
            Assert.Equal(@"CodeDog, Ltd.", dn1["o"]);
            Assert.Equal(@"dev", dn1["ou"]);
            var dn2 = new DistinguishedName("test");
            Assert.Equal("test", dn2.CN);
            Assert.Equal("CN=test", dn2);
            var dn3 = new DistinguishedName("A=1,B=2,C=3");
            var dn4 = new DistinguishedName("B=2,C=3,A=1");
            Assert.True(dn3 == dn4);
        }

        [/*Fun*/Fact]
        public void OpenSsl_CreateSelfSigned() {
            var caSubject = new DistinguishedName("CN=CodeDog Root CA,O=CodeDog,C=PL");
            var mySubject = new DistinguishedName("test.site");
            var caOptions = new OpenSslOptions();
            var myOptions = new OpenSslOptions();
            OpenSsl.CreateSelfSignedRootCA(caSubject, caOptions);
            OpenSsl.CreateSignedHostCertificate(mySubject, caSubject.CN, myOptions.Password);
            var caFileName = Path.Combine(OpenSsl.OutputDirectory, $"{caSubject.CN}.pfx");
            var myFileName = Path.Combine(OpenSsl.OutputDirectory, $"{mySubject.CN}.pfx");
            using var rootCert = X509.GetCertificateFromFile(caFileName, caOptions.Password, X509KeyStorageFlags.EphemeralKeySet);
            using var siteCert = X509.GetCertificateFromFile(myFileName, myOptions.Password, X509KeyStorageFlags.EphemeralKeySet);
            Assert.Equal(caSubject.CN, rootCert.GetNameInfo(X509NameType.DnsName, false));
            Assert.Equal(caSubject.CN, rootCert.GetNameInfo(X509NameType.DnsName, true));
            Assert.Equal(mySubject.CN, siteCert.GetNameInfo(X509NameType.DnsName, false));
            Assert.Equal(caSubject.CN, siteCert.GetNameInfo(X509NameType.DnsName, true));
        }

    }

};