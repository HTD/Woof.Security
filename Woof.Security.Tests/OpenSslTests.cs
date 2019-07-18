using System;
using Xunit;
using Woof.SecurityEx;
using System.Security.Cryptography.X509Certificates;

namespace Woof.Security.Tests {
    public class OpenSslTests {

        private const string CAName = "CodeDog Root CA";
        private const string CAPasswd = "woof";
        private const string Organization = "CodeDog Ltd";
        private const string HostName = "codedog.test.net";

        [Fact]
        public void RootCA() {
            Assert.True(OpenSsl.CreateSelfSignedRootCA(CAName, Organization));
            if (!X509.RootCertificateExists(CAName)) X509.ImportCertificate($"{CAName}.pfx", CAPasswd, StoreName.Root, StoreLocation.LocalMachine);
        }


        [Fact]
        public void HostCert() {
            if (!X509.RootCertificateExists(CAName)) RootCA();
            Assert.True(OpenSsl.CreateSignedHostCertificate(HostName, Organization, CAName));
            if (!X509.CertificateExists(HostName)) X509.ImportCertificate($"{HostName}.pfx", CAPasswd, StoreName.My, StoreLocation.LocalMachine);
        }

    }

}