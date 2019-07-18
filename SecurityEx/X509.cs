using System.Security.Cryptography.X509Certificates;

namespace Woof.SecurityEx {

    /// <summary>
    /// Fast automated X.509 certificate operations.
    /// </summary>
    public static class X509 {

        /// <summary>
        /// Returns true if the certificate for specified host name exists in one of the certificate stores.
        /// </summary>
        /// <param name="hostName">Host name the certificate is issued for.</param>
        /// <returns>True if exists.</returns>
        public static bool CertificateExists(string hostName) => GetCertificateForHost(hostName) != null;

        /// <summary>
        /// Tests if root CA with specified name exists.
        /// </summary>
        /// <param name="name">IssuedTo CN.</param>
        /// <returns>True if certificate exists.</returns>
        public static bool RootCertificateExists(string name) {
            X509Store store = null;
            X509CertificateCollection matches;
            try {
                var locations = new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser };
                foreach (var storeLocation in locations) {
                    store = new X509Store(StoreName.Root, storeLocation);
                    store.Open(OpenFlags.ReadOnly);
                    matches = store.Certificates.Find(X509FindType.FindBySubjectName, name, true);
                    if (matches.Count > 0) return true;
                    store.Close();
                    store = null;
                }
                return false;
            }
            finally {
                store?.Close();
            }
        }

        /// <summary>
        /// Gets the X.509 certificate for the specified host name from system and user stores.
        /// </summary>
        /// <param name="hostName">Host name the certificate is issued for.</param>
        /// <returns>X.509 certificate or null if no matching certificate is found in applicable stores.</returns>
        /// <remarks>The certificate is searched in computer store, then in user store.</remarks>
        public static X509Certificate2 GetCertificateForHost(string hostName) {
            if (hostName == null) return null;
            X509Store store = null;
            X509CertificateCollection matches;
            try {
                var stores = new[] { StoreName.My, StoreName.TrustedPublisher };
                var locations = new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser };
                foreach (var storeLocation in locations)
                    foreach (var storeName in stores) {
                        store = new X509Store(storeName, storeLocation);
                        store.Open(OpenFlags.ReadOnly);
                        matches = store.Certificates.Find(X509FindType.FindBySubjectName, hostName, true);
                        if (matches.Count > 0) return matches[0] as X509Certificate2;
                        store.Close();
                        store = null;
                    }
                return null;
            }
            finally {
                store?.Close();
            }
        }

        /// <summary>
        /// Imports X.509 certificate from file to certificate store.
        /// </summary>
        /// <param name="fileName">Certificate file.</param>
        /// <param name="password">Password.</param>
        /// <param name="storeName">Store name.</param>
        /// <param name="storeLocation">Store location.</param>
        public static void ImportCertificate(string fileName, string password, StoreName storeName, StoreLocation storeLocation) {
            var keyStorageFlags =
                X509KeyStorageFlags.PersistKeySet
                | (storeLocation == StoreLocation.LocalMachine ? X509KeyStorageFlags.MachineKeySet : X509KeyStorageFlags.UserKeySet);
            var cert = new X509Certificate2(fileName, password, keyStorageFlags);
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.MaxAllowed);
            store.Add(cert);
            store.Close();
        }

    }

}