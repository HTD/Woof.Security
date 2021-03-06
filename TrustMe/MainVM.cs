﻿using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using TrustMe.Properties;
using Woof.SecurityEx;
using Woof.WindowsEx;

namespace TrustMe {

    /// <summary>
    /// Uses bound properties and commands from UI to do actual work.
    /// </summary>
    class MainVM : ViewModelBase {

        /// <summary>
        /// Gets or sets installed OpenSSL version.
        /// </summary>
        public string OpenSSLVersion {
            get => _OpenSSLVersion;
            set {
                _OpenSSLVersion = value;
                OnPropertyChanged("OpenSSLVersion");
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether any certificate processing should be enabled.
        /// </summary>
        public bool IsProcessingEnabled { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the site certificate processing should be enabled.
        /// </summary>
        public bool IsSiteProcessingEnabled { get; set; }

        /// <summary>
        /// Gets the root CA certificate info (whatever, currently thumb print).
        /// </summary>
        public string RootCACertInfo {
            get => _RootCACertInfo;
            set {
                _RootCACertInfo = value;
                OnPropertyChanged("RootCACertInfo");
            }
        }

        /// <summary>
        /// Gets the site certificate info (whatever, currently thumb print).
        /// </summary>
        public string SiteCertInfo {
            get => _SiteCertInfo;
            set {
                _SiteCertInfo = value;
                OnPropertyChanged("SiteCertInfo");
            }
        }

        /// <summary>
        /// Gets the current executable (and targetted OS) architecture.
        /// </summary>
        public string TargetArchitecture { get; } = Environment.Is64BitProcess ? "x64" : "x86";

        /// <summary>
        /// Gets or sets the root CA subject distinguished name.
        /// </summary>
        public string RootCA { get; set; }

        /// <summary>
        /// Gets or sets the site subject distinguished name.
        /// </summary>
        public string Site { get; set; }

        /// <summary>
        /// Gets the root CA certificate password.
        /// </summary>
        private string RootCACertPassword => (App.Current.MainWindow as MainWindow).RootCACertPassword.Password;

        /// <summary>
        /// Gets the site certificate password.
        /// </summary>
        private string SiteCertPassword => (App.Current.MainWindow as MainWindow).SiteCertPassword.Password;

        /// <summary>
        /// Initializes the view model, loads the stored settings and executes "Refresh" command.
        /// </summary>
        public MainVM() {
            RootCA = Settings.RootCA;
            Site = Settings.Site;
            Execute("Refresh");
        }

        /// <summary>
        /// Handles UI commands.
        /// </summary>
        /// <param name="parameter">Command to execute.</param>
        public override void Execute(object parameter) {
            switch (parameter as string) {
                case "InstallOpenSSL":
                    try {
                        OpenSsl.Install();
                    }
                    catch (Exception x) {
                        MessageBox.Show(x.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    }
                    finally {
                        OpenSSLVersion = OpenSsl.Version;
                    }
                    break;
                case "InstallRootCACert": {
                        try {
                            if (String.IsNullOrWhiteSpace(RootCACertPassword)) {
                                MessageBox.Show("Root CA certificate password must be set.", "WOOF!", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                                return;
                            }
                            var dn = new DistinguishedName(RootCA);
                            var options = new OpenSslOptions { Password = RootCACertPassword, LeaveFiles = true };
                            OpenSsl.CreateSelfSignedRootCA(dn, options);
                            X509.ImportCertificate(Path.Combine(OpenSsl.OutputDirectory, $"{dn.CN}.pfx"), options.Password, StoreName.Root, StoreLocation.LocalMachine);
                            Execute("Refresh");
                        }
                        catch (Exception x) {
                            MessageBox.Show(x.Message, "WOOF!", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                    break;
                case "InstallSiteCert": {
                        try {
                            var rootDn = new DistinguishedName(RootCA);
                            var rootCACertFileName = rootDn.CN;
                            var rootPfx = Path.Combine(OpenSsl.OutputDirectory, $"{rootCACertFileName}.pfx");
                            var rootCrt = Path.Combine(OpenSsl.OutputDirectory, $"{rootCACertFileName}.crt");
                            var rootKey = Path.Combine(OpenSsl.OutputDirectory, $"{rootCACertFileName}.key");
                            var crtAndKeyExist = File.Exists(rootCrt) && File.Exists(rootKey);
                            var pfxExists = File.Exists(rootPfx);
                            var gotCAPasswd = !String.IsNullOrWhiteSpace(RootCACertPassword);
                            var gotSitePasswd = !String.IsNullOrWhiteSpace(SiteCertPassword);
                            if (!pfxExists && !crtAndKeyExist) {
                                MessageBox.Show("Can't find Root CA certificate file(s).", "WOOF!", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                                return;
                            }
                            if (!crtAndKeyExist && !gotCAPasswd) {
                                MessageBox.Show("Root CA certificate password must be set.", "WOOF!", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                                return;
                            }
                            if (!gotSitePasswd) {
                                MessageBox.Show("Site certificate password must be set.", "WOOF!", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                                return;
                            }
                            var dn = new DistinguishedName(Site);
                            var options = new OpenSslOptions { Password = SiteCertPassword, LeaveFiles = true };
                            OpenSsl.CreateSignedHostCertificate(dn, rootCACertFileName, SiteCertPassword, options);
                            X509.ImportCertificate(Path.Combine(OpenSsl.OutputDirectory, $"{dn.CN}.pfx"), options.Password, StoreName.My, StoreLocation.LocalMachine);
                            Execute("Refresh");
                        }
                        catch (Exception x) {
                            MessageBox.Show(x.Message, "WOOF!", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                    break;
                case "Refresh":
                    OpenSSLVersion = OpenSsl.Version;
                    OnPropertyChanged("RootCA");
                    OnPropertyChanged("Site");
                    RootCACertInfo = GetRootCACertInfo();
                    SiteCertInfo = GetSiteCertInfo();
                    UpdateAvailability();
                    break;
                case "Save":
                    Settings.RootCA = RootCA;
                    Settings.Site = Site;
                    Settings.Save();
                    break;
                case "Load":
                    RootCA = Settings.RootCA;
                    Site = Settings.Site;
                    Execute("Refresh");
                    break;
                case "CertLM":
                    using (var certLM = Process.Start("mmc", "certlm.msc")) { }
                    break;
            }
        }

        private string GetRootCACertInfo() {
            if (String.IsNullOrWhiteSpace(RootCA)) return null;
            var dn = new DistinguishedName(RootCA);
            var cert = X509.GetRootCACertificate(dn.CN);
            if (cert is null) return null;
            return $"[{cert.Thumbprint}] {cert.GetNameInfo(X509NameType.DnsName, false)}";
        }

        private string GetSiteCertInfo() {
            if (String.IsNullOrWhiteSpace(Site)) return null;
            var dn = new DistinguishedName(Site);
            var cert = X509.GetCertificateForHost(dn.CN);
            if (cert is null) return null;
            return $"[{cert.Thumbprint}] {cert.GetNameInfo(X509NameType.DnsName, false)} (issued by {cert.GetNameInfo(X509NameType.DnsName, true)})";
        }

        private void UpdateAvailability() {
            bool lastProcessingEnabled = IsProcessingEnabled, lastSiteProcessingEnabled = IsSiteProcessingEnabled;
            IsProcessingEnabled = !(OpenSSLVersion is null);
            IsSiteProcessingEnabled = IsProcessingEnabled && !(RootCACertInfo is null);
            if (IsProcessingEnabled != lastProcessingEnabled) OnPropertyChanged("IsProcessingEnabled");
            if (IsSiteProcessingEnabled != lastSiteProcessingEnabled) OnPropertyChanged("IsSiteProcessingEnabled");
        }

        private readonly Settings Settings = Settings.Default;
        private string _OpenSSLVersion;
        private string _RootCACertInfo;
        private string _SiteCertInfo;

    }

}
