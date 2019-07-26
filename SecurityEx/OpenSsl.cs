using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Woof.SecurityEx {

    /// <summary>
    /// OpenSSL wrapper for creating self-signed X509 certificates.
    /// </summary>
    public static class OpenSsl {

        /// <summary>
        /// Gets or sets the directory for the output files. Default ".cert-files" (relative to current directory).
        /// </summary>
        public static string OutputDirectory { get; set; } = ".cert-files";
        /// <summary>
        /// Gets the OpenSSL executable product version or null if it's not installed in its default directory.
        /// </summary>
        public static string Version {
            get {
                if (!File.Exists(ExePath)) return null;
                var versionInfo = FileVersionInfo.GetVersionInfo(ExePath);
                return versionInfo.ProductVersion;
            }
        }

        /// <summary>
        /// Creates self signed root certification authority.
        /// </summary>
        /// <param name="subjectDn"><see cref="DistinguishedName"/> of the Root CA.</param>
        /// <param name="options"><see cref="OpenSslOptions"/>: Password (default "woof"), FileName (default as CN), LeaveFiles (default false).</param>
        public static void CreateSelfSignedRootCA(DistinguishedName subjectDn, OpenSslOptions options = default) {
            lock (ProcessingLock) {
                if (options is null) options = new OpenSslOptions();
                var subject = String.Join("", subjectDn.Attributes.Select(a => $"/{a}"));
                var fileName = options.FileName ?? subjectDn.CN;
                var escFileName = Esc(fileName);
                var escPassword = Esc(options.Password);
                var escSubject = Esc(subject);
                var cd = Directory.GetCurrentDirectory();
                Directory.CreateDirectory(OutputDirectory);
                Directory.SetCurrentDirectory(OutputDirectory);
                try {
                    var openSslCommands = new[] {
                    $"genrsa -out \"{escFileName}.key\" 2048",
                    $"req -x509 -new -nodes -key \"{escFileName}.key\" -sha256 -days 1024 -subj \"{escSubject}\" -out \"{escFileName}.crt\"",
                    $"pkcs12 -export -in \"{escFileName}.crt\" -inkey \"{escFileName}.key\" -out \"{escFileName}.pfx\" -passout \"pass:{escPassword}\""
                };
                    Exe(openSslCommands, out var output);
                }
                finally {
                    File.Delete($"{fileName}.srl");
                    if (!options.LeaveFiles) {
                        File.Delete($"{fileName}.key");
                        File.Delete($"{fileName}.crt");

                    }
                    Directory.SetCurrentDirectory(cd);
                }
            }
        }

        /// <summary>
        /// Creates signed certificate for host.
        /// </summary>
        /// <param name="subjectDn"><see cref="DistinguishedName"/> of the certificate's subject.</param>
        /// <param name="rootCACertFileName">The file name WITHOUT EXTENSION of the Root CA certificate.</param>
        /// <param name="rootCACertPassword">Password for the root certificate.</param>
        /// <param name="options"><see cref="OpenSslOptions"/>: Password (default "woof"), FileName (default as CN), LeaveFiles (default false).</param>
        public static void CreateSignedHostCertificate(DistinguishedName subjectDn, string rootCACertFileName, string rootCACertPassword, OpenSslOptions options = default) {
            lock (ProcessingLock) {
                if (options is null) options = new OpenSslOptions();
                var subject = String.Join("", subjectDn.Attributes.Select(a => $"/{a}"));
                var fileName = options.FileName ?? subjectDn.CN;
                var escFn = Esc(fileName);
                var escPasswd = Esc(options.Password);
                var escSubject = Esc(subject);
                var escRootFn = Esc(rootCACertFileName);
                var escRootPasswd = Esc(rootCACertPassword);
                var escMinConfigFn = Esc(MinimalConfigFile);
                var escSanConfigFn = Esc(SANExtConfigFile);
                string[] getRootCertWithKey;
                var cd = Directory.GetCurrentDirectory();
                Directory.CreateDirectory(OutputDirectory);
                Directory.SetCurrentDirectory(OutputDirectory);
                try {
                    if (File.Exists($"{rootCACertFileName}.crt") || File.Exists($"{rootCACertFileName}.key")) {
                        getRootCertWithKey = new string[0];
                    }
                    else if (File.Exists($"{rootCACertFileName}.pfx")) {
                        getRootCertWithKey = new[] {
                    $"pkcs12 -in \"{escRootFn}.pfx\" -passin \"pass:{escRootPasswd}\" -passout \"pass:{escRootPasswd}\" -nocerts -out \"{escRootFn}.key\"",
                    $"pkcs12 -in \"{escRootFn}.pfx\" -passin \"pass:{escRootPasswd}\" -clcerts -nokeys -out \"{escRootFn}.crt\"",
                };
                    }
                    else throw new FileNotFoundException("Root CA certificate file not found");
                    var createSigned =
                        new[] {
                    $"genrsa -out \"{escFn}.key\" 2048",
                    $"req -config \"{escMinConfigFn}\" -new -key \"{escFn}.key\" -subj \"{escSubject}\" -out \"{escFn}.csr\"",
                    $"x509 -req -in \"{escFn}.csr\" -extensions san -extfile \"{escSanConfigFn}\" -CA \"{escRootFn}.crt\" -CAkey \"{escRootFn}.key\" -passin \"pass:{escRootPasswd}\" -CAcreateserial -out \"{fileName}.crt\" -days 1024 -sha256",
                    $"pkcs12 -export -in \"{escFn}.crt\" -inkey \"{escFn}.key\" -out \"{escFn}.pfx\" -certfile \"{escRootFn}.crt\" -passin \"pass:{escRootPasswd}\" -passout \"pass:{escPasswd}\""
                        };

                    File.WriteAllText(MinimalConfigFile, "[req]\r\ndistinguished_name=req");
                    File.WriteAllText(SANExtConfigFile, $"[san]\r\nsubjectAltName=DNS:{subjectDn.CN}");
                    Exe(getRootCertWithKey.Concat(createSigned), out var output);
                }
                finally {
                    File.Delete(MinimalConfigFile);
                    File.Delete(SANExtConfigFile);
                    File.Delete($"{rootCACertFileName}.srl");
                    if (!options.LeaveFiles) {
                        File.Delete($"{rootCACertFileName}.key");
                        File.Delete($"{rootCACertFileName}.crt");
                        File.Delete($"{fileName}.key");
                        File.Delete($"{fileName}.csr");
                        File.Delete($"{fileName}.crt");
                    }
                    Directory.SetCurrentDirectory(cd);
                }
            }
        }

        /// <summary>
        /// Escapes command line arguments.
        /// </summary>
        /// <param name="input">Command line argument.</param>
        /// <returns>Escaped version.</returns>
        private static string Esc(string input) => input.Replace("\"", "\\\"");

        /// <summary>
        /// Executes OpenSSL command.
        /// </summary>
        /// <param name="commandLine">Command line.</param>
        /// <param name="output">Command output.</param>
        /// <exception cref="FileNotFoundException">Thrown when the OpenSSL executable is not found.</exception>
        /// <exception cref="InvalidOperationException">Thrown when OpenSSL returns an error message.</exception>
        private static void Exe(string commandLine, out string output) {
            if (!File.Exists(ExePath)) {
                Install();
                if (!File.Exists(ExePath)) throw new FileNotFoundException(MissingExeMessage);
            }
            var psi = new ProcessStartInfo(ExePath, commandLine) {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            string errors;
            using (var process = new Process() { StartInfo = psi }) {
                process.Start();
                process.WaitForExit();
                using (process.StandardError) errors = process.StandardError.ReadToEnd();
                using (process.StandardOutput) output = process.StandardOutput.ReadToEnd();
            }
            if (errors.Length > output.Length) output = errors;
            var errorOccured = output.Contains("an't") || output.Contains("invalid") || output.Contains("error");
            if (errorOccured) throw new InvalidOperationException(errors);
        }

        /// <summary>
        /// Executes a chain of OpenSSL commands.
        /// </summary>
        /// <param name="commands">Commands to execute.</param>
        /// <param name="output">Combined output.</param>
        /// <exception cref="FileNotFoundException">Thrown when the OpenSSL executable is not found.</exception>
        /// <exception cref="InvalidOperationException">Thrown when OpenSSL returns an error message.</exception>
        private static void Exe(IEnumerable<string> commands, out string output) {
            var builder = new StringBuilder();
            foreach (var command in commands) {
                Exe(command, out var commandOutput);
                builder.AppendLine(commandOutput);
            }
            output = builder.ToString();
        }

        /// <summary>
        /// Downloads the latest version of OpenSSL for Windows x64 from Shining Light Productions website.
        /// </summary>
        /// <returns>Path to the downloaded file.</returns>
        private static string DownloadOpenSsl() {
            try {
                var site = "https://slproweb.com";
                string html;
                using (var client = new WebClient()) html = client.DownloadString($"{site}/products/Win32OpenSSL.html");
                var arch = Environment.Is64BitProcess ? "64" : "32";
                var start = html.IndexOf($"/download/Win{arch}OpenSSL_Light-");
                var end = html.IndexOf("\"", start);
                var path = html.Substring(start, end - start);
                var fileName = path.Replace("/download/", "");
                using (var client = new WebClient()) client.DownloadFile($"{site}{path}", fileName);
                return fileName;
            }
            catch (Exception) {
                throw new InvalidDataException("OpenSSL was not found on Shining Light Productions website. You're on your own now.");
            }
        }

        /// <summary>
        /// Downloads and installs OpenSSL from Shining Light Productions website.
        /// </summary>
        public static void Install() {
            var fileName = DownloadOpenSsl();
            var filePath = Path.GetFullPath(fileName);
            var process = Process.Start(new ProcessStartInfo(filePath) { UseShellExecute = false });
            process.WaitForExit();
        }

        /// <summary>
        /// Gets or sets directory where OpenSSL executable is installed.
        /// </summary>
        private static string OpenSSLDirectory { get; set; }
            = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.Is64BitProcess ? @"OpenSSL-Win64" : @"OpenSSL-Win32", "bin");

        /// <summary>
        /// Gets the path to the OpenSSL executable.
        /// </summary>
        private static string ExePath => Path.Combine(OpenSSLDirectory, "openssl.exe");

        private static readonly object ProcessingLock = new object();

        /// <summary>
        /// Temporary minimal configuration file name for OpenSSL.
        /// </summary>
        private const string MinimalConfigFile = ".openssl-minimal.cnf";

        /// <summary>
        /// Temporary SAN extension file name for OpenSSL.
        /// </summary>
        private const string SANExtConfigFile = ".openssl-ext-x509.cnf";

        /// <summary>
        /// Exception message for missing OpenSSL executable.
        /// </summary>
        private const string MissingExeMessage = "OpenSSL not found. Check X509.OpenSslDirectory field or install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html.";

    }

    /// <summary>
    /// Options for OpenSSL methods.
    /// </summary>
    public sealed class OpenSslOptions {

        /// <summary>
        /// Gets or sets a password for storing certificate's private keys. Default "woof".
        /// </summary>
        public string Password { get; set; } = "woof";

        /// <summary>
        /// Gets or sets an optional file name for storing the certificate target files. If not set, the certificate subject's CN will be used.
        /// </summary>
        public string FileName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the generated target intermediate files should be left after exporting the certificate to PFX format.
        /// </summary>
        public bool LeaveFiles { get; set; }

    }

}