using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;

namespace Woof.SecurityEx {

    /// <summary>
    /// OpenSSL wrapper for creating self-signed X509 certificates.
    /// </summary>
    public static class OpenSsl {

        /// <summary>
        /// Gets or sets directory where OpenSSL executable is installed.
        /// </summary>
        public static string ExeDirectory { get; set; } = @"C:\OpenSSL-Win64\bin";

        /// <summary>
        /// Creates self signed root certification authority.
        /// </summary>
        /// <param name="name">Name of the certification authority.</param>
        /// <param name="organization">Organization.</param>
        /// <param name="password">Password for pfx file, default "woof".</param>
        /// <param name="leaveFiles">If true, intermediate files won't be deleted.</param>
        /// <returns>True if successfull.</returns>
        public static bool CreateSelfSignedRootCA(string name, string organization, string password = "woof", bool leaveFiles = false) {
            try {
                var openSslCommands = new[] {
                    $"genrsa -out \"{name}.key\" 2048",
                    $"req -x509 -new -nodes -key \"{name}.key\" -sha256 -days 1024 -subj \"/O={organization}/CN={name}\" -out \"{name}.crt\"",
                    $"pkcs12 -export -in \"{name}.crt\" -inkey \"{name}.key\" -out \"{name}.pfx\" -passout pass:{password}"
                };
                return Exe(openSslCommands, out var output);
            }
            finally {
                if (!leaveFiles) {
                    File.Delete($"{name}.key");
                    File.Delete($"{name}.crt");
                    File.Delete($"{name}.srl");
                }
            }
        }

        /// <summary>
        /// Creates signed certificate for host.
        /// </summary>
        /// <param name="name">Host name (domain name).</param>
        /// <param name="organization">Organization.</param>
        /// <param name="rootName">Name of the root certificate.</param>
        /// <param name="password">Password for pfx file, default "woof".</param>
        /// <param name="leaveFiles">Set true to leave intermediate key, csr, crt, srl files.</param>
        /// <returns>True if successfull.</returns>
        public static bool CreateSignedHostCertificate(string name, string organization, string rootName, string password = "woof", bool leaveFiles = false) {
            try {
                var openSslCommands = File.Exists($"{rootName}.pfx")
                    ? new[] {
                        $"pkcs12 -in \"{rootName}.pfx\" -passin pass:{password} -passout pass:{password} -nocerts -out \"{rootName}.key\"",
                        $"pkcs12 -in \"{rootName}.pfx\" -passin pass:{password} -clcerts -nokeys -out \"{rootName}.crt\"",
                        $"genrsa -out \"{name}.key\" 2048",
                        $"req -new -key \"{name}.key\" -subj \"/O={organization}/CN={name}\" -out \"{name}.csr\"",
                        $"x509 -req -in \"{name}.csr\" -CA \"{rootName}.crt\" -CAkey \"{rootName}.key\" -passin pass:{password} -CAcreateserial -out \"{name}.crt\" -days 1024 -sha256",
                        $"pkcs12 -export -in \"{name}.crt\" -inkey \"{name}.key\" -out \"{name}.pfx\" -certfile \"{rootName}.crt\" -passin pass:{password} -passout pass:{password}"
                    }
                    : new[] {
                        $"genrsa -out \"{rootName}.key\" 2048",
                        $"req -x509 -new -nodes -key \"{rootName}.key\" -sha256 -days 1024 -subj \"/O={organization}/CN={rootName}\" -out \"{rootName}.crt\"",
                        $"pkcs12 -export -in \"{rootName}.crt\" -inkey \"{rootName}.key\" -out \"{rootName}.pfx\" -passout pass:{password}",
                        $"genrsa -out \"{name}.key\" 2048",
                        $"req -new -key \"{name}.key\" -subj \"/O={organization}/CN={name}\" -out \"{name}.csr\"",
                        $"x509 -req -in \"{name}.csr\" -CA \"{rootName}.crt\" -CAkey \"{rootName}.key\" -CAcreateserial -out \"{name}.crt\" -days 1024 -sha256",
                        $"pkcs12 -export -in \"{name}.crt\" -inkey \"{name}.key\" -out \"{name}.pfx\" -certfile \"{rootName}.crt\" -passout pass:{password}"
                    };
                var result = Exe(openSslCommands, out var output);
                return result;
                
            } finally {
                if (!leaveFiles) {
                    File.Delete($"{rootName}.key");
                    File.Delete($"{rootName}.crt");
                    File.Delete($"{rootName}.srl");
                    File.Delete($"{name}.key");
                    File.Delete($"{name}.csr");
                    File.Delete($"{name}.crt");
                }
            }
        }

        /// <summary>
        /// Executes OpenSSL command.
        /// </summary>
        /// <param name="commandLine">Command line.</param>
        /// <param name="output">Command output.</param>
        /// <returns>True if successfull.</returns>
        private static bool Exe(string commandLine, out string output) {
            if (!File.Exists(ExePath)) {
                InstallOpenSsl();
                if (!File.Exists(ExePath)) throw new FileNotFoundException(MissingExeMessage);
            }
            var psi = new ProcessStartInfo(ExePath, commandLine) {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            var process = new Process() { StartInfo = psi };
            process.Start();
            process.WaitForExit();
            var encoding = Encoding.UTF8;
            string errors;
            using (process.StandardError) errors = process.StandardError.ReadToEnd();
            using (process.StandardOutput) output = process.StandardOutput.ReadToEnd();
            if (errors.Length > output.Length) output = errors;
            var errorOccured = output.Contains("an't") || output.Contains("invalid") || output.Contains("error");
            return !errorOccured;
        }

        /// <summary>
        /// Executes a chain of OpenSSL commands.
        /// </summary>
        /// <param name="commands">Commands to execute.</param>
        /// <param name="output">Combined output.</param>
        /// <returns>True if successfull.</returns>
        private static bool Exe(string[] commands, out string output) {
            var outputs = new List<string>();
            foreach (var command in commands) {
                if (!Exe(command, out var commandOutput)) { output = commandOutput; return false; }
                outputs.Add(commandOutput);
            }
            output = string.Join(Environment.NewLine, outputs);
            return true;
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
                var start = html.IndexOf("/download/Win64OpenSSL_Light-");
                var end = html.IndexOf("\"", start);
                var path = html.Substring(start, end - start);
                var fileName = path.Replace("/download/", "");
                using (var client = new WebClient()) client.DownloadFile($"{site}{path}", fileName);
                return fileName;
            } catch (Exception) {
                throw new InvalidDataException("OpenSSL was not found on Shining Light Productions website. You're on your own now.");
            }
        }

        /// <summary>
        /// Downloads and installs OpenSSL from Shining Light Productions website.
        /// </summary>
        private static void InstallOpenSsl() {
            var fileName = DownloadOpenSsl();
            var filePath = Path.GetFullPath(fileName);
            var process = Process.Start(new ProcessStartInfo(filePath) { UseShellExecute = false });
            process.WaitForExit();
        }

        /// <summary>
        /// Gets the path to the OpenSSL executable.
        /// </summary>
        private static string ExePath => Path.Combine(ExeDirectory, "openssl.exe");

        /// <summary>
        /// Exception message for missing OpenSSL executable.
        /// </summary>
        private const string MissingExeMessage = "OpenSSL not found. Check X509.OpenSslDirectory field or install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html.";

    }

}