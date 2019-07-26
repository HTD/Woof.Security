using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

namespace Woof.SecurityEx {

    /// <summary>
    /// The type of logon operation to perform.
    /// </summary>
    public enum LogonType {
        /// <summary>
        /// Intended for users who will be interactively using the computer, such as a user being logged on by a terminal server, remote shell, or similar process. This logon type has the additional expense of caching logon information for disconnected operations; therefore, it is inappropriate for some client/server applications, such as a mail server.
        /// </summary>
        Interactive = 2,
        /// <summary>
        /// Intended for high performance servers to authenticate plaintext passwords. The LogonUser function does not cache credentials for this logon type.
        /// </summary>
        Network = 3,
        /// <summary>
        /// Intended for batch servers, where processes may be executing on behalf of a user without their direct intervention. This type is also for higher performance servers that process many plaintext authentication attempts at a time, such as mail or web servers.
        /// </summary>
        Batch = 4,
        /// <summary>
        /// Indicates a service-type logon. The account provided must have the service privilege enabled.
        /// </summary>
        Service = 5,
        /// <summary>
        /// Preserves the name and password in the authentication package, which allows the server to make connections to other network servers while impersonating the client. A server can accept plaintext credentials from a client, call LogonUser, verify that the user can access the system across the network, and still communicate with other servers.
        /// </summary>
        NetworkClearText = 8,
        /// <summary>
        /// Allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identifier but uses different credentials for other network connections.
        /// </summary>
        NewCredentials = 9
    }

    /// <summary>
    /// The logon provider type enumeration.
    /// </summary>
    public enum LogonProvider {
        /// <summary>
        /// Use the standard logon provider for the system. The default security provider is negotiate, unless you pass NULL for the domain name and the user name is not in UPN format. In this case, the default provider is NTLM.
        /// </summary>
        Default = 0,
        /// <summary>
        /// Use the negotiate logon provider.
        /// </summary>
        WinNT40 = 2,
        /// <summary>
        /// Use the NTLM logon provider.
        /// </summary>
        WinNT50 = 3
    }

    /// <summary>
    /// Extended <see cref="WindowsIdentity"/> class.
    /// </summary>
    public class WindowsIdentityEx : WindowsIdentity {

        /// <summary>
        /// Creates new <see cref="WindowsIdentity"/> from plain text credentials.
        /// </summary>
        /// <param name="user">User name or user principal name.</param>
        /// <param name="domain">Domain name.</param>
        /// <param name="password">Password.</param>
        /// <param name="logonType">Type of logon operation to perform.</param>
        /// <param name="logonProvider">The logon provider type.</param>
        public WindowsIdentityEx(
            string user,
            string domain,
            string password,
            LogonType logonType = LogonType.NetworkClearText,
            LogonProvider logonProvider = LogonProvider.Default)
            : this(userToken: GetIdentity(user, domain, password, logonType, logonProvider)) { }

        /// <summary>
        /// Creates new <see cref="WindowsIdentity"/> from user token as <see cref="NativeMethods.SafeTokenHandle"/>.
        /// </summary>
        /// <param name="userToken">User token obtained from <see cref="GetIdentity(string, string, string, LogonType, LogonProvider)"/> method.</param>
        private WindowsIdentityEx(NativeMethods.SafeTokenHandle userToken) : base(userToken.DangerousGetHandle()) => UserToken = userToken;

        /// <summary>
        /// Attempts to log a user on to the local computer.
        /// </summary>
        /// <param name="user">User name or user principal name.</param>
        /// <param name="domain">Domain name.</param>
        /// <param name="password">Password.</param>
        /// <param name="logonType">Type of logon operation to perform.</param>
        /// <param name="logonProvider">The logon provider type.</param>
        /// <returns>Safe token handle.</returns>
        private static NativeMethods.SafeTokenHandle GetIdentity(string user, string domain, string password, LogonType logonType = LogonType.NetworkClearText, LogonProvider logonProvider = LogonProvider.Default) {
            NativeMethods.LogonUser(user, domain, password, (int)logonType, (int)logonProvider, out NativeMethods.SafeTokenHandle token);
            return token;
        }

        /// <summary>
        /// Disposes user token.
        /// </summary>
        /// <param name="disposing">True on final invocation.</param>
        protected override void Dispose(bool disposing) {
            base.Dispose(disposing);
            if (disposing) UserToken.Dispose();
        }

        private readonly NativeMethods.SafeTokenHandle UserToken;

        /// <summary>
        /// Native methods used by <see cref="WindowsIdentityEx"/>.
        /// </summary>
        static class NativeMethods {

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public extern static bool CloseHandle(IntPtr handle);


            public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid {

                private SafeTokenHandle() : base(true) { }

                [DllImport("kernel32.dll")]
                [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
                [SuppressUnmanagedCodeSecurity]
                [return: MarshalAs(UnmanagedType.Bool)]
                private static extern bool CloseHandle(IntPtr handle);

                protected override bool ReleaseHandle() => CloseHandle(handle);

            }

        }

    }

}