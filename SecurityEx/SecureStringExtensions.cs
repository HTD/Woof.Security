using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Woof.SecurityEx {

    /// <summary>
    /// Extensions for <see cref="SecureString"/> and some other classes making <see cref="SecureString"/> type way more usable, yet still secure.
    /// </summary>
    public static class SecureStringExtensions {
        
        /// <summary>
        /// Encrypts secure string and returns encrypted data.
        /// </summary>
        /// <param name="s">This <see cref="SecureString"/>.</param>
        /// <param name="scope">Scope of the data protection (default <see cref="DataProtectionScope.CurrentUser"/>).</param>
        /// <returns>Encrypted data.</returns>
        public static byte[] Protect(this SecureString s, DataProtectionScope scope = DataProtectionScope.CurrentUser) {
            var udata = Marshal.SecureStringToGlobalAllocUnicode(s);
            var plain = new DataBlob { Data = udata, Length = s.Length << 1 };
            var cipher = DataBlob.Empty;
            var flags = scope == DataProtectionScope.CurrentUser ? CryptProtectFlags.None : CryptProtectFlags.LocalMachine;
            try {
                NativeMethods.CryptProtectData(plain, null, DataBlob.Empty, IntPtr.Zero, CryptProtectPrompt.Empty, flags, out cipher);
                var buffer = new byte[cipher.Length];
                Marshal.Copy(cipher.Data, buffer, 0, cipher.Length);
                return buffer;
            }
            finally {
                if (plain.Data != IntPtr.Zero) Marshal.FreeHGlobal(plain.Data);
                if (cipher.Data != IntPtr.Zero) Marshal.FreeHGlobal(cipher.Data);
            }
        }

        /// <summary>
        /// Decrypts protected data to <see cref="SecureString"/>.
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="scope">Scope of the data protection (default <see cref="DataProtectionScope.CurrentUser"/>).</param>
        /// <returns><see cref="SecureString"/>.</returns>
        public unsafe static SecureString Unprotect(this byte[] data, DataProtectionScope scope = DataProtectionScope.CurrentUser) {
            var cipher = new DataBlob { Length = data.Length, Data = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, cipher.Data, data.Length);
            var plain = DataBlob.Empty;
            var flags = scope == DataProtectionScope.CurrentUser ? CryptProtectFlags.None : CryptProtectFlags.LocalMachine;
            try {
                if (NativeMethods.CryptUnprotectData(cipher, null, DataBlob.Empty, IntPtr.Zero, CryptProtectPrompt.Empty, flags, out plain))
                    return new SecureString((char*)plain.Data, plain.Length >> 1);
                throw new UnauthorizedAccessException($"Could not unprotect the data in {scope} context");
            }
            finally {
                if (plain.Data != IntPtr.Zero) Marshal.FreeHGlobal(plain.Data);
                if (cipher.Data != IntPtr.Zero) Marshal.FreeHGlobal(cipher.Data);
            }
        }

        /// <summary>
        /// Writes the <see cref="SecureString"/> to the <see cref="StreamWriter"/>.
        /// As plain text, however it doesn't create managed string in memory.
        /// </summary>
        /// <param name="sw">This <see cref="StreamWriter"/>.</param>.
        /// <param name="ss"><see cref="SecureString"/>.</param>
        public unsafe static void WriteSecureString(this StreamWriter sw, SecureString ss) {
            var c = (char*)Marshal.SecureStringToGlobalAllocUnicode(ss);
            for (int i = 0, n = ss.Length; i < n; i++) sw.Write(*(c + i));
            Marshal.ZeroFreeGlobalAllocUnicode((IntPtr)c);
        }

        /// <summary>
        /// Reads secure string from the stream reader, the secure string must be followed by CRLF, LF, or EOF.
        /// </summary>
        /// <param name="sr">This <see cref="StreamReader"/>.</param>
        /// <returns>Secure string read from reader.</returns>
        public static SecureString ReadSecureString(this StreamReader sr) {
            int c;
            SecureString s = new SecureString();
            while ((c = sr.Read()) >= 0) {
                var code = sr.BaseStream.ReadByte();
                if (c == 13) continue; // CR
                if (c == 10) break; // LF
                s.AppendChar((char)c);
            }
            return s;
        }

        /// <summary>
        /// Converts secure string into plain string.
        /// WARNING: INVOKING THIS DEFEATS THE PURPOSE OF <see cref="SecureString"/>, use only for debugging.
        /// </summary>
        /// <param name="s">This <see cref="SecureString"/>.</param>
        /// <returns>Plain string.</returns>
        public static string Peek(this SecureString s) {
            if (s == null) return null;
            var bstr = Marshal.SecureStringToBSTR(s);
            try {
                return Marshal.PtrToStringBSTR(bstr);
            } finally {
                Marshal.ZeroFreeBSTR(bstr);
            }
        }

        #region P/Invoke

        #region Structures / constants / enumerations

        /// <summary>
        /// Flags that indicate when prompts to the user are to be displayed.
        /// </summary>
        [Flags]
        private enum CryptProtectPromptFlags {

            /// <summary>
            /// No prompts.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// This flag is used to provide the prompt for the protect phase.
            /// </summary>
            PromptOnUnprotect = 0x1,

            /// <summary>
            /// This flag can be combined with CRYPTPROTECT_PROMPT_ON_PROTECT to enforce the UI (user interface) policy of the caller. When CryptUnprotectData is called, the dwPromptFlags specified in the CryptProtectData call are enforced.
            /// </summary>
            PromptOnProtect = 0x2

        }

        /// <summary>
        /// Provides the text of a prompt and information about when and where that prompt is to be displayed when using the CryptProtectData and CryptUnprotectData functions.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CryptProtectPrompt {

            /// <summary>
            /// The size, in bytes, of this structure.
            /// </summary>
            public int Size;

            /// <summary>
            /// DWORD flags that indicate when prompts to the user are to be displayed.
            /// </summary>
            public CryptProtectPromptFlags Flags;

            /// <summary>
            /// Window handle to the parent window.
            /// </summary>
            public IntPtr AppHandle;

            /// <summary>
            /// A string containing the text of a prompt to be displayed.
            /// </summary>
            public String Prompt;

            /// <summary>
            /// Gets empty prompt structure.
            /// </summary>
            public static CryptProtectPrompt Empty => new CryptProtectPrompt {
                Size = Marshal.SizeOf(typeof(CryptProtectPrompt)),
                Flags = CryptProtectPromptFlags.None,
                AppHandle = IntPtr.Zero,
                Prompt = null
            };

        }

        /// <summary>
        /// Flags for CryptProtectData and CryptUnprotectData native methods.
        /// </summary>
        [Flags]
        private enum CryptProtectFlags {

            /// <summary>
            /// No flags.
            /// </summary>
            None = 0x0,

            /// <summary>
            /// For remote-access situations where UI is not an option if UI was specified on protect or unprotect operation, the call will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION.
            /// </summary>
            UiForbidden = 0x1,

            /// <summary>
            /// Per machine protected data -- any user on machine where CryptProtectData took place may CryptUnprotectData.
            /// </summary>
            LocalMachine = 0x4,

            /// <summary>
            /// Force credential synchronize during CryptProtectData() Synchronize is only operation that occurs during this operation.
            /// </summary>
            CreadSync = 0x8,

            /// <summary>
            /// Generate an Audit on protect and unprotect operations.
            /// </summary>
            Audit = 0x10,

            /// <summary>
            /// Protect data with a non-recoverable key.
            /// </summary>
            NoRecovery = 0x20,

            /// <summary>
            /// Verify the protection of a protected blob.
            /// </summary>
            VerifyProtection = 0x40

        }

        /// <summary>
        /// Contains an arbitrary array of bytes.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DataBlob {

            /// <summary>
            /// Data length in bytes.
            /// </summary>
            public int Length;

            /// <summary>
            /// A pointer to the data buffer.
            /// </summary>
            public IntPtr Data;

            /// <summary>
            /// Gets empty <see cref="DataBlob"/> structure.
            /// </summary>
            public static DataBlob Empty => new DataBlob { };
            
        }

        #endregion

        /// <summary>
        /// Unmanaged data protection methods.
        /// </summary>
        private static class NativeMethods {

            [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptProtectData(
                DataBlob pDataIn,
                String szDataDescr,
                DataBlob pOptionalEntropy,
                IntPtr pvReserved,
                CryptProtectPrompt pPromptStruct,
                CryptProtectFlags dwFlags,
                out DataBlob pDataOut
            );

            [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptUnprotectData(
                DataBlob pDataIn,
                StringBuilder szDataDescr,
                DataBlob pOptionalEntropy,
                IntPtr pvReserved,
                CryptProtectPrompt pPromptStruct,
                CryptProtectFlags dwFlags,
                out DataBlob pDataOut
            );

        }

        #endregion

    }

}