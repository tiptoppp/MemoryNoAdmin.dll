using System;
using System.IO;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Globalization;
using System.Threading.Tasks;
using System.ComponentModel;
using static MemoryNoAdmin.Imps;

namespace MemoryNoAdmin
{
    public partial class Mem
    {
        public Proc mProc = new Proc();

        public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
        {
            UIntPtr retVal;

            if (mProc.Is64Bit || IntPtr.Size == 8)
            {
                MEMORY_BASIC_INFORMATION64 tmp64 = new MEMORY_BASIC_INFORMATION64();
                retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64, new UIntPtr((uint)Marshal.SizeOf(tmp64)));

                lpBuffer.BaseAddress = tmp64.BaseAddress;
                lpBuffer.AllocationBase = tmp64.AllocationBase;
                lpBuffer.AllocationProtect = tmp64.AllocationProtect;
                lpBuffer.RegionSize = (long)tmp64.RegionSize;
                lpBuffer.State = tmp64.State;
                lpBuffer.Protect = tmp64.Protect;
                lpBuffer.Type = tmp64.Type;

                return retVal;
            }
            MEMORY_BASIC_INFORMATION32 tmp32 = new MEMORY_BASIC_INFORMATION32();

            retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

            lpBuffer.BaseAddress = tmp32.BaseAddress;
            lpBuffer.AllocationBase = tmp32.AllocationBase;
            lpBuffer.AllocationProtect = tmp32.AllocationProtect;
            lpBuffer.RegionSize = tmp32.RegionSize;
            lpBuffer.State = tmp32.State;
            lpBuffer.Protect = tmp32.Protect;
            lpBuffer.Type = tmp32.Type;

            return retVal;
        }

        public bool OpenProcess(int pid, out string FailReason){

            if (pid <= 0){
                FailReason = "OpenProcess given proc ID 0.";
                return false;
            }


            if (mProc.Process != null && mProc.Process.Id == pid){
                FailReason = "mProc.Process is null";
                return true;
            }

            try{
                mProc.Process = Process.GetProcessById(pid);

                if (mProc.Process != null && !mProc.Process.Responding){
                    FailReason = "Process is not responding or null.";
                    return false;
                }

                mProc.Handle = Imps.OpenProcess(0x1F0FFF, true, pid);

                if (mProc.Handle == IntPtr.Zero){
                    var eCode = Marshal.GetLastWin32Error();
                       mProc = null;
                    FailReason = "failed opening a handle to the target process(GetLastWin32ErrorCode: " + eCode + ")";
                    return false;
                }

                mProc.Is64Bit = Environment.Is64BitOperatingSystem && (IsWow64Process(mProc.Handle, out bool retVal) && !retVal);

                mProc.MainModule = mProc.Process.MainModule;

                FailReason = "";
                return true;
            }catch (Exception ex) {
                FailReason = "OpenProcess has crashed. " + ex;
                return false;
            }
        }

        public bool OpenProcess(string proc, out string FailReason)
        {
            return OpenProcess(GetProcIdFromName(proc), out FailReason);
        }

        public bool OpenProcess(string proc)
        {
            return OpenProcess(GetProcIdFromName(proc), out string FailReason);
        }

        public bool OpenProcess(int pid){
            return OpenProcess(pid, out string FailReason);
        }

   public void SetFocus(){
            SetForegroundWindow(mProc.Process.MainWindowHandle);
        }

        public int GetProcIdFromName(string name)
        {
            Process[] processlist = Process.GetProcesses();

            if (name.ToLower().Contains(".exe"))
                name = name.Replace(".exe", "");
            if (name.ToLower().Contains(".bin"))
                name = name.Replace(".bin", "");

            foreach (System.Diagnostics.Process theprocess in processlist)
            {
                if (theprocess.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase))
                    return theprocess.Id;
            }

            return 0;
        }

        public string LoadCode(string name, string iniFile)
        {
            StringBuilder returnCode = new StringBuilder(1024);
            uint read_ini_result;

            if (!String.IsNullOrEmpty(iniFile)){
                if (File.Exists(iniFile))
                    read_ini_result = GetPrivateProfileString("codes", name, "", returnCode, (uint)returnCode.Capacity, iniFile);
                      
            }else
                returnCode.Append(name);

            return returnCode.ToString();
        }

        private int LoadIntCode(string name, string path)
        {
            try{
                int intValue = Convert.ToInt32(LoadCode(name, path), 16);
                if (intValue >= 0)
                    return intValue;
                else
                    return 0;
            } catch{
                return 0;
            }
        }

        public void ThreadStartClient(string func, string name)
        {
            using (NamedPipeClientStream pipeStream = new NamedPipeClientStream(name))
            {
                if (!pipeStream.IsConnected)
                    pipeStream.Connect();

                using (StreamWriter sw = new StreamWriter(pipeStream))
                {
                    if (!sw.AutoFlush)
                        sw.AutoFlush = true;
                    sw.WriteLine(func);
                }
            }
        }        

        #region protection

        public bool ChangeProtection(string code, MemoryProtection newProtection, out MemoryProtection oldProtection, string file = "")
        {
	        UIntPtr theCode = GetCode(code, file);
	        if (theCode == UIntPtr.Zero 
	            || mProc.Handle == IntPtr.Zero)
	        {
		        oldProtection = default;
		        return false;
	        }

	        return VirtualProtectEx(mProc.Handle, theCode, (IntPtr)(mProc.Is64Bit ? 8 : 4), newProtection, out oldProtection);
        }
        #endregion

        public UIntPtr GetCode(string name, string path = "", int size = 8)
        {
            string theCode = "";
            if (mProc == null)
                return UIntPtr.Zero;

            if (mProc.Is64Bit){
                if (size == 8) size = 16;
                return Get64BitCode(name, path, size);
            }

            if (!String.IsNullOrEmpty(path))
                theCode = LoadCode(name, path);
            else
                theCode = name;

            if (String.IsNullOrEmpty(theCode))
                return UIntPtr.Zero;

            if (theCode.Contains(" "))
                theCode = theCode.Replace(" ", String.Empty);

            if (!theCode.Contains("+") && !theCode.Contains(","))
            {
                try
                {
                    return new UIntPtr(Convert.ToUInt32(theCode, 16));
                } catch{
                    return UIntPtr.Zero;
                }
            }

            string newOffsets = theCode;

            if (theCode.Contains("+"))
                newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

            byte[] memoryAddress = new byte[size];

            if (newOffsets.Contains(','))
            {
                List<int> offsetsList = new List<int>();

                string[] newerOffsets = newOffsets.Split(',');
                foreach (string oldOffsets in newerOffsets)
                {
                    string test = oldOffsets;
                    if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x","");
                    int preParse = 0;
                    if (!oldOffsets.Contains("-"))
                        preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                    else
                    {
                        test = test.Replace("-", "");
                        preParse = Int32.Parse(test, NumberStyles.AllowHexSpecifier);
                        preParse = preParse * -1;
                    }
                    offsetsList.Add(preParse);
                }
                int[] offsets = offsetsList.ToArray();

                if (theCode.Contains("base") || theCode.Contains("main"))
                    ReadProcessMemory(mProc.Handle, (UIntPtr)((int)mProc.MainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    IntPtr altModule = IntPtr.Zero;
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = GetModuleAddressByName(moduleName[0]);
                        }
                        catch
                        {
                    
                        }
                    }
                    ReadProcessMemory(mProc.Handle, (UIntPtr)((int)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
                else
                    ReadProcessMemory(mProc.Handle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

                uint num1 = BitConverter.ToUInt32(memoryAddress, 0);

                UIntPtr base1 = (UIntPtr)0;

                for (int i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt32(num1 + offsets[i]));
                    ReadProcessMemory(mProc.Handle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToUInt32(memoryAddress, 0);
                }
                return base1;
            }
            else
            {
                int trueCode = Convert.ToInt32(newOffsets, 16);
                IntPtr altModule = IntPtr.Zero;
               if (theCode.ToLower().Contains("base") || theCode.ToLower().Contains("main"))
                    altModule = mProc.MainModule.BaseAddress;
                else if (!theCode.ToLower().Contains("base") && !theCode.ToLower().Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int32.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = GetModuleAddressByName(moduleName[0]);
                        }
                        catch
                        {
                       }
                    }
                }
                else
                    altModule = GetModuleAddressByName(theCode.Split('+')[0]);
                return (UIntPtr)((int)altModule + trueCode);
            }
        }

        public IntPtr GetModuleAddressByName (string name)
        {
            return mProc.Process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase)).BaseAddress;
        }

        public UIntPtr Get64BitCode(string name, string path = "", int size = 16)
        {
            string theCode = "";
            if (!String.IsNullOrEmpty(path))
                theCode = LoadCode(name, path);
            else
                theCode = name;

            if (String.IsNullOrEmpty(theCode))
                return UIntPtr.Zero;

            if (theCode.Contains(" "))
                theCode.Replace(" ", String.Empty);

            string newOffsets = theCode;
            if (theCode.Contains("+"))
                newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);

            byte[] memoryAddress = new byte[size];

            if (!theCode.Contains("+") && !theCode.Contains(","))
            {
                try {
                    return new UIntPtr(Convert.ToUInt64(theCode, 16));
                }
                catch
                {
                    return UIntPtr.Zero;
                }
            }

            if (newOffsets.Contains(','))
            {
                List<Int64> offsetsList = new List<Int64>();

                string[] newerOffsets = newOffsets.Split(',');
                foreach (string oldOffsets in newerOffsets)
                {
                    string test = oldOffsets;
                    if (oldOffsets.Contains("0x")) test = oldOffsets.Replace("0x", "");
                    Int64 preParse = 0;
                    if (!oldOffsets.Contains("-"))
                        preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                    else
                    {
                        test = test.Replace("-", "");
                        preParse = Int64.Parse(test, NumberStyles.AllowHexSpecifier);
                        preParse = preParse * -1;
                    }
                    offsetsList.Add(preParse);
                }
                Int64[] offsets = offsetsList.ToArray();

                if (theCode.Contains("base") || theCode.Contains("main"))
                    ReadProcessMemory(mProc.Handle, (UIntPtr)((Int64)mProc.MainModule.BaseAddress + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    IntPtr altModule = IntPtr.Zero;
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                        altModule = (IntPtr)Int64.Parse(moduleName[0], System.Globalization.NumberStyles.HexNumber);
                    else
                    {
                        try
                        {
                            altModule = GetModuleAddressByName(moduleName[0]);
                        }
                        catch
                        {
                        }
                    }
                    ReadProcessMemory(mProc.Handle, (UIntPtr)((Int64)altModule + offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
                else
                    ReadProcessMemory(mProc.Handle, (UIntPtr)(offsets[0]), memoryAddress, (UIntPtr)size, IntPtr.Zero);

                Int64 num1 = BitConverter.ToInt64(memoryAddress, 0);

                UIntPtr base1 = (UIntPtr)0;

                for (int i = 1; i < offsets.Length; i++)
                {
                    base1 = new UIntPtr(Convert.ToUInt64(num1 + offsets[i]));
                    ReadProcessMemory(mProc.Handle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                    num1 = BitConverter.ToInt64(memoryAddress, 0);
                }
                return base1;
            }
            else
            {
                Int64 trueCode = Convert.ToInt64(newOffsets, 16);
                IntPtr altModule = IntPtr.Zero;
                if (theCode.Contains("base") || theCode.Contains("main"))
                    altModule = mProc.MainModule.BaseAddress;
                else if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    string[] moduleName = theCode.Split('+');
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") && !moduleName[0].ToLower().Contains(".bin"))
                    {
                        string theAddr = moduleName[0];
                        if (theAddr.Contains("0x")) theAddr = theAddr.Replace("0x", "");
                        altModule = (IntPtr)Int64.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = GetModuleAddressByName(moduleName[0]);
                        }
                        catch
                        {
                         }
                    }
                }
                else
                    altModule = GetModuleAddressByName(theCode.Split('+')[0]);
                return (UIntPtr)((Int64)altModule + trueCode);
            }
        }

        public void CloseProcess()
        {
            if (mProc.Handle == null)
                return;

            CloseHandle(mProc.Handle);
            mProc = null;
        }

        public bool InjectDll(String strDllName)
        {
            IntPtr bytesout;

            if (mProc.Process == null)
            {
               return false;
            }

            foreach (ProcessModule pm in mProc.Process.Modules)
            {
                if (pm.ModuleName.StartsWith("inject", StringComparison.InvariantCultureIgnoreCase))
                    return false;
            }

            if (!mProc.Process.Responding)
                return false;

            int lenWrite = strDllName.Length + 1;
            UIntPtr allocMem = VirtualAllocEx(mProc.Handle, (UIntPtr)null, (uint)lenWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            WriteProcessMemory(mProc.Handle, allocMem, strDllName, (UIntPtr)lenWrite, out bytesout);
            UIntPtr GameProc = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (GameProc == null)
                return false;

            IntPtr hThread = CreateRemoteThread(mProc.Handle, (IntPtr)null, 0, GameProc, allocMem, 0, out bytesout);

            int Result = WaitForSingleObject(hThread, 10 * 1000);
            if (Result == 0x00000080L || Result == 0x00000102L)
            {
                if (hThread != null)
                    CloseHandle(hThread);
                return false;
            }
            VirtualFreeEx(mProc.Handle, allocMem, (UIntPtr)0, 0x8000);

            if (hThread != null)
                CloseHandle(hThread);

            return true;
        }

#if WINXP
#else

        public UIntPtr CreateCodeCave(string code, byte[] newBytes, int replaceCount, int size = 0x1000, string file = "")
        {
            if (replaceCount < 5)
                return UIntPtr.Zero;

            UIntPtr theCode;
            theCode = GetCode(code, file);
            UIntPtr address = theCode;

            UIntPtr caveAddress = UIntPtr.Zero;
            UIntPtr prefered = address;

            for(var i = 0; i < 10 && caveAddress == UIntPtr.Zero; i++)
            {
                caveAddress = VirtualAllocEx(mProc.Handle, FindFreeBlockForRegion(prefered, (uint)size), (uint)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (caveAddress == UIntPtr.Zero)
                    prefered = UIntPtr.Add(prefered, 0x10000);
            }

            if (caveAddress == UIntPtr.Zero)
                caveAddress = VirtualAllocEx(mProc.Handle, UIntPtr.Zero, (uint)size, MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);

            int nopsNeeded = replaceCount > 5 ? replaceCount - 5 : 0;

            int offset = (int)((long)caveAddress - (long)address - 5);

            byte[] jmpBytes = new byte[5 + nopsNeeded];
            jmpBytes[0] = 0xE9;
            BitConverter.GetBytes(offset).CopyTo(jmpBytes, 1);

            for(var i = 5; i < jmpBytes.Length; i++)
            {
                jmpBytes[i] = 0x90;
            }

            byte[] caveBytes = new byte[5 + newBytes.Length];
            offset = (int)(((long)address + jmpBytes.Length) - ((long)caveAddress + newBytes.Length) - 5);

            newBytes.CopyTo(caveBytes, 0);
            caveBytes[newBytes.Length] = 0xE9;
            BitConverter.GetBytes(offset).CopyTo(caveBytes, newBytes.Length + 1);

            WriteBytes(caveAddress, caveBytes);
            WriteBytes(address, jmpBytes);

            return caveAddress;
        }
        
        private UIntPtr FindFreeBlockForRegion(UIntPtr baseAddress, uint size)
        {
            UIntPtr minAddress = UIntPtr.Subtract(baseAddress, 0x70000000);
            UIntPtr maxAddress = UIntPtr.Add(baseAddress, 0x70000000);

            UIntPtr ret = UIntPtr.Zero;
            UIntPtr tmpAddress = UIntPtr.Zero;

            GetSystemInfo(out SYSTEM_INFO si);

            if (mProc.Is64Bit)
            {
                if ((long)minAddress > (long)si.maximumApplicationAddress ||
                    (long)minAddress < (long)si.minimumApplicationAddress)
                    minAddress = si.minimumApplicationAddress;

                if ((long)maxAddress < (long)si.minimumApplicationAddress ||
                    (long)maxAddress > (long)si.maximumApplicationAddress)
                    maxAddress = si.maximumApplicationAddress;
            }
            else
            {
                minAddress = si.minimumApplicationAddress;
                maxAddress = si.maximumApplicationAddress;
            }

            MEMORY_BASIC_INFORMATION mbi;

            UIntPtr current = minAddress;
            UIntPtr previous = current;

            while (VirtualQueryEx(mProc.Handle, current, out mbi).ToUInt64() != 0)
            {
               if ((long)mbi.BaseAddress > (long)maxAddress)
                    return UIntPtr.Zero;

                if (mbi.State == MEM_FREE && mbi.RegionSize > size)
                {
                    if ((long)mbi.BaseAddress % si.allocationGranularity > 0)
                    {
                        tmpAddress = mbi.BaseAddress;
                        int offset = (int)(si.allocationGranularity -
                                           ((long)tmpAddress % si.allocationGranularity));

                        if((mbi.RegionSize - offset) >= size)
                        {
                            tmpAddress = UIntPtr.Add(tmpAddress, offset);

                            if((long)tmpAddress < (long)baseAddress)
                            {
                                tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

                                if ((long)tmpAddress > (long)baseAddress)
                                    tmpAddress = baseAddress;

                                tmpAddress = UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                            }

                            if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                                ret = tmpAddress;
                        }
                    }
                    else
                    {
                        tmpAddress = mbi.BaseAddress;

                        if((long)tmpAddress < (long)baseAddress)
                        {
                            tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - size));

                            if ((long)tmpAddress > (long)baseAddress)
                                tmpAddress = baseAddress;

                            tmpAddress =
                                UIntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
                        }

                        if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
                            ret = tmpAddress;
                    }
                }

                if (mbi.RegionSize % si.allocationGranularity > 0)
                    mbi.RegionSize += si.allocationGranularity - (mbi.RegionSize % si.allocationGranularity);

                previous = current;
                current = new UIntPtr( ((ulong)mbi.BaseAddress) + (ulong)mbi.RegionSize);

                if ((long)current >= (long)maxAddress)
                    return ret;

                if ((long)previous >= (long)current)
                    return ret;
            }

            return ret;
        }
#endif

        public static void SuspendProcess(int pid)
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);

            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }

        public static void ResumeProcess(int pid)
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);
            if (process.ProcessName == string.Empty)
                return;

            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero)
                    continue;

                var suspendCount = 0;
                do
                {
                    suspendCount = ResumeThread(pOpenThread);
                } while (suspendCount > 0);
                CloseHandle(pOpenThread);
            }
        }

#if WINXP
#else
        async Task PutTaskDelay(int delay)
        {
            await Task.Delay(delay);
        }
#endif

        void AppendAllBytes(string path, byte[] bytes)
        {
            using (var stream = new FileStream(path, FileMode.Append))
            {
                stream.Write(bytes, 0, bytes.Length);
            }
        }

        public byte[] FileToBytes(string path, bool dontDelete = false) {
            byte[] newArray = File.ReadAllBytes(path);
            if (!dontDelete)
                File.Delete(path);
            return newArray;
        }

        public string MSize()
        {
            if (mProc.Is64Bit)
                return ("x16");
            else
                return ("x8");
        }

        public static string ByteArrayToHexString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            int i = 1;
            foreach (byte b in ba)
            {
                if (i == 16)
                {
                    hex.AppendFormat("{0:x2}{1}", b, Environment.NewLine);
                    i = 0;
                }
                else
                    hex.AppendFormat("{0:x2} ", b);
                i++;
            }
            return hex.ToString().ToUpper();
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2} ", b);
            }
            return hex.ToString();
        }

        public ulong GetMinAddress()
        {
            SYSTEM_INFO SI;
            GetSystemInfo(out SI);
            return (ulong)SI.minimumApplicationAddress;
        }

        public bool DumpMemory(string file = "dump.dmp")
        {
            Debug.Write("[DEBUG] memory dump starting... (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
            UIntPtr proc_max_address = sys_info.maximumApplicationAddress;

            Int64 proc_min_address_l = (Int64)proc_min_address;
            Int64 proc_max_address_l = (Int64)mProc.Process.VirtualMemorySize64 + proc_min_address_l;

            if (File.Exists(file))
                File.Delete(file);


            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            while (proc_min_address_l < proc_max_address_l)
            {
                VirtualQueryEx(mProc.Handle, proc_min_address, out memInfo);
                byte[] buffer = new byte[(Int64)memInfo.RegionSize];
                UIntPtr test = (UIntPtr)((Int64)memInfo.RegionSize);
                UIntPtr test2 = (UIntPtr)((Int64)memInfo.BaseAddress);

                ReadProcessMemory(mProc.Handle, test2, buffer, test, IntPtr.Zero);

                AppendAllBytes(file, buffer);

                proc_min_address_l += (Int64)memInfo.RegionSize;
                proc_min_address = new UIntPtr((ulong)proc_min_address_l);
            }

            return true;
        }

        public void GetThreads()
        {
            if (mProc.Process == null)
            {
                return;
            }

            foreach (ProcessThread thd in mProc.Process.Threads)
            {
             }
        }

        public static IntPtr GetThreadStartAddress(int threadId)
        {
            var hThread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)threadId);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception();
            var buf = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                var result = Imps.NtQueryInformationThread(hThread,
                                 ThreadInfoClass.ThreadQuerySetWin32StartAddress,
                                 buf, IntPtr.Size, IntPtr.Zero);
                if (result != 0)
                    throw new Win32Exception(string.Format("NtQueryInformationThread failed; NTSTATUS = {0:X8}", result));
                return Marshal.ReadIntPtr(buf);
            }
            finally
            {
                CloseHandle(hThread);
                Marshal.FreeHGlobal(buf);
            }
        }

        public bool SuspendThreadByID(int ThreadID)
        {
            foreach (ProcessThread thd in mProc.Process.Threads)
            {
                if (thd.Id != ThreadID)
                    continue;

                IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)ThreadID);

                if (threadHandle == IntPtr.Zero)
                    break;

                if (SuspendThread(threadHandle) == -1)
                {
                    CloseHandle(threadHandle);
                    break;
                }
                else
                {
                    CloseHandle(threadHandle);
                    return true;
                }
            }
            return false;
        }

    }
}
