using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static MemoryNoAdmin.Imps;

namespace MemoryNoAdmin
{
    public partial class Mem
    {
        ConcurrentDictionary<string, CancellationTokenSource> FreezeTokenSrcs = new ConcurrentDictionary<string, CancellationTokenSource>();

        public bool FreezeValue(string address, string type, string value, string file = "")
        {
            CancellationTokenSource cts = new CancellationTokenSource();

            if (FreezeTokenSrcs.ContainsKey(address))
            {
                try
                {
                    FreezeTokenSrcs[address].Cancel();
                    FreezeTokenSrcs.TryRemove(address, out _);
                }
                catch
                {
                    return false;
                }
            }
            else {
               }

            FreezeTokenSrcs.TryAdd(address, cts);

            Task.Factory.StartNew(() =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    WriteMemory(address, type, value, file);
                    Thread.Sleep(25);
                }
            },
            cts.Token);

            return true;
        }

        public void UnfreezeValue(string address)
        {
            try
            {
                lock (FreezeTokenSrcs)
                {
                    FreezeTokenSrcs[address].Cancel();
                    FreezeTokenSrcs.TryRemove(address, out _);
                }
            }
            catch
            {
             }
        }

        public bool WriteMemory(string code, string type, string write, string file = "", System.Text.Encoding stringEncoding = null, bool RemoveWriteProtection = true)
        {
            byte[] memory = new byte[4];
            int size = 4;

            UIntPtr theCode;
            theCode = GetCode(code, file);

            if (theCode == null || theCode == UIntPtr.Zero || theCode.ToUInt64() < 0x10000)
                return false;

            if (type.ToLower() == "float")
            {
                write = Convert.ToString(float.Parse(write, CultureInfo.InvariantCulture));
                memory = BitConverter.GetBytes(Convert.ToSingle(write));
                size = 4;
            }
            else if (type.ToLower() == "int")
            {
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size = 4;
            }
            else if (type.ToLower() == "byte")
            {
                memory = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size = 1;
            }
            else if (type.ToLower() == "2bytes")
            {
                memory = new byte[2];
                memory[0] = (byte)(Convert.ToInt32(write) % 256);
                memory[1] = (byte)(Convert.ToInt32(write) / 256);
                size = 2;
            }
            else if (type.ToLower() == "bytes")
            {
                if (write.Contains(",") || write.Contains(" "))
                {
                    string[] stringBytes;
                    if (write.Contains(","))
                        stringBytes = write.Split(',');
                    else
                        stringBytes = write.Split(' ');
               
                    int c = stringBytes.Count();
                    memory = new byte[c];
                    for (int i = 0; i < c; i++)
                    {
                        memory[i] = Convert.ToByte(stringBytes[i], 16);
                    }
                    size = stringBytes.Count();
                }
                else
                {
                    memory = new byte[1];
                    memory[0] = Convert.ToByte(write, 16);
                    size = 1;
                }
            }
            else if (type.ToLower() == "double")
            {
                memory = BitConverter.GetBytes(Convert.ToDouble(write));
                size = 8;
            }
            else if (type.ToLower() == "long")
            {
                memory = BitConverter.GetBytes(Convert.ToInt64(write));
                size = 8;
            }
            else if (type.ToLower() == "string")
            {
                if (stringEncoding == null)
                    memory = System.Text.Encoding.UTF8.GetBytes(write);
                else
                    memory = stringEncoding.GetBytes(write);
                size = memory.Length;
            }

            MemoryProtection OldMemProt = 0x00;
            bool WriteProcMem = false;
            if (RemoveWriteProtection)
                ChangeProtection(code, MemoryProtection.ExecuteReadWrite, out OldMemProt, file);
            WriteProcMem = WriteProcessMemory(mProc.Handle, theCode, memory, (UIntPtr)size, IntPtr.Zero);
            if (RemoveWriteProtection)
                ChangeProtection(code, OldMemProt, out _, file);
            return WriteProcMem;
        }

        public bool WriteMove(string code, string type, string write, int MoveQty, string file = "", int SlowDown = 0)
        {
            byte[] memory = new byte[4];
            int size = 4;

            UIntPtr theCode;
            theCode = GetCode(code, file);

            if (type == "float")
            {
                memory = new byte[write.Length];
                memory = BitConverter.GetBytes(Convert.ToSingle(write));
                size = write.Length;
            }
            else if (type == "int")
            {
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size = 4;
            }
            else if (type == "double")
            {
                memory = BitConverter.GetBytes(Convert.ToDouble(write));
                size = 8;
            }
            else if (type == "long")
            {
                memory = BitConverter.GetBytes(Convert.ToInt64(write));
                size = 8;
            }
            else if (type == "byte")
            {
                memory = new byte[1];
                memory[0] = Convert.ToByte(write, 16);
                size = 1;
            }
            else if (type == "string")
            {
                memory = new byte[write.Length];
                memory = System.Text.Encoding.UTF8.GetBytes(write);
                size = write.Length;
            }

            UIntPtr newCode = UIntPtr.Add(theCode, MoveQty);

            Thread.Sleep(SlowDown);
            return WriteProcessMemory(mProc.Handle, newCode, memory, (UIntPtr)size, IntPtr.Zero);
        }

        public void WriteBytes(string code, byte[] write, string file = "")
        {
            UIntPtr theCode;
            theCode = GetCode(code, file);
            WriteProcessMemory(mProc.Handle, theCode, write, (UIntPtr)write.Length, IntPtr.Zero);
        }

        public void WriteBits(string code, bool[] bits, string file = "")
        {
            if (bits.Length != 8)
                throw new ArgumentException("Not enough bits for a whole byte", nameof(bits));

            byte[] buf = new byte[1];

            UIntPtr theCode = GetCode(code, file);

            for (var i = 0; i < 8; i++)
            {
                if (bits[i])
                    buf[0] |= (byte)(1 << i);
            }

            WriteProcessMemory(mProc.Handle, theCode, buf, (UIntPtr)1, IntPtr.Zero);
        }

        public void WriteBytes(UIntPtr address, byte[] write)
        {
            WriteProcessMemory(mProc.Handle, address, write, (UIntPtr)write.Length, out IntPtr bytesRead);
        }
    }
}
