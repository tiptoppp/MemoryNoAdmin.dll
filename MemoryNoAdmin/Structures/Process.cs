using System;
using System.Diagnostics;

namespace MemoryNoAdmin
{
    public class Proc
    {
        public Process Process { get; set; }
        public IntPtr Handle { get; set; }
        public bool Is64Bit { get; set; }
        public ProcessModule MainModule { get; set; }
    }
}
