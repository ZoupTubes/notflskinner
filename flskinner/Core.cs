using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace flskinner
{
    class Core
    {
        [DllImport("flskinner_core.dll", CallingConvention = CallingConvention.Cdecl)]
        public extern static void inject(string directory, string fl_studio_path);

        [DllImport("flskinner_core.dll", CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr get_version();

        public static string Version { 
            get {
                return System.Runtime.InteropServices.Marshal.PtrToStringAnsi(get_version());
            } 
        }
    }
}
