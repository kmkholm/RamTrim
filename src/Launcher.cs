// RamTrim.exe - hosts the embedded RamTrim PowerShell script in-process, so the tool ships as one file.
// Built with the C# compiler that comes with Windows (see build.cmd). No PowerShell window is shown.
using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("RamTrim")]
[assembly: AssemblyDescription("Memory trimmer and security monitor for Windows")]
[assembly: AssemblyCompany("Dr. Mohammed Tawfik")]
[assembly: AssemblyProduct("RamTrim")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Mohammed Tawfik")]
[assembly: AssemblyVersion("3.0.0.0")]
[assembly: AssemblyFileVersion("3.0.0.0")]

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        string snap = null;
        for (int i = 0; i + 1 < args.Length; i++)
            if (string.Equals(args[i], "-Snap", StringComparison.OrdinalIgnoreCase)) snap = args[i + 1];
        try
        {
            string script;
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("RamTrim.ps1"))
            using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                script = r.ReadToEnd();

            InitialSessionState iss = InitialSessionState.CreateDefault();
            iss.ApartmentState = ApartmentState.STA;
            iss.ThreadOptions = PSThreadOptions.UseCurrentThread;
            // process-scope only: lets the built-in Windows modules (NetTCPIP, Defender, ScheduledTasks) load
            iss.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
            iss.Variables.Add(new SessionStateVariableEntry("RamTrimExe", Assembly.GetExecutingAssembly().Location, "Path of the running RamTrim.exe"));

            using (Runspace rs = RunspaceFactory.CreateRunspace(iss))
            {
                rs.Open();
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;
                    ps.AddScript(script);
                    if (snap != null) ps.AddParameter("Snap", snap);
                    ps.Invoke();
                    if (snap != null && ps.Streams.Error.Count > 0)
                    {
                        StringBuilder sb = new StringBuilder();
                        foreach (ErrorRecord e in ps.Streams.Error) sb.AppendLine(e.ToString() + "  @ " + e.InvocationInfo.PositionMessage);
                        File.WriteAllText(Path.Combine(snap, "snap_errors.txt"), sb.ToString(), Encoding.UTF8);
                    }
                }
            }
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.ToString(), "RamTrim", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
