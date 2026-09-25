import type { PrivateClipboard } from "./index";

// Fixed program: no input is interpolated into PowerShell, C#, arguments or env.
// Windows clipboard sequence comparison and clearing happen under OpenClipboard.
const program = String.raw`
$ErrorActionPreference = 'Stop'
try {
Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
public static class AbsPrivateClipboard {
  [DllImport("user32.dll")] static extern bool OpenClipboard(IntPtr h);
  [DllImport("user32.dll")] static extern bool CloseClipboard();
  [DllImport("user32.dll")] static extern bool EmptyClipboard();
  [DllImport("user32.dll")] static extern IntPtr SetClipboardData(uint f, IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern uint RegisterClipboardFormat(string s);
  [DllImport("user32.dll")] static extern uint GetClipboardSequenceNumber();
  [DllImport("kernel32.dll")] static extern IntPtr GlobalAlloc(uint f, UIntPtr size);
  [DllImport("kernel32.dll")] static extern IntPtr GlobalLock(IntPtr h);
  [DllImport("kernel32.dll")] static extern bool GlobalUnlock(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr h);
  static void Put(uint format, byte[] bytes) {
    IntPtr h = GlobalAlloc(0x42, (UIntPtr)bytes.Length);
    if(h == IntPtr.Zero) throw new Exception();
    try {
      IntPtr p=GlobalLock(h); if(p == IntPtr.Zero) throw new Exception();
      try { Marshal.Copy(bytes,0,p,bytes.Length); } finally { GlobalUnlock(h); }
      if(SetClipboardData(format,h) == IntPtr.Zero) throw new Exception();
      h=IntPtr.Zero;
    } finally { if(h != IntPtr.Zero) GlobalFree(h); Array.Clear(bytes,0,bytes.Length); }
  }
  static void Open(IntPtr h) {
    for(int i=0;i<30;i++) { if(OpenClipboard(h)) return; Thread.Sleep(20); }
    throw new Exception();
  }
  public static void Run() {
    string code=Console.ReadLine(); int ttl=int.Parse(Console.ReadLine());
    if(code==null || code.Length!=6 || ttl<1000 || ttl>30000) throw new Exception();
    foreach(char c in code) if(c<'0'||c>'9') throw new Exception();
    using(Form owner=new Form()) {
      IntPtr window=owner.Handle;
      Open(window);
      try {
        if(!EmptyClipboard()) throw new Exception();
        Put(RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing"),new byte[]{0});
        Put(RegisterClipboardFormat("CanIncludeInClipboardHistory"),new byte[4]);
        Put(RegisterClipboardFormat("CanUploadToCloudClipboard"),new byte[4]);
        Put(13,Encoding.Unicode.GetBytes(code+"\0"));
      } catch { EmptyClipboard(); throw; }
      finally { CloseClipboard(); }
      code=null;
      uint sequence=GetClipboardSequenceNumber();
      Console.WriteLine("copied"); Console.Out.Flush();
      Thread.Sleep(ttl);
      Open(window);
      try { if(GetClipboardSequenceNumber()==sequence) EmptyClipboard(); }
      finally { CloseClipboard(); }
    }
  }
}
'@
[AbsPrivateClipboard]::Run()
} catch { [Console]::Out.WriteLine('failed'); exit 1 }
`;

/** Windows / WSL only. No code in argv, environment, files or process output.
 * The short-lived helper owns expiry independently of the MCP process. Native
 * history/roaming opt-out does not control third-party clipboard monitors.
 */
export function createWindowsPrivateClipboard(
  options: { executable?: string } = {},
): PrivateClipboard {
  return {
    async copy(bytes, ttlMs) {
      if (
        bytes.length !== 6 ||
        bytes.some((b) => b < 48 || b > 57) ||
        !Number.isSafeInteger(ttlMs) ||
        ttlMs < 1000 ||
        ttlMs > 30000
      )
        throw Error("Invalid private clipboard input");
      const child = Bun.spawn(
        [
          options.executable ?? "powershell.exe",
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-STA",
          "-Command",
          program,
        ],
        {
          stdin: "pipe",
          stdout: "pipe",
          stderr: "ignore",
        },
      );
      child.stdin.write(bytes);
      child.stdin.write("\n" + ttlMs + "\n");
      child.stdin.end();
      const reader = child.stdout.getReader();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const first = await Promise.race([
          reader.read(),
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(Error("Private clipboard unavailable")),
              15000,
            );
          }),
        ]);
        if (
          first.done ||
          new TextDecoder().decode(first.value).trim() !== "copied"
        )
          throw Error("Private clipboard unavailable");
        // Drain only fixed helper status; it must never become tool output.
        void (async () => {
          try {
            while (!(await reader.read()).done) {}
          } catch {
          } finally {
            reader.releaseLock();
          }
        })();
        void child.exited.catch(() => {});
      } catch {
        // Do not kill the helper: if a write raced with timeout it must still clear.
        void reader.cancel().catch(() => {});
        throw Error("Private clipboard write unconfirmed");
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
