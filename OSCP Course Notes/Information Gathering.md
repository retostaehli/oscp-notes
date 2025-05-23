---
title: Information Gathering
---
# Passive Information Gathering
## Whois enumeration
``` zsh 
whois offensive-security.com -h 192.168.173.251 
```
- `-h` is used to indicate the whois server to use for the query
## Google Dorks
- https://www.exploit-db.com/google-hacking-database
- https://dorksearch.com 
- `site:offsec.com` -> Search for a specific domain
- `filetype:pdf` -> Search for a specific filetype
- `ext:php` -> Search for a specific extension (indexed)
- `intitle:"index of"` -> Search specific page title
- `-filetype:html` -> Exclude HTML files from search
## Github
- Search for open source projects by companies
- Similiar to Google Dorks, github has keywords to narrow down searches
- Tools like [Gitrob](https://github.com/michenriksen/gitrob) or [Gitleaks](https://github.com/zricethezav/gitleaks) can help in automated search
- [Trufflehog](https://github.com/trufflesecurity/trufflehog)can be used to find secrets in Github (and other sources)
## Shodan
- Tool to crawl devices connected to the Internet
- `hostname:offsec.com` -> Specify a hostname
- `port:22` -> Specify a port
## Security Headers and TLS
- Many services like [Securityheaders](https://securityheaders.com) or [SSL Labs](https://www.ssllabs.com)
# Active Information Gathering
## DNS
 - Use `host` command to enumerate domain (or `dig` or `dnsrecon` or `nslookup` or `dnsenum`)
 - Specify the record type with `-t`
```zsh 
host -t txt offsec.com

nslookup -type=TXT info.megacorpone.com 8.8.8.8
``` 
- Subdomain enumeration with `bash` or `gobuster` or `dnsrecon`
```zsh
gobuster dns -d offsec.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

for subdomain in $(cat wordlist.txt);do host $subdomain.offsec.com; done

for ip in $(seq 200 254); do host 51.222.169.$ip; done

dnsrecon -d megacorpone.com -D //usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t brt
```
- Use `dnsrecon` using the `-t` to specify the scantype
```zsh
dnsrecon -d megacorpone.com -t std
```
- `dnsenum` can also be used to automate things from above
```zsh 
dnsenum megacorpone.com
```

## Port Scanning
- We can use `nc` or `nmap` or `Test-NetConnection` to scan for open ports
```zsh
nc -nvv -w 1 -z 192.168.50.152 3388-3390

nc -nv -u -z -w 1 192.168.50.149 120-123

sudo nmap -p- --min-rate 10000 10.10.11.21

sudo nmap -sU -sS -p- --min-rate 10000 10.10.11.21

sudo nmap -p 80,3389,5985,49668 -sCV 10.10.11.21

sudo nmap -sn 192.168.50.1-253

sudo nmap -p 80 192.168.50.1-253

sudo nmap -sT --top-ports=20 192.168.50.1-253

Test-NetConnection -Port 445 192.168.50.151

1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null 

1..254 | % {$ip="192.168.50.$_"; Write-Output "$ip $(Test-Connection -Computername "$ip" -Quiet -Count 1)"}

for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```
- Running `nmap` with `sudo` ensures that it defaults to a SYN scan which is much faster. To perform a CONNECT scan we can add the `-sT`option or run it as a non-privileged user
- With the option `-sn` we can perform a network sweep
- Adding the `-oA` ensures that the results is being outputted to all formats
- OS fingerprinting can be done using the `-O` option. `nmap` will only show the OS Version if it is pretty sure. We can use `--osscan-guess` to still output its best guess
- The `--top-ports=X` ensures that only the `X` most common ports get scanned
- Add `-sC` for default scripts
- Add `--scripts all` to run all scripts (Probably not a good idea due to speed)
- Add `"http* and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)"` on web ports
- Add `-sV` to detect services and enumerate versions
- Add `-A` to include service detection, scripts and OS guessing
- There is a list of [NSE Scripts](https://nmap.org/nsedoc/scripts/) we can use with `--script NSE-Name` . To get more information about a script we can use the `--script-help NSE-Name` option

## SMB

### Linux
- We can use `nbtscan` to search for open NetBIOS 
```zsh
sudo nbtscan -r 192.168.50.0/24
```
- The option `-r` to use UDP port 137
- Available NSE Scripts can be listed using `ls` and then used as usual. We can use all vulnerability scripts with `--script=smb-vuln\*`
```zsh 
ls -1 /usr/share/nmap/scripts/smb* 

nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152

nmap -script=smb-vuln\* -p445 192.168.103.40
``` 
- We can try to enumerate users with `nxc` and option `--rid-brute`
```zsh
nxc smb certified.htb -u 'Guest' -p '' --rid-brute
```
#### smbclient
- If we have credentials for a share we can enumerate it using `smbclient`or mount it
```zsh
smbclient //192.168.231.248/Users -U domain/emma_wong --password="Butterfly04\!"

sudo mount -t cifs -o "username=emma_wong,password=Butterfly04\!" //192.168.231.248/transfer ./transfer
```
- To download all files from a share we can use `mget`
```zsh
mask ""
recurse on
prompt off #This will disable confirmation for each file
mget *
```
#### nxc
- If we have credentials for a share we can also use `nxc` to enumerate shares and download files 
```zsh
#Use netexec with the spider_plus module and option to download
nxc smb 192.168.140.159 -u 'Guest' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```
### Windows
- We can use `net view` to list shares on a host. By providing the `/all` flag, shares ending with the dollar sign also get shown
```zsh 
net view \\dc01 /all 
```

## SMTP 
- To check if a user exist, issue the `VRFY` command on an open SMTP session
- Checking the memberships of a mailing list can be done with `EXPN`
- If we have valid credentials, we can send an email using `swaks`
```zsh
swaks --from test@supermagicorg.com --to dave.wizard@supermagicorg.com,someone.else@supermagicorg.com --server 192.168.45.50 --port 587 --auth login --auth-user 'test@supermagicorg.com' --auth-password 'test' --header 'Subject: IT Action needed' --body "Hi Dave. Please open the attachement" --attach @/home/redo/Documents/oscp/exercises/ClientSideAttacks/WebDAV/config.Library-ms
```
  
### Linux
- We can use `nc` to get the SMTP headers
```zsh
nc -nv 192.168.50.8 25
```
- We can use `telnet` to interact with SMTP
```zsh
telnet 192.168.183.199 25
HELO server.domain
VRFY root
VRFY idontexist
EXPN test-list
```
- We can use `smtp-user-enum` to try and bruteforce potential usernames
```zsh
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t postfish.off
```

### Windows
- We can again use `Test-NetConnection` to check for open SMTP port. Interacting with SMTP can be done with `telnet`
```zsh
Test-NetConnection -Port 25 192.168.50.8

telnet 192.168.50.8 25
```

## POP3 IMAP
- We can use `telnet` to interact with POP3 or IMAP
```zsh
telnet 192.168.121.150 110
Connected to 192.168.121.150.
Escape character is '^]'.
+OK POP3
USER alexa@mail.com
+OK Send your password
PASS init12345
+OK Mailbox locked and ready
list
+OK 2 messages:
1 683
2 1462
RETR 1


telnet 192.168.121.150 143 
Connected to 192.168.121.150.
Escape character is '^]'.
* OK IMAPrev1
A1 LOGIN alexa@mail.com init12345
A1 OK LOGIN completed
A1 LIST "" *
* LIST (\HasNoChildren) "." "INBOX"
A1 OK LIST completed
A1 LIST INBOX *
* LIST (\HasNoChildren) "." "INBOX"
A1 OK LIST completed
```
## SNMP
- Scan for open SNMP port with `nmap`. The option `--open` will only list open ports
```zsh
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```
- We can use `onesixtyone` to scan SNMP targets
- With `-c` we can provide a communitystring or a file containing communitystrings
```zsh
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips

onesixtyone -c community -i ips
```
- One we know a valid communitystring we can use `snmpwalk` 
```zsh
snmpwalk -c public -v1 -t 10 192.168.50.151 -Oa
```
- The option `-Oa` will automatically translate any hexadecimal string into ASCII
- Using specific OIDs we can query for specific information. There are a couple of OID DBs online to search for specific OIDs
#### User enumeration with SNMP
```zsh
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
```
#### Running processes with SNMP
```zsh
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
```
#### Installed Software with SNMP
```zsh
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
```
#### Listening TCP Ports with SNMP
```zsh
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```
#### Extended MIBs 
- Also always try to scan for extended queries
```
snmpwalk -v 1 -c public 192.168.50.151 NET-SNMP-EXTEND-MIB::nsExtendOutputFull

snmpwalk -v 1 -c public 192.168.50.151 NET-SNMP-EXTEND-MIB::nsExtendObjects
```
## Git
- If we find a git repository, we can use `git log` to see commit messages
- To show files altered by git we can use `git log -p`
- Use `git show <commithash>`
- To switch back to a specific branch we can use `git checkout <commithash>`
- To show the git diff of a commit we can use `git diff-tree -p <commithash>`
- To dump a .git folder from a URL we can use [https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)
## Identd
- If port 113 `identd` is open, we can use [ident-user-enum](https://github.com/pentestmonkey/ident-user-enum.git) to enumerate users
```zsh$
ident-user-enum 192.168.1.100 <portnumber>
ident-user-enum 192.168.1.100 22 113 139 445
```