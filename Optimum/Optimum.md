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

