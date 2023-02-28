#windows 
# Enumeration
## Nmap
```
nmap -sC -sV jeeves.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 06:53 EST
Nmap scan report for jeeves.htb (10.129.228.112)
Host is up (0.21s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-28T16:53:57
|_  start_date: 2023-02-28T16:48:22
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 4h59m58s, deviation: 0s, median: 4h59m57s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.25 seconds
```

## Directory check
### Gobuster
#### at 80
```
gobuster dir -k -u http://jeeves.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
```
Nothing

#### at 50000
```
 gobuster dir -k -u http://jeeves.htb:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200

/askjeeves            (Status: 302) [Size: 0] [--> http://jeeves.htb:50000/askjeeves/]
Progress: 220560 / 220561 (100.00%)
```

## SMB port 445
```
smbmap -H jeeves.htb        
[!] Authentication error on jeeves.htb
```

## HTTP
### at 80
### at 50000
#### http://jeeves.htb:50000/askjeeves/

![[Pasted image 20230228210224.png]]

