# Enumeration

## Nmap scan
```
nmap -sC -sV -Pn jerry.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-13 01:15 EST
Nmap scan report for jerry.htb (10.129.210.31)
Host is up (0.18s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.41 seconds
```

## Feroxbuster


## http - TCP port 8080

access to `http://jerry.htb:8080`

apache tomcat 7.0.88 shows up
![[Pasted image 20230213152928.png]]


