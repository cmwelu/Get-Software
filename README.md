#Get-Software

##Overview
This PowerShell script will utilize a few different methods to acquire a list of installed software on a system. This can help give System Administrators an awareness of all software across a network that needs to be patched, as well as giving an attacker awareness of the surroundings. The list of software is derived from the Uninstall registry key (HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall) and the Win32_Product WMI Class. 

This script can utilize a number of methods to acquire the data from remote systems. PSRemoting can be utilized, and requires WinRM to be running on the remote system. Additionally, Remote Registry or Remote WMI Queries can be used. The user can select which method(s) are appropriate for the network to be scanned.

This PowerShell script has been tested on Windows 10 with PowerShell 5, collecting from various PowerShell versions and operating systems to include:
* Windows 7
* Windows 8
* Windows 10
* Windows Server 2008R2
* Windows Server 2012
* Windows Server 2012R2

Note: This script was created during Dakota State University's CSC-842 Rapid Tool Development course.

##Usage
```PowerShell
 .\Get-Software.ps1 [[-ComputerName] <String[]>] [-PSRemoting] [-RemoteReg] [-Wmi] [-WmiSoft] [<CommonParameters>]
```

For detailed help and examples, run 
````PowerShell
Get-Help .\Get-Software.ps1
````
##Known Issues
The Win32_Product class is not query optimized. Whenever it is queried, a consistency check of all installed packages happens. This essentially runs the installation repair process on every piece of software. 
This is not ideal, and this check will not happen by default in this script. To enable this data source, use the -WmiSoft switch.

##Future Work
* Potentially filter the output of the data, having an option to view which hosts a particular piece of software is installed on, though this can be accomplished through existing PowerShell Cmdlets through the pipeline.
* Expand the script to gather additional data, beyond just software. This has the potential to be a broad defensive data collection platform.
* Utilize threading to collect from multiple computers concurrently

##Resources
* [Video Demo](https://youtu.be/qttB9gJL5MU)
* [TechNet Blog](https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/13/use-powershell-to-quickly-find-installed-software/) referenced in this project
