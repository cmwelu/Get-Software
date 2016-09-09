<#
.SYNOPSIS
A Powershell script to acquire a list of installed software on a system.

.DESCRIPTION
The script will list software installed on a system. Data collection methods include from the Uninstall Registry key and Win32_Product WMI Class. Data can be collected remotely via PS Remoting (Requires WinRM), Remote Registry, or Remote WMI Queries.

.PARAMETER ComputerName
An array of fully qualified computer names to collect data from. If none is specified, the local machine will be collected from.

.PARAMETER PSRemoting
A switch to use PSRemoting as the remote data collection method. This will require WinRM to be enabled on the remote system.

.PARAMETER RemoteReg
A switch to use Remote Registry as the remote data collection method.

.PARAMETER Wmi
A switch to use Remote WMI Queries as the remote data collection method.

.PARAMETER WmiSoft
A switch to query the Win32_Product class. Please see the notes for further information.

.EXAMPLE
./Get-Software.ps1
Gets Software from the Local Machine 

.EXAMPLE
./Get-Software.ps1 -PSRemoting -ComputerName Win7vm
Gets Software using PS Remoting from Win7vm

.EXAMPLE
Get-Content computerList.txt | ./Get-Software.ps1 -RemoteReg -Wmi -WmiSoft
Gets Software from computers in computerList.txt using Remote Registry and Remote WMI Queries

.NOTES
The Win32_Product class is not query optimized. Whenever it is queried, a consistency check of all installed packages happens. This essentially runs the installation repair process on every piece of software. 
This is not ideal, and this check will not happen by default in this script. To enable this data source, use the -WmiSoft switch.

.LINK
https://github.com/cmwelu/Get-Software

#>
[CmdletBinding()]
Param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $ComputerName,
    [switch]$PSRemoting = $false,
    [switch]$RemoteReg = $false,
    [switch]$Wmi = $false,
    [switch]$WmiSoft = $false
)
process
{
    function Get-Software-Wmi($ComputerName)
    {
        $software = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product | Select-Object Name, Version, @{Name='Publisher'; Expression={$_.Vendor}}, InstallDate, InstallSource, InstallLocation, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $software
    }

    function Get-Software-Reg($ComputerName)
    {
        Write-Verbose "Opening Registry on: $ComputerName"
        # Credit: https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/13/use-powershell-to-quickly-find-installed-software/
        $Reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey(‘LocalMachine’,$ComputerName) 
        $Regkey=$Reg.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") 
        $Subkeys=$Regkey.GetSubKeyNames() 
        $Software = @()
        foreach($Key in $Subkeys){
        Write-Verbose "Opening Subkey: $Key"
            $ThisKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\”+$Key 
            $ThisSubKey=$Reg.OpenSubKey($ThisKey) 

            #Only add entries that have a name
            if($ThisSubKey.GetValue("DisplayName") -ne $null)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name “Name” -Value $($ThisSubKey.GetValue(“DisplayName”))
                $Obj | Add-Member -MemberType NoteProperty -Name “Version” -Value $($ThisSubKey.GetValue(“DisplayVersion”))
                $Obj | Add-Member -MemberType NoteProperty -Name “InstallLocation” -Value $($ThisSubKey.GetValue(“InstallLocation”))
                $Obj | Add-Member -MemberType NoteProperty -Name “InstallSource” -Value $($ThisSubKey.GetValue("InstallSource"))
                $Obj | Add-Member -MemberType NoteProperty -Name “Publisher” -Value $($ThisSubKey.GetValue(“Publisher”))
                $Obj | Add-Member -MemberType NoteProperty -Name “PSComputerName” -Value $ComputerName
                $Software += $Obj
            }
        }
        return $software
    }

    function Get-Software($WmiSoft)
    {
        #Get the data from Registry, select and rename fields
        $Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object @{Name='Name'; Expression={$_.DisplayName}}, @{Name='Version'; Expression={$_.DisplayVersion}}, Publisher, InstallDate, InstallSource, InstallLocation, @{Name='PSComputerName'; Expression={$env:computername}}

        #Only get from WMI if the user would like. This can be quite slow, and actually initiates the install/repair operation on ALL software.
        if($WmiSoft)
        {
            #Get the data from WMI, select and rename fields
            $Software +=   Get-WmiObject -Class Win32_Product | Select-Object Name, Version, @{Name='Publisher'; Expression={$_.Vendor}}, InstallDate, InstallSource, InstallLocation, @{Name='PSComputerName'; Expression={$env:computername}}
        }
        $Software = $Software | Select-Object Name, Version, Publisher, InstallDate, InstallSource
        #Select unique entries based on Name
        $Software = $Software | Sort-Object Name -Unique
        return $Software
    }

    #---------------------MAIN--------------------------

    #If no remote computers specified, run on the local computer. Use Get-Software function locally.
    if(!$ComputerName)
    {
        $MasterSoftware+= Get-Software $WmiSoft
    }
    elseif($PSRemoting -OR $Wmi -OR $RemoteReg)
    {
        ForEach ($Computer in $ComputerName)
        {
            Write-Verbose "Getting info from $Computer"
            $Software = $null
            #Collect all data using PSRemoting
            if($PSRemoting)
            {
                    Write-Verbose "Using PSRemoting"
                    $Software += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-Software} -ArgumentList $WmiSoft

                    #FUTURE: Other Data Collection Methods Here
            }
            #Collect everything we can with Remote Registry
            if($RemoteReg)
            {
                Write-Verbose "Using Remote Reg"
                $Software += Get-Software-Reg $Computer

                #FUTURE: Other Data Collection Methods Here
            }
            #Collect everything we can with Remote WMI Queries
            if($Wmi)
            {
                if($WmiSoft)
                {
                    Write-Verbose "Using WMI"
                    $Software += Get-Software-Wmi $Computer
                }

                #FUTURE: Other Data Collection Methods Here
            }
            #Dedup Software on Current Computer based on Name
            $MasterSoftware+= $software | Sort-Object Name -Unique
        }
    }
    else
    {
        Write-Error "ERROR: You must specify either -PSRemoting, -RemoteReg, or -Wmi when collecting from remote computers."
    }
}
end
{
    #Output the Software List, only those that are not null.
    $MasterSoftware | Where-Object { $_.Name -NE $Null }
}