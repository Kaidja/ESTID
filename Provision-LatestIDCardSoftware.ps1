Function Write-Log
{

    PARAM(
         [String]$Message,
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-WmiObject -Query "Select Bias from Win32_TimeZone"
         $Date= Get-Date -Format "HH:mm:ss.fff"
         $Date2= Get-Date -Format "MM-dd-yyyy"
         $type=1
         
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| 
            Out-File -FilePath $Script:LogDirectory -Append -NoClobber -Encoding default -Force
}

Function Get-ErrorInformation
{
    [cmdletbinding()] 
    Param(
        [String]$Component
    )

    Write-Log -Message "Exception: $($Error[0].Exception.Message)" -Severity 3 -Component $Component
    Write-Log -Message "ErrorID: $($Error[0].FullyQualifiedErrorId)" -Severity 3 -Component $Component
    Write-Log -Message "ScriptLineNumber: $($Error[0].InvocationInfo.ScriptLineNumber)" -Severity 3 -Component $Component
    Write-Log -Message "Message: $($Error[0].InvocationInfo.PositionMessage)" -Severity 3 -Component $Component
}

Function Import-KJConfigMgrModule
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
            [String]$SiteCode,
            $SiteServer
    )
    
    Try {
        Write-Log -Message "Importing Configuration Manager PowerShell Module" -Severity 1 -Component 'Function: Import-KJConfigMgrModule'

        Import-Module $env:SMS_ADMIN_UI_PATH.Replace("\bin\i386","\bin\configurationmanager.psd1") -ErrorAction STOP
        $CMSite = Get-PSProvider -PSProvider CMSITE -ErrorAction SilentlyContinue
    
        If($CMSite.Drives){
            Set-Location -Path "$($CMSite.Drives.Name):\" | Out-Null
            Write-Log -Message "*** Configuration Manager PowerShell Provider exists" -Severity 1 -Component 'Function: Import-KJConfigMgrModule'
        }
        Else{
            New-PSDrive -Name $SiteCode -PSProvider 'CMSite' -Description 'SCCM Site' -Root $SiteServer -ErrorAction STOP -Scope Global
            Set-Location -Path "$($SiteCode):\" | Out-Null
        }
    }
    Catch {
        Get-ErrorInformation -Component 'Function: Import-KJConfigMgrModule'
        Throw "Module import failed"
    }

}

Function Get-KJLastIDCardVersion
{
    Param(
        $URL
    )

    Try{
        Write-Log -Message "Reading ID-Card version from $URL" -Severity 1 -Component 'Function: Get-KJLastIDCardVersion'

        $HTML = Invoke-WebRequest $URL -ErrorAction STOP
        $AllElements = $HTML.AllElements
        $Results = $AllElements | Where-Object { $PSItem.TagName -eq "TD" }

        $IDSoftwareVersions = @()
        $Results | ForEach-Object {

            If($_.innerText -like 'Open-EID-*.exe'){

                $IDSoftwareVersions += $_.innerText
            }

        }
        Write-Log -Message "Total versions of ID-Card $($IDSoftwareVersions.Count)" -Severity 1 -Component 'Function: Get-KJLastIDCardVersion'
        
        $IDSoftwareVersions
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Get-KJLastIDCardVersion'
    }
}

Function Get-KJConfigMgrApplication
{
    Param(
        $Name
    )

  
     Write-Log -Message "Reading Application: $Name" -Severity 1 -Component 'Function: Get-KJConfigMgrApplication'
     Get-CMApplication -Name $Name

}

Function Save-KJLastIDCardVersion
{
    Param(
        $URL,
        $Folder,
        $Version
    )

    Try{
        Write-Log -Message "Downloading latest ID-Card EXE from $URL. $Version version" -Severity 1 -Component 'Function: Save-KJLastIDCardVersion'
        Invoke-WebRequest -Uri "$URL/$Version" -OutFile "$Folder\$Version" -ErrorAction STOP
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Save-KJLastIDCardVersion'
    }
}

Function Save-KJIDCardMSIFiles
{
    Param(
        $Folder,
        $Version
    )
    
    Try{
        Write-Log -Message "Downloading ID-Card MSI files to $Folder folder." -Severity 1 -Component 'Function: Save-KJIDCardMSIFiles'
        Start-Process -FilePath "$Folder\$Version" -ArgumentList "/Layout /Silent" -Wait -PassThru -ErrorAction STOP
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Save-KJIDCardMSIFiles'
    }
}

Function Move-KJIDCardInstallationFiles
{
    Param(
        $DownloadFolder,
        $SourceRootFolder,
        $Version
    )
    
    Try{
        Write-Log -Message "Create new version folder $Version." -Severity 1 -Component 'Function: Move-KJIDCardInstallationFiles'
        New-Item -Path "$SourceRootFolder\$Version" -ItemType Directory -ErrorAction STOP -Force
        
        Write-Log -Message "Move all MSI files to $DownloadFolder folder" -Severity 1 -Component 'Function: Move-KJIDCardInstallationFiles'
        Get-ChildItem -Path $DownloadFolder -Filter "*.msi" -ErrorAction STOP | ForEach-Object {

            Move-Item -Path $PSItem.FullName -Destination "$SourceRootFolder\$Version" -Force
            Write-Log -Message "Copying $($PSItem.FullName) to $SourceRootFolder\$Version" -severity 1 -component 'Function: Move-KJIDCardInstallationFiles'
        }

        Write-Log -Message "Move all EXE files to $DownloadFolder folder" -Severity 1 -Component 'Function: Move-KJIDCardInstallationFiles'
        Get-ChildItem -Path $DownloadFolder -Filter "*.exe" -ErrorAction STOP | ForEach-Object {

            Move-Item -Path $PSItem.FullName -Destination "$SourceRootFolder\$Version" -Force
            Write-Log -Message "Copying $($PSItem.FullName) to $SourceRoot\$NewVersion" -severity 1 -component 'Function: Move-KJIDCardInstallationFiles'
        }
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Move-KJIDCardInstallationFiles'
    }
}

Function New-KJConfigMgrApplication
{
    Param(
        $Name,
        $IconLocationFile
    )

    Try{
        Write-Log -Message "Creating new ConfigMgr Application $Name. Icon file location: $IconLocationFile" -Severity 1 -Component 'Function: New-KJConfigMgrApplication'
        New-CMApplication -Name $Name -IconLocationFile $IconLocationFile -ErrorAction STOP
    }
    Catch{
        Get-ErrorInformation -Component 'Function: New-KJConfigMgrApplication'
    }
}

Function Move-KJConfigMgrObject
{
    Param(
        [parameter(Mandatory=$true)]
        [ValidateSet("Application", "DeviceCollection")]
        [String]$ObjectType,
        [String]$Name,
        [String]$FolderPath
    )

    Try{
        Switch($ObjectType){
            'Application' {$ObjectInput = Get-KJConfigMgrApplication -Name $Name}
            'DeviceCollection' {$ObjectInput = Get-CMCollection -Name $Name -CollectionType Device}
        }

        Write-Log -Message "Moving $Name to $FolderPath" -Severity 1 -Component 'Function: Move-KJConfigMgrObject'
        Move-CMObject -InputObject $ObjectInput -FolderPath $FolderPath -ErrorAction STOP
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Move-KJConfigMgrObject'
    }
}

Function Get-KJConfigMgrDetectionMethod
{
   Param(
    $DetectionFile,
    $Version
   ) 
    
    Try{
        Write-Log -Message "Reading ConfigMgr App Detection script from $DetectionFile" -Severity 1 -Component 'Function: Get-KJConfigMgrDetectionMethod'
        $DetectionMethod = Get-Content $DetectionFile -Raw -ErrorAction STOP
        $DetectionMethod.Replace('IDCARDVERSIONHERE',$Version)
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Get-KJConfigMgrDetectionMethod'
    }
}


Function Start-KJConfigMgrContentDistribution
{

    Param(
        $Name,
        $DistributionPointGroupName
    )

    Try{
        Write-Log -Message "Distributing new ConfigMgr Application to $DistributionPointGroupName Group" -Severity 1 -Component 'Function: Start-KJConfigMgrContentDistribution'
        Start-CMContentDistribution -ApplicationName $Name -DistributionPointGroupName $DistributionPointGroupName -ErrorAction STOP

    }
    Catch{
        Get-ErrorInformation -Component 'Function: Start-KJConfigMgrContentDistribution'
    }

}

Function New-KJConfigMgrCollection
{
    Param(
        [parameter(Mandatory=$true)]
        [ValidateSet("Device", "User")]
        $Type,
        $Name,
        $LimitingCollectionName
    )

    Try{
        Switch($Type){
    
            'Device' {$CollectionType = 'Device'}
            'User' {$CollectionType = 'User'}
        }

        Write-Log -Message "Creating new Device Collection $Name. Limiting this new Collection against $LimitingCollectionName" -Severity 1 -Component 'Function: New-KJConfigMgrCollection'
        New-CMCollection -CollectionType $CollectionType -Name $Name -LimitingCollectionName $LimitingCollectionName -ErrorAction STOP
    }
    Catch{
        Get-ErrorInformation -Component 'Function: New-KJConfigMgrCollection'
    }
}

Function Send-KJMailNotification
{
    Param(
        $SmtpServer,
        $To,
        $From,
        $Subject,
        $Body
    )

    Try{
        Write-Log -Message "Sending new version notification to $To" -Severity 1 -Component 'Function: Send-KJMailNotification'
        Send-MailMessage `
            -SmtpServer $SmtpServer `
            -To $To `
            -From $From `
            -Subject $Subject `
            -Body $Body `
            -ErrorAction STOP
    }
    Catch{
        Get-ErrorInformation -Component 'Function: Send-KJMailNotification'
    }
}

Function Add-KJConfigMgrApplicationScriptDT
{
    Param(
     $DeploymentTypeName,
     $InstallCommand,
     $ContentLocation,
     $ApplicationName,
     $ScriptLanguage = 'PowerShell',
     [parameter(Mandatory=$true)]
     [ValidateSet("Hidden", "Maximized", "Normal" , "Minimized")]
        $UserInteractionMode,
     $ScriptText
    )

    Try{
        Write-Log -Message "Creating new ConfigMgr Application Deplyment Type" -Severity 1 -Component 'Function: Add-KJConfigMgrApplicationScriptDT'
        Add-CMScriptDeploymentType `
            -DeploymentTypeName $DeploymentTypeName `
            -InstallCommand $CommandLine `
            -ContentLocation $PackageSource `
            -ApplicationName $ApplicationName `
            -ScriptLanguage $ScriptLanguage `
            -UserInteractionMode $UserInteractionMode `
            -ScriptText $DetectionMethod `
            -ErrorAction STOP

    }
    Catch{
        Get-ErrorInformation -Component 'Function: Add-KJConfigMgrApplicationScriptDT'
    }
}

Function New-ConfigMgrAppDeployment
{
    Param(
        $ApplicationName,
     [parameter(Mandatory=$true)]
     [ValidateSet("Available", "Required")]
        $DeployPurpose,
        $CollectionName,
        $AvailableDate,
        $DeadlineDateTime
    )

    Try{
        Write-Log -Message "Creating new ConfigMgr Application Deplyment." -Severity 1 -Component 'Function: New-ConfigMgrAppDeployment'
        New-CMApplicationDeployment `
            -Name $ApplicationName `
            -AvailableDate $AvailableDate `
            -DeployPurpose $DeployPurpose `
            -CollectionName $CollectionName `
            -DeployAction Install `
            -DeadlineDateTime $DeadlineDateTime `
            -ErrorAction STOP

    }
    Catch{
        Get-ErrorInformation -Component 'Function: New-ConfigMgrAppDeployment'
    }
}
########### SCRIPT ENTRY POINT ##########################

$URL = 'https://installer.id.ee/media/win'
$DownloadLocation = 'E:\Scripts\Download'
$SourceRoot = 'E:\Sources\Software\ID-Kaart'
$IconFile = "$SourceRoot\ID.jpg"
$Script:LogDirectory = "E:\Scripts\Logs\IDSoftware.log"
$DetectionFile = 'E:\Scripts\ID-CardDetectionMethod.txt'
$SiteServer = 'CM01.contoso.com'

Write-Log -Message "************************ Starting to check new version of ID-Card Utility  - $(Get-Date)*** ********************" -Severity 1 -Component 'START'

#Get the latest EST ID Card utility version
$IDCardVersions = Get-KJLastIDCardVersion -URL $URL
$LastIDCardVersion = $IDCardVersions | Select-Object -Last 1
$IDCardVersionString = $LastIDCardVersion.TrimStart("Open-EID-").trimend("_x86.exe")
$LastIDCardExeVersion = [System.Version]"$($LastIDCardVersion.TrimStart("Open-EID-").TrimEnd("_x86.exe"))"

#ConfigMgr variables
$ApplicationName = "Eesti ID-Kaardi Utiliit - $IDCardVersionString"
$PackageSource = "\\cm01\sources$\Software\ID-Kaart\$IDCardVersionString"
$CommandLine = "$LastIDCardVersion /quiet /norestart AutoUpdate=0 IconsDesktop=0 RunQesteidutil=0"
$InstallCollectionName = "SWD - Eesti ID-Kaardi Utiliit - $IDCardVersionString"
$SiteCode = 'PS1'
$SoftwareAPPRootFolder = "$($SiteCode):\Application\ID-Kaart"
$SoftwareCollRootFolder = "$($SiteCode):\DeviceCollection\Software"
$DistributionPointGroupName = 'All Content'
$LimitingCollectionName = 'All TPT Workstations'
$DeploymentTypeName = "Install - $ApplicationName"
$DeploymentAvailableDate = Get-Date
$DeploymentDeadlineDateTime = (Get-Date).AddMinutes(5)

#Notification configuraton. By default notification is turned off. This requires SMTP address.
$SendNotification = $True
$SmtpServer = '193.40.160.1'
$Subject = 'Uus ID-Kaardi tarkvara on saadaval'
$To = 'Toivo.parnpuu@tptlive.ee'
$From = 'ITHaldus@tptlive.ee'
$Body = "Uus versioon on saadaval - $IDCardVersionString"

#Import ConfigMgr PowerShell Module
Import-KJConfigMgrModule -SiteCode $SiteCode -SiteServer $SiteServer

If(Get-KJConfigMgrApplication -Name $ApplicationName){
    Write-Log -Message "No new version available. Quit script now" -Severity 1 -Component 'MAIN FLOW'
}
Else{

    If($SendNotification){
        Send-KJMailNotification -SmtpServer -To $To -From $From -Subject $Subject -Body $Body
    }

    Save-KJLastIDCardVersion -URL $URL -Folder $DownloadLocation -Version $LastIDCardVersion
    Save-KJIDCardMSIFiles -Folder $DownloadLocation -Version $LastIDCardVersion
    Move-KJIDCardInstallationFiles -DownloadFolder $DownloadLocation -SourceRootFolder $SourceRoot -Version $IDCardVersionString
    New-KJConfigMgrApplication -Name $ApplicationName -IconLocationFile $IconFile
    Move-KJConfigMgrObject -ObjectType Application -Name $ApplicationName -FolderPath $SoftwareAPPRootFolder
    
    $DetectionMethod = Get-KJConfigMgrDetectionMethod -DetectionFile $DetectionFile -Version $IDCardVersionString
    
    Add-KJConfigMgrApplicationScriptDT `
        -DeploymentTypeName $DeploymentTypeName `
        -InstallCommand $CommandLine `
        -ContentLocation $PackageSource `
        -ApplicationName $ApplicationName `
        -ScriptLanguage PowerShell `
        -UserInteractionMode Hidden `
        -ScriptText $DetectionMethod

    Start-KJConfigMgrContentDistribution -Name $ApplicationName -DistributionPointGroupName $DistributionPointGroupName  
    
    New-KJConfigMgrCollection -Name $InstallCollectionName -Type Device -LimitingCollectionName $LimitingCollectionName
    Move-KJConfigMgrObject -ObjectType DeviceCollection -Name $InstallCollectionName -FolderPath $SoftwareCollRootFolder

    New-ConfigMgrAppDeployment `
        -ApplicationName $ApplicationName `
        -DeployPurpose Required `
        -CollectionName $InstallCollectionName `
        -AvailableDate $DeploymentAvailableDate `
        -DeadlineDateTime $DeploymentDeadlineDateTime
    
}
Write-Log -Message "************************ Finished all actions  - $(Get-Date)*** ********************" -Severity 1 -Component 'END'

