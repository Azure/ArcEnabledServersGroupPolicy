[string] $remotePath = "\\dc-01.contoso.lcl\Software\Arc"
[string] $localPath = "$env:HOMEDRIVE\ArcDeployment"

[string] $RegKey = "HKLM\SOFTWARE\Microsoft\Azure Connected Machine Agent"

[string] $logFile = "installationlog.txt"
[string] $InstaltionFolder = "ArcDeployment"
[string] $configFilename = "ArcConfig.json"


if (!(Test-Path $localPath) ) {
    $BitsDirectory = new-item -path C:\ -Name $InstaltionFolder -ItemType Directory 
    $logpath = new-item -path $BitsDirectory -Name $logFile -ItemType File
}
else{
$BitsDirectory = "C:\ArcDeployment"
}


function Deploy-Agent {
    [bool] $isDeployed = Test-Path $RegKey
    if ($isDeployed) {
        $logMessage = "Azure Arc Serverenabled agent is deployed , exit process"
        $logMessage >> $logpath
        exit
    }
    else { 
        Copy-Item -Path "$remotePath\*" -Destination $BitsDirectory -Recurse -Verbose


        $exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", "$BitsDirectory\AzureConnectedMachineAgent.msi" , "/l*v", "$BitsDirectory\$logFile", "/qn") -Wait -Passthru).ExitCode
        
        if($exitCode -eq 0){
       Start-Sleep -Seconds 120
       $x=   & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --config "$BitsDirectory\$configFilename"
            $x >> $logpath 
       
        }
        else {
            $message = (net helpmsg $exitCode)
            $message >> $logpath 
        }

    }
}

    Deploy-Agent

  
