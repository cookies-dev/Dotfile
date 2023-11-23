$USERPROFILE =  $env:USERPROFILE
# Import-Module PSProfiler
# Measure-Script {
(@(& "$USERPROFILE/AppData/Local/Programs/oh-my-posh/bin/oh-my-posh.exe" init pwsh --config="$USERPROFILE\Documents\Dotfile\powershell\.maxim-theme.omp.json" --print) -join "`n") | Invoke-Expression
Import-Module posh-git
Import-Module -Name Terminal-Icons
# Import-Module ZLocation
# Import-Module WSLTabCompletion

# check code command exists

$insider = "$USERPROFILE\AppData\Local\Programs\Microsoft VS Code Insiders\bin"
if (!(Test-Path "$insider\code.cmd")) {
    Copy-Item "$insider\code-insiders.cmd" "$insider\code.cmd"
    Copy-Item "$insider\code-insiders" "$insider\code"
}
if (!(Test-Path "$insider\codi.cmd")) {
    Copy-Item "$insider\code-insiders.cmd" "$insider\codi.cmd"
    Copy-Item "$insider\code-insiders" "$insider\codi"
}
# local modules

# # for all files in the modules directory, import them
# $PSModulePath = "$env:USERPROFILE\Documents\MEGAsync\PowerModule"
# Get-ChildItem -Path $PSModulePath -Filter *.psm1 | ForEach-Object {
#     Import-Module $_.FullName
# }

# Set-PoshPrompt -Theme  $USERPROFILE\Documents\Dotfile\powershell\.maxim-theme.omp.json

# Chocolatey profile
$MProfile = "$USERPROFILE\Documents\Dotfile\powershell\Microsoft.PowerShell_profile.ps1"
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineKeyHandler -Chord "Ctrl+f" -Function ForwardWord

Set-Alias zip Compress-Archive
Set-Alias unzip Expand-Archive
Set-Alias touch ni
# Set-Alias ubuntu \\wsl.localhost\Ubuntu
Set-Alias g git

# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Documents\") {
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Documents\" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}

#
# Aliases
#
# If your favorite editor is not here, add an elseif and ensure that the directory it is installed in exists in your $env:Path
#
if (Test-CommandExists nvim) {
    $EDITOR = 'nvim'
}
elseif (Test-CommandExists pvim) {
    $EDITOR = 'pvim'
}
elseif (Test-CommandExists vim) {
    $EDITOR = 'vim'
}
elseif (Test-CommandExists vi) {
    $EDITOR = 'vi'
}
elseif (Test-CommandExists code) {
    #VS Code
    $EDITOR = 'code'
}
elseif (Test-CommandExists notepad) {
    #fallback to notepad since it exists on every windows machine
    $EDITOR = 'notepad'
}
Set-Alias -Name vim -Value $EDITOR


function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}


function uptime {
    #Windows Powershell
    # Get-WmiObject win32_operatingsystem | Select-Object csname, @{
    #     LABEL      = 'LastBootUpTime';
    #     EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) }
    # }

    #Powershell Core / Powershell 7+ (Uncomment the below section and comment out the above portion)

    $bootUpTime = Get-WmiObject win32_operatingsystem | Select-Object lastbootuptime
    $plusMinus = $bootUpTime.lastbootuptime.SubString(21, 1)
    $plusMinusMinutes = $bootUpTime.lastbootuptime.SubString(22, 3)
    $hourOffset = [int]$plusMinusMinutes / 60
    $minuteOffset = 00
    if ($hourOffset -contains '.') { $minuteOffset = [int](60 * [decimal]('.' + $hourOffset.ToString().Split('.')[1])) }
    if ([int]$hourOffset -lt 10 ) { $hourOffset = "0" + $hourOffset + $minuteOffset.ToString().PadLeft(2, '0') } else { $hourOffset = $hourOffset + $minuteOffset.ToString().PadLeft(2, '0') }
    $leftSplit = $bootUpTime.lastbootuptime.Split($plusMinus)[0]
    $upSince = [datetime]::ParseExact(($leftSplit + $plusMinus + $hourOffset), 'yyyyMMddHHmmss.ffffffzzz', $null)
    Get-WmiObject win32_operatingsystem | Select-Object @{LABEL = 'Machine Name'; EXPRESSION = { $_.csname } }, @{LABEL = 'Last Boot Up Time'; EXPRESSION = { $upsince } }
    #Works for Both (Just outputs the DateTime instead of that and the machine name)
    # net statistics workstation | Select-String "since" | foreach-object { $_.ToString().Replace('Statistics since ', '') }
}


function find-file($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}
function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}
function ds([string]$file) {
    # check if file exists
    if (!(Test-Path $file)) {
        # check if similar file exists in current directory not subdirectories
        $similarFiles = Get-ChildItem -Path $pwd -Filter "*$file*" -ErrorAction SilentlyContinue
        if ($similarFiles) {
            # print similar files Index,Mode,LastWriteTime,Length,Name
            $similarFiles | Format-Table -AutoSize -Property Index, Name
            # prompt user to select file
            $index = Read-Host "Select file by index > "
            # get file name
            $file = $similarFiles[$index].Name
            # check if file exists
            if (!(Test-Path $file)) {
                Write-Error "File $file does not exist"
                return
            }
        }
        else {
            Write-Error "File $file does not exist"
        }
    }

    if (!(Test-Path $file)) {
        Write-Error "File $file does not exist"
        return
    }
    if ($file -notmatch "\.disabled$") {
        Rename-Item $file "$file.disabled"
    }
    else {
        Rename-Item $file ($file -replace "\.disabled$", "")
    }
}
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }
function n { notepad $args }
function c { code $args }
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }
# function Ubuntu: { Set-Location \\wsl.localhost\Ubuntu }
# function Kali: { Set-Location \\wsl.localhost\kali-linux }
function ll { Get-ChildItem -Path $pwd -File }
function g { Set-Location $HOME\Documents\ }
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip ).Content }
function reloadProfile { & $profile }
function reloadEnv { refreshenv }
function reload { & $profile; refreshenv }
function touch($file) { "" | Out-File $file -Encoding ASCII }
function df { get-volume }
function sed($file, $find, $replace) { (Get-Content $file).replace("$find", $replace) | Set-Content $file }
function which($name) { Get-Command $name | Select-Object -ExpandProperty Definition }
function export($name, $value) { set-item -force -path "env:$name" -value $value; }
function pkill($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
function pgrep($name) { Get-Process $name }
function catx([string]$file) { bat --paging=never $file }
function webStart([string]$file) { git clone https://github.com/bdebon/quick-parcel-project.git $file }
function ScreenSize { Write-Output " x: $($Host.UI.RawUI.WindowSize.Width) y: $($Host.UI.RawUI.WindowSize.Height)" }
function start_ssh { Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service }
function notepad([string]$file) { Start-Process notepad++ $file }
function key {	ssh-add C:\Users\theyk\.ssh\id_rsa_git }
# function PortForward {
#     If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
#         $arguments = "& '" + $myinvocation.mycommand.definition + "'"
#         Start-Process powershell -Verb runAs -ArgumentList $arguments
#         Break
#     }

#     $remoteport = bash.exe -c "ifconfig eth0 | grep 'inet '"
#     $found = $remoteport -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';

#     if ( $found ) {
#         $remoteport = $matches[0];
#     }
#     else {
#         Write-Output "The Script Exited, the ip address of WSL 2 cannot be found";
#         exit;
#     }

#     $ports = @(3000, 3001, 5000, 5500, 8080, 19000, 19002, 19006);

#     Invoke-Expression "netsh interface portproxy reset";

#     for ( $i = 0; $i -lt $ports.length; $i++ ) {
#         $port = $ports[$i];
#         Invoke-Expression "netsh interface portproxy add v4tov4 listenport=$port connectport=$port connectaddress=$remoteport";
#     }

#     Invoke-Expression "netsh interface portproxy show v4tov4";
# }
function du {
    Get-ChildItem . |
    ForEach-Object { $f = $_; Get-ChildItem -r $_.FullName |
        measure-object -property length -sum |
        Select-Object  @{Name = "Name"; Expression = { $f } },
        @{Name         = "Sum (MB)";
            Expression = { "{0:N3}" -f ($_.sum / 1MB) }
        }, Sum } |
    Sort-Object Sum -desc |
    format-table -Property Name, "Sum (MB)", Sum -autosize
}
function Path {
    # get environment variable PATH and split it into an array of paths (split by ;) sorted name ascending
    $env:Path.Split(';') | Sort-Object -Descending | ForEach-Object { Write-Output $_ }
}

function CatHost {
    catx C:\Windows\System32\drivers\etc\hosts
}

function Reinstall {
    Remove-Item -Path .\node_modules\ -Recurse -Force
    Write-Host -Foreground Green "[V] Removed node_modules"
    npm cache clean --force
    Write-Host -Foreground Green "[V] Cleaned npm cache"
    npm install
    Write-Host -Foreground Green "[V] Reinstalled node_modules"
}

function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [ValidateRange(4, [int]::MaxValue)]
        [int] $length,
        [int] $upper = 1,
        [int] $lower = 1,
        [int] $numeric = 1,
        [int] $special = 1
    )
    if ($upper + $lower + $numeric + $special -gt $length) {
        throw "number of upper/lower/numeric/special char must be lower or equal to length"
    }
    $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lCharSet = "abcdefghijklmnopqrstuvwxyz"
    $nCharSet = "0123456789"
    $sCharSet = "/*-+,!?=()@;:._"
    $charSet = ""
    if ($upper -gt 0) { $charSet += $uCharSet }
    if ($lower -gt 0) { $charSet += $lCharSet }
    if ($numeric -gt 0) { $charSet += $nCharSet }
    if ($special -gt 0) { $charSet += $sCharSet }

    $charSet = $charSet.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
    $rng.GetBytes($bytes)
 
    $result = New-Object char[]($length)
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
    }
    $password = (-join $result)
    $valid = $true
    if ($upper -gt ($password.ToCharArray() | Where-Object { $_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
    if ($lower -gt ($password.ToCharArray() | Where-Object { $_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
    if ($numeric -gt ($password.ToCharArray() | Where-Object { $_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
    if ($special -gt ($password.ToCharArray() | Where-Object { $_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }
 
    if (!$valid) {
        $password = Get-RandomPassword $length $upper $lower $numeric $special
    }
    return $password
}

function Timer {
    param(
        [Parameter(Mandatory = $true)]
        [int]$seconds
    )

    # set a timer and write a message in loop (every second, update the message)
    $timer = New-Object System.Timers.Timer -ArgumentList ($seconds * 1000)
    $backTimer = $seconds
    $timer.Start()
    while ($timer.Enabled) {
        Write-Progress -Activity "Timer is running..." -Status "$seconds seconds left" -PercentComplete (100 - ($seconds / $backTimer * 100))
        Start-Sleep -Seconds 1
        $seconds--
        if ($seconds -eq 0) {
            $timer.Stop()
        }
    }
    Write-Host -Foreground Green "Timer is done!"
}

# RG SYSTEM
function vr {
    param(
        [Parameter(Mandatory = $true)]
        [str]$param
    )
    Set-Location $USERPROFILE\Documents\rg\devbox
    &vagrant.exe $param
} 

function super {
    if (-Not (Get-Module -ListAvailable -Name NtObjectManager)) {
        $ProgressPreference = "SilentlyContinue"
        Install-Module -Name NtObjectManager -Repository PSGallery -Force
    }
    Import-Module NtObjectManager
    Start-Service -Name TrustedInstaller
    $parent = Get-NtProcess -ServiceName TrustedInstaller
    $proc = New-Win32Process cmd.exe -CreationFlags NewConsole -ParentProcess $parent
}

# check_size
# }
# Write-Host -Foreground Green "`n[ZLocation] knows about $((Get-ZLocation).Keys.Count) locations.`n"
$USERPROFILE =  $env:USERPROFILE
# Import-Module PSProfiler
# Measure-Script {
(@(& "$USERPROFILE/AppData/Local/Programs/oh-my-posh/bin/oh-my-posh.exe" init pwsh --config="$USERPROFILE\Documents\Dotfile\powershell\.maxim-theme.omp.json" --print) -join "`n") | Invoke-Expression
Import-Module posh-git
Import-Module -Name Terminal-Icons
# Import-Module ZLocation
# Import-Module WSLTabCompletion

# check code command exists

$insider = "$USERPROFILE\AppData\Local\Programs\Microsoft VS Code Insiders\bin"
if (!(Test-Path "$insider\code.cmd")) {
    Copy-Item "$insider\code-insiders.cmd" "$insider\code.cmd"
    Copy-Item "$insider\code-insiders" "$insider\code"
}
if (!(Test-Path "$insider\codi.cmd")) {
    Copy-Item "$insider\code-insiders.cmd" "$insider\codi.cmd"
    Copy-Item "$insider\code-insiders" "$insider\codi"
}
# local modules

# # for all files in the modules directory, import them
# $PSModulePath = "$env:USERPROFILE\Documents\MEGAsync\PowerModule"
# Get-ChildItem -Path $PSModulePath -Filter *.psm1 | ForEach-Object {
#     Import-Module $_.FullName
# }

# Set-PoshPrompt -Theme  $USERPROFILE\Documents\Dotfile\powershell\.maxim-theme.omp.json

# Chocolatey profile
$MProfile = "$USERPROFILE\Documents\Dotfile\powershell\Microsoft.PowerShell_profile.ps1"
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineKeyHandler -Chord "Ctrl+f" -Function ForwardWord

Set-Alias zip Compress-Archive
Set-Alias unzip Expand-Archive
Set-Alias touch ni
# Set-Alias ubuntu \\wsl.localhost\Ubuntu
Set-Alias g git

# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Documents\") {
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Documents\" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}

#
# Aliases
#
# If your favorite editor is not here, add an elseif and ensure that the directory it is installed in exists in your $env:Path
#
if (Test-CommandExists nvim) {
    $EDITOR = 'nvim'
}
elseif (Test-CommandExists pvim) {
    $EDITOR = 'pvim'
}
elseif (Test-CommandExists vim) {
    $EDITOR = 'vim'
}
elseif (Test-CommandExists vi) {
    $EDITOR = 'vi'
}
elseif (Test-CommandExists code) {
    #VS Code
    $EDITOR = 'code'
}
elseif (Test-CommandExists notepad) {
    #fallback to notepad since it exists on every windows machine
    $EDITOR = 'notepad'
}
Set-Alias -Name vim -Value $EDITOR


function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}


function uptime {
    #Windows Powershell
    # Get-WmiObject win32_operatingsystem | Select-Object csname, @{
    #     LABEL      = 'LastBootUpTime';
    #     EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) }
    # }

    #Powershell Core / Powershell 7+ (Uncomment the below section and comment out the above portion)

    $bootUpTime = Get-WmiObject win32_operatingsystem | Select-Object lastbootuptime
    $plusMinus = $bootUpTime.lastbootuptime.SubString(21, 1)
    $plusMinusMinutes = $bootUpTime.lastbootuptime.SubString(22, 3)
    $hourOffset = [int]$plusMinusMinutes / 60
    $minuteOffset = 00
    if ($hourOffset -contains '.') { $minuteOffset = [int](60 * [decimal]('.' + $hourOffset.ToString().Split('.')[1])) }
    if ([int]$hourOffset -lt 10 ) { $hourOffset = "0" + $hourOffset + $minuteOffset.ToString().PadLeft(2, '0') } else { $hourOffset = $hourOffset + $minuteOffset.ToString().PadLeft(2, '0') }
    $leftSplit = $bootUpTime.lastbootuptime.Split($plusMinus)[0]
    $upSince = [datetime]::ParseExact(($leftSplit + $plusMinus + $hourOffset), 'yyyyMMddHHmmss.ffffffzzz', $null)
    Get-WmiObject win32_operatingsystem | Select-Object @{LABEL = 'Machine Name'; EXPRESSION = { $_.csname } }, @{LABEL = 'Last Boot Up Time'; EXPRESSION = { $upsince } }
    #Works for Both (Just outputs the DateTime instead of that and the machine name)
    # net statistics workstation | Select-String "since" | foreach-object { $_.ToString().Replace('Statistics since ', '') }
}


function find-file($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}
function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}
function ds([string]$file) {
    # check if file exists
    if (!(Test-Path $file)) {
        # check if similar file exists in current directory not subdirectories
        $similarFiles = Get-ChildItem -Path $pwd -Filter "*$file*" -ErrorAction SilentlyContinue
        if ($similarFiles) {
            # print similar files Index,Mode,LastWriteTime,Length,Name
            $similarFiles | Format-Table -AutoSize -Property Index, Name
            # prompt user to select file
            $index = Read-Host "Select file by index > "
            # get file name
            $file = $similarFiles[$index].Name
            # check if file exists
            if (!(Test-Path $file)) {
                Write-Error "File $file does not exist"
                return
            }
        }
        else {
            Write-Error "File $file does not exist"
        }
    }

    if (!(Test-Path $file)) {
        Write-Error "File $file does not exist"
        return
    }
    if ($file -notmatch "\.disabled$") {
        Rename-Item $file "$file.disabled"
    }
    else {
        Rename-Item $file ($file -replace "\.disabled$", "")
    }
}
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }
function md5 { Get-FileHash -Algorithm MD5 $args }
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }
function n { notepad $args }
function c { code $args }
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }
# function Ubuntu: { Set-Location \\wsl.localhost\Ubuntu }
# function Kali: { Set-Location \\wsl.localhost\kali-linux }
function ll { Get-ChildItem -Path $pwd -File }
function g { Set-Location $HOME\Documents\ }
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip ).Content }
function reloadProfile { & $profile }
function reloadEnv { refreshenv }
function reload { & $profile; refreshenv }
function touch($file) { "" | Out-File $file -Encoding ASCII }
function df { get-volume }
function sed($file, $find, $replace) { (Get-Content $file).replace("$find", $replace) | Set-Content $file }
function which($name) { Get-Command $name | Select-Object -ExpandProperty Definition }
function export($name, $value) { set-item -force -path "env:$name" -value $value; }
function pkill($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
function pgrep($name) { Get-Process $name }
function catx([string]$file) { bat --paging=never $file }
function webStart([string]$file) { git clone https://github.com/bdebon/quick-parcel-project.git $file }
function ScreenSize { Write-Output " x: $($Host.UI.RawUI.WindowSize.Width) y: $($Host.UI.RawUI.WindowSize.Height)" }
function start_ssh { Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service }
function notepad([string]$file) { Start-Process notepad++ $file }
function key {	ssh-add C:\Users\theyk\.ssh\id_rsa_git }
# function PortForward {
#     If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
#         $arguments = "& '" + $myinvocation.mycommand.definition + "'"
#         Start-Process powershell -Verb runAs -ArgumentList $arguments
#         Break
#     }

#     $remoteport = bash.exe -c "ifconfig eth0 | grep 'inet '"
#     $found = $remoteport -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';

#     if ( $found ) {
#         $remoteport = $matches[0];
#     }
#     else {
#         Write-Output "The Script Exited, the ip address of WSL 2 cannot be found";
#         exit;
#     }

#     $ports = @(3000, 3001, 5000, 5500, 8080, 19000, 19002, 19006);

#     Invoke-Expression "netsh interface portproxy reset";

#     for ( $i = 0; $i -lt $ports.length; $i++ ) {
#         $port = $ports[$i];
#         Invoke-Expression "netsh interface portproxy add v4tov4 listenport=$port connectport=$port connectaddress=$remoteport";
#     }

#     Invoke-Expression "netsh interface portproxy show v4tov4";
# }
function du {
    Get-ChildItem . |
    ForEach-Object { $f = $_; Get-ChildItem -r $_.FullName |
        measure-object -property length -sum |
        Select-Object  @{Name = "Name"; Expression = { $f } },
        @{Name         = "Sum (MB)";
            Expression = { "{0:N3}" -f ($_.sum / 1MB) }
        }, Sum } |
    Sort-Object Sum -desc |
    format-table -Property Name, "Sum (MB)", Sum -autosize
}
function Path {
    # get environment variable PATH and split it into an array of paths (split by ;) sorted name ascending
    $env:Path.Split(';') | Sort-Object -Descending | ForEach-Object { Write-Output $_ }
}

function CatHost {
    catx C:\Windows\System32\drivers\etc\hosts
}

function Reinstall {
    Remove-Item -Path .\node_modules\ -Recurse -Force
    Write-Host -Foreground Green "[V] Removed node_modules"
    npm cache clean --force
    Write-Host -Foreground Green "[V] Cleaned npm cache"
    npm install
    Write-Host -Foreground Green "[V] Reinstalled node_modules"
}

function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [ValidateRange(4, [int]::MaxValue)]
        [int] $length,
        [int] $upper = 1,
        [int] $lower = 1,
        [int] $numeric = 1,
        [int] $special = 1
    )
    if ($upper + $lower + $numeric + $special -gt $length) {
        throw "number of upper/lower/numeric/special char must be lower or equal to length"
    }
    $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lCharSet = "abcdefghijklmnopqrstuvwxyz"
    $nCharSet = "0123456789"
    $sCharSet = "/*-+,!?=()@;:._"
    $charSet = ""
    if ($upper -gt 0) { $charSet += $uCharSet }
    if ($lower -gt 0) { $charSet += $lCharSet }
    if ($numeric -gt 0) { $charSet += $nCharSet }
    if ($special -gt 0) { $charSet += $sCharSet }

    $charSet = $charSet.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
    $rng.GetBytes($bytes)
 
    $result = New-Object char[]($length)
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
    }
    $password = (-join $result)
    $valid = $true
    if ($upper -gt ($password.ToCharArray() | Where-Object { $_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
    if ($lower -gt ($password.ToCharArray() | Where-Object { $_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
    if ($numeric -gt ($password.ToCharArray() | Where-Object { $_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
    if ($special -gt ($password.ToCharArray() | Where-Object { $_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }
 
    if (!$valid) {
        $password = Get-RandomPassword $length $upper $lower $numeric $special
    }
    return $password
}

function Timer {
    param(
        [Parameter(Mandatory = $true)]
        [int]$seconds
    )

    # set a timer and write a message in loop (every second, update the message)
    $timer = New-Object System.Timers.Timer -ArgumentList ($seconds * 1000)
    $backTimer = $seconds
    $timer.Start()
    while ($timer.Enabled) {
        Write-Progress -Activity "Timer is running..." -Status "$seconds seconds left" -PercentComplete (100 - ($seconds / $backTimer * 100))
        Start-Sleep -Seconds 1
        $seconds--
        if ($seconds -eq 0) {
            $timer.Stop()
        }
    }
    Write-Host -Foreground Green "Timer is done!"
}

# RG SYSTEM
function vr {
    param(
        [Parameter(Mandatory = $true)]
        [str]$param
    )
    Set-Location $USERPROFILE\Documents\rg\devbox
    &vagrant.exe $param
} 

function super {
    if (-Not (Get-Module -ListAvailable -Name NtObjectManager)) {
        $ProgressPreference = "SilentlyContinue"
        Install-Module -Name NtObjectManager -Repository PSGallery -Force
    }
    Import-Module NtObjectManager
    Start-Service -Name TrustedInstaller
    $parent = Get-NtProcess -ServiceName TrustedInstaller
    $proc = New-Win32Process cmd.exe -CreationFlags NewConsole -ParentProcess $parent
}

# check_size
# }
# Write-Host -Foreground Green "`n[ZLocation] knows about $((Get-ZLocation).Keys.Count) locations.`n"
