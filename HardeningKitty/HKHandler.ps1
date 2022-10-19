# Copyright Saketh Reddy of BASIS Scottsdale Team 1
# Please contact the author for permission to use this code, especially for Cypat (intentionally not spelled out to prevent Search Engine Indexing) competitions.

$scriptpath = $MyInvocation.MyCommand.Path
$dir = Split-Path $scriptpath
Push-Location $dir

Set-ExecutionPolicy Unrestricted

Import-Module .\Invoke-HardeningKitty.ps1

$ListName = "finding_list_cis_microsoft_windows_server_2019_1809_1.2.1"
# $ListName = "finding_list_cis_microsoft_windows_10_enterprise_21h2_1.0.0"

# Audit and Backup Configuration
mkdir logs
mkdir backups
Invoke-HardeningKitty -Mode Audit -Log -LogFile .\logs\machineRawBefore.txt -FileFindingList .\lists\${ListName}_machine.csv -Backup -BackupFile .\backups\machine.csv
Invoke-HardeningKitty -Mode Audit -Log -LogFile .\logs\userRawBefore.txt -FileFindingList .\lists\${ListName}_user.csv -Backup -BackupFile .\backups\user.csv

# Write "### Begin Machine List" Before.txt
echo "### Begin Machine List" >> .\logs\Before.txt
# Filter machineRawBefore.txt, removing lines "Severity=Passed"
Select-String -Path .\logs\machineRawBefore.txt -Pattern "Severity=Passed" -NotMatch | Out-File -Append -FilePath .\logs\Before.txt

# Append "### Begin User List" Before.txt
echo "### Begin User List" >> .\logs\Before.txt
# Filter userRawBefore.txt, removing lines "Severity=Passed"
Select-String -Path .\logs\userRawBefore.txt -Pattern "Severity=Passed" -NotMatch | Out-File -Append -FilePath .\logs\Before.txt


# HailMary like there's no tomorrow!
Invoke-HardeningKitty -Mode HailMary -FileFindingList .\lists\${ListName}_machine.csv -Backup -BackupFile .\backups\machine.csv
Invoke-HardeningKitty -Mode HailMary -FileFindingList .\lists\${ListName}_user.csv -Backup -BackupFile .\backups\user.csv

# Post-HailMary Audit Only
Invoke-HardeningKitty -Mode Audit -Log -LogFile .\logs\machineRawAfter.txt -FileFindingList .\lists\${ListName}_machine.csv
Invoke-HardeningKitty -Mode Audit -Log -LogFile .\logs\userRawAfter.txt -FileFindingList .\lists\${ListName}_user.csv

# Write "### Begin Machine List" After.txt
echo "### Begin Machine List" >> .\logs\After.txt
# Filter machineRawAfter.txt, removing lines "Severity=Passed"
Select-String -Path .\logs\machineRawAfter.txt -Pattern "Severity=Passed" -NotMatch | Out-File -Append -FilePath .\logs\After.txt

# Append "### Begin User List" After.txt
echo "### Begin User List" >> .\logs\After.txt
# Filter userRawAfter.txt, removing lines "Severity=Passed"
Select-String -Path .\logs\userRawAfter.txt -Pattern "Severity=Passed" -NotMatch | Out-File -Append -FilePath .\logs\After.txt

# Write "### Begin Diff" Diff.txt
echo "### Begin Diff" >> .\logs\Diff.txt
# Diff Before.txt and After.txt
Compare-Object -ReferenceObject (Get-Content .\logs\Before.txt) -DifferenceObject (Get-Content .\logs\After.txt) | Out-File -Append -FilePath .\logs\Diff.txt

Pop-Location

