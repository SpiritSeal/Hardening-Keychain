if (-not (Test-Path -Path "C:\rocket")) {
    New-Item -ItemType Directory -Path "C:\rocket"
}

# Get a list of all Windows services
$services = Get-Service

# Select the properties you want to include in the CSV file
$services = $services | Select-Object Name, Status, StartType

# Export the selected properties to a CSV file
$services | Export-Csv -Path "C:\rocket\svcexfil.csv" -NoTypeInformation

..\winmerge-2.16.24-x64-exe\WinMerge\WinMergeU.exe C:\rocket\svcexfil.csv .\svcbaseline.csv

