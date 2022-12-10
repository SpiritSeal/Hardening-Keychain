if (-not (Test-Path -Path "C:\rocket")) {
    New-Item -ItemType Directory -Path "C:\rocket"
}

# Get a list of all registry keys from the HKLM Windows Software hive
$keys = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\ -Recurse

# Select the properties you want to include in the CSV file
$keys = $keys | Select-Object PSPath, Property

# Export the selected properties to a CSV file
$keys | Export-Csv -Path "C:\rocket\regexfil.csv" -NoTypeInformation



..\winmerge-2.16.24-x64-exe\WinMerge\WinMergeU.exe C:\rocket\regexfil.csv .\regbaseline.csv

