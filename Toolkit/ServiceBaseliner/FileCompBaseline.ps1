if (-not (Test-Path -Path "C:\rocket")) {
    New-Item -ItemType Directory -Path "C:\rocket"
}

# Get a list of all files on the system
$files = Get-ChildItem -Recurse C:\\


$filesWithTime = $files | Select-Object FullName, LastWriteTime
$filesWithTime | Export-Csv -Path "C:\rocket\fileWithTimeexfil.csv" -NoTypeInformation

$filesHidden = $files | Where-Object { $_.Attributes -eq "Hidden" }
$filesHidden = $filesHidden | Select-Object FullName, LastWriteTime
$filesHidden | Export-Csv -Path "C:\rocket\filesHidden.csv" -NoTypeInformation

# Select the properties you want to include in the CSV file
$files = $files | Select-Object FullName

# Export the selected properties to a CSV file
$files | Export-Csv -Path "C:\rocket\fileexfil.csv" -NoTypeInformation


..\winmerge-2.16.24-x64-exe\WinMerge\WinMergeU.exe C:\rocket\fileexfil.csv .\filebaseline.csv

