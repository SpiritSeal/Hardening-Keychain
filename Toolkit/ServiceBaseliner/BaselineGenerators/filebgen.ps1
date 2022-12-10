# Get a list of all files on the system
$files = Get-ChildItem -Recurse

# Select the properties you want to include in the CSV file
$files = $files | Select-Object FullName, LastWriteTime

# Export the selected properties to a CSV file
$files | Export-Csv -Path "C:\rocket\filebaseline.csv" -NoTypeInformation
