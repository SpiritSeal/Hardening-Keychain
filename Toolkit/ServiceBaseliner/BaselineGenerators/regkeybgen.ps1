# Get a list of all registry keys from the HKLM, HKCU, HKCR, and HKCC hives
$keys = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\ -Recurse

# Select the properties you want to include in the CSV file
$keys = $keys | Select-Object PSPath, Property

# Export the selected properties to a CSV file
$keys | Export-Csv -Path "C:\rocket\regbaseline.csv" -NoTypeInformation
