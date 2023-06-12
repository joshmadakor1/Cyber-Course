############################# SET THE VARIABLES BELOW ##############################
# Ex: sacyberlab01
$storageAccountName = "Storage Account Name Goes Here"

# Ex: 0W8lxv+FmDgkOw0K3hOhNA3DNROKiAthDxHMn5nf0vi/PROTT/84HUezjL0wxclM8OI3yX4+F/K+AStiySi8Q==
$storageAccountKey = "Storage Account Access Key Goes Here"

# Ex: testcontainer
$containerName = "Storage Account Container Name Goes Here"
############################# SET THE VARIABLES ABOVE ##############################


# You can leave these alone
$localFileContent = "This is a test file" 
$localFilePath = "$env:USERPROFILE\Desktop\testfile.txt"
$blobName = "testfile.txt"

#Create a local text file
$localFileContent | Out-File -FilePath $localFilePath -Encoding ascii

#Authenticate with your Azure account
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

#Upload file to Azure Storage
Set-AzStorageBlobContent -File $localFilePath -Container $containerName -Blob $blobName -Context $context

#Confirmation message
Write-Host "File uploaded successfully to $storageAccountName/$containerName/$blobName"
