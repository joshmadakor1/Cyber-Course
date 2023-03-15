# Set your Key Vault Name and Secret Name
$KEY_VAULT_NAME = "key-vault-02242023" # Enter the name of your actual Key Vault instance
$SECRET_NAME = "Tenant-Global-Admin-Password" # Enter the name of your Secret Name
$NUMBER_OF_TIMES_TO_READ_KEY = 3 # The number of times you want to read the key


# Install the Azure Module if it doesn't exist
if ((Get-Module -Name Az) -eq $false) {
    Install-Module -Name Az
}
else {
    Write-Host "Az module already installed."
}

# Connect to Azure using your credentials if not already connected
if ((Get-AzContext) -eq $false) {
    Connect-AzAccount
}
else {
    Write-Host "Already logged in to Azure"
}

$count = 0
while ($count -lt $NUMBER_OF_TIMES_TO_READ_KEY) {
    # Get the key object from the key vault
    $Key = Get-AzKeyVaultSecret -VaultName $KEY_VAULT_NAME -Name $SECRET_NAME -AsPlainText
    Write-Host "Retrieved Secret: $($Key)"
    $count++
}

# Display the key object details
$Key | ConvertTo-Json -Depth 99