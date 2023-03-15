# This script fails to login '$max_attempts' times, and then successfully logs in once

# Authenticate user against Azure AD
$tenantId = "939e93f3-04f6-479d-82ff-345c231abb4d" # Your Tenant ID, you can find on the AAD Blade in the Azure Portal
$username = "955262333@joshmadakorgmail.onmicrosoft.com" # Some Username that exists in your AAD Tenant
$correct_password = "<Correct Password for the user above>" # Enter the correct password for the above user
$wrong_password = "___WRONG PASSWORD___" # This is used to generate auth failures
$max_attempts = 11 # This is the number of times to fail the login before succeeding

# Install the Azure Module if it doesn't exist
if ((Get-Module -Name Az) -eq $false) {
    Install-Module -Name Az
}

# Disconnect from AAD if already connected; we want to try to authenticate
if ((Get-AzContext) -eq $true) {
    Disconnect-AzAccount
}

# This section will fail 11 logon attempts against Azure AD
$count = 0

while ($count -le $max_attempts) {
    $count++
    try {
        $securePassword = ConvertTo-SecureString $wrong_password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
        Connect-AzureAD -TenantId $tenantId -Credential $cred -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Login Failure. $($count))"
        # $Error[0].Exception.Message # Remove the Hash (#) before $Error if you want to see the error message
    }
}

# This section will (should) successfully authenticate against AAD, simulating a successful brute force attack
$securePassword = ConvertTo-SecureString $correct_password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
Connect-AzureAD -TenantId $tenantId -Credential $cred -ErrorAction SilentlyContinue