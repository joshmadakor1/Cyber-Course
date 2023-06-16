# This script fails to login '$max_attempts' times, and then successfully logs in once

# Authenticate user against Azure AD
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" # Your Tenant ID, you can find on the AAD Blade in the Azure Portal
$username = "attacker@joshmadakorgmail.onmicrosoft.com" # Some Username that exists in your AAD Tenant
$correct_password = "Cyberlab123!" # Enter the correct password for the above user
$wrong_password = "___WRONG PASSWORD___" # This is used to generate auth failures
$max_attempts = 11 # This is the number of times to fail the login before succeeding

# Disconnect from AAD if already connected; we want to try to authenticate
if ((Get-AzContext) -eq $true) {
    Disconnect-AzAccount
}

# This section will fail 11 logon attempts against Azure AD
$count = 0

while ($count -le $max_attempts) {
    Start-Sleep -Seconds 1
    $count++
    try {
        $securePassword = ConvertTo-SecureString $wrong_password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
        Connect-AzAccount -TenantId $tenantId -Credential $cred -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Login Failure. $($count))"
        # $Error[0].Exception.Message # Remove the Hash (#) before $Error if you want to see the error message
    }
}

# This section will (should) successfully authenticate against AAD, simulating a successful brute force attack
$securePassword = ConvertTo-SecureString $correct_password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
Connect-AzAccount -TenantId $tenantId -Credential $cred -ErrorAction SilentlyContinue
